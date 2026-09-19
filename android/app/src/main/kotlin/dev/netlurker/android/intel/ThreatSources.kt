package dev.netlurker.android.intel

import dev.netlurker.android.core.Ip
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * The configured DNS blacklists the desktop build queries, with the same zone names.
 *
 * A zone that cannot be reached is reported separately from a zone that answered "not
 * listed". Private DNS (DNS-over-TLS on Android 9+) sometimes refuses these queries; when
 * that happens the UI says the zone was unreachable instead of implying a clean result.
 */
object Dnsbl {

    data class Zone(val label: String, val suffix: String)

    val ZONES = listOf(
        Zone("SBL/XBL", "sbl-xbl.spamhaus.org"),
        Zone("Blocklist.de", "bl.blocklist.de"),
        Zone("Barracuda", "b.barracudacentral.org"),
        Zone("UCEPROTECT", "dnsbl-1.uceprotect.net")
    )

    data class Outcome(
        val hits: List<String>,
        val unreachable: List<String>,
        val queried: Int
    ) {
        val clean: Boolean get() = hits.isEmpty() && unreachable.isEmpty() && queried > 0
    }

    /** Only IPv4 has a DNSBL reverse form; IPv6 is reported as skipped by the caller. */
    fun isListing(zone: Zone, address: String): Boolean {
        val code = address.removePrefix("127.0.0.").toIntOrNull() ?: return false
        if (!address.startsWith("127.0.0.")) return false
        return if (zone.suffix == "sbl-xbl.spamhaus.org") code in setOf(2, 3, 4, 5, 6, 7, 9)
        else code == 2
    }

    fun check(ip: String, lookup: (String) -> List<String> = { name ->
        InetAddress.getAllByName(name).mapNotNull { it.hostAddress }
    }): Outcome? {
        val reversed = Ip.reverseForDnsbl(ip) ?: return null
        val hits = mutableListOf<String>()
        val unreachable = mutableListOf<String>()
        var queried = 0
        for (zone in ZONES) {
            queried++
            try {
                val answers = lookup("$reversed.${zone.suffix}")
                if (answers.any { isListing(zone, it) }) hits += zone.label
                if (answers.isEmpty() || answers.any { !isListing(zone, it) }) unreachable += zone.label
            } catch (e: UnknownHostException) {
                // InetAddress conflates NXDOMAIN, resolver refusal and connectivity
                // errors. Without an RCODE we cannot assert a clean result.
                unreachable += zone.label
            } catch (e: SecurityException) {
                unreachable += zone.label
            } catch (e: Exception) {
                unreachable += zone.label
            }
        }
        return Outcome(hits, unreachable, queried)
    }
}

/** AbuseIPDB. Requires the user's own key; NetLurker never ships a shared one. */
object AbuseIpDb {

    data class Outcome(
        val abuseScore: Int,
        val totalReports: Int,
        val lastReportEpochSec: Long,
        val isTor: Boolean,
        val country: String,
        val isp: String,
        val usageType: String
    )

    fun check(ip: String, apiKey: String, timeoutMs: Int = 8_000): Outcome {
        require(apiKey.isNotBlank()) { "no API key" }
        val response = Http.get(
            "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90",
            headers = mapOf("Key" to apiKey, "Accept" to "application/json"),
            timeoutMs = timeoutMs
        )
        if (!response.ok) throw IllegalStateException(response.error ?: "request failed")
        return parse(response.body, ip)
    }

    fun parse(body: String, ip: String): Outcome {
        val data = objectDocument(body).getJSONObject("data")
        require(Ip.sameAddress(data.strictString("ipAddress"), ip)) { "response address mismatch" }
        val score = data.strictInt("abuseConfidenceScore", 0, 100)
        val reports = data.strictInt("totalReports")
        val tor = data.opt("isTor")
        require(tor == null || tor == JSONObject.NULL || tor is Boolean) { "invalid isTor" }
        return Outcome(score, reports, parseIso8601(data.optString("lastReportedAt")),
            tor == true, data.optString("countryCode"), data.optString("isp"), data.optString("usageType"))
    }

}

/** CIRCL passive DNS — how many names have historically resolved to this address. */
object PassiveDns {

    data class Outcome(val records: Int, val names: String, val newest: Long)

    fun check(ip: String, timeoutMs: Int = 8_000): Outcome {
        val response = Http.get("https://cve.circl.lu/pdns/query/$ip", timeoutMs = timeoutMs)
        if (!response.ok) throw IllegalStateException(response.error ?: "request failed")
        return parse(response.body, ip)
    }

    fun parse(body: String, ip: String): Outcome {
        val trimmed = body.trim()
        val rows = if (trimmed.startsWith("[")) {
            val array = document(trimmed) as? JSONArray ?: error("expected array")
            (0 until array.length()).map { array.getJSONObject(it) }
        } else {
            require(trimmed.isNotEmpty()) { "empty response" }
            trimmed.lineSequence().filter { it.isNotBlank() }.map { objectDocument(it) }.toList()
        }
        val names = LinkedHashSet<String>()
        var newest = 0L
        for (obj in rows) {
            val name = obj.strictString("rrname")
            require(name.isNotBlank() && obj.strictString("rrtype") in setOf("A", "AAAA") &&
                Ip.sameAddress(obj.strictString("rdata"), ip)) { "invalid passive DNS record" }
            names += name
            val last = obj.opt("time_last")
            val time = if (last is Number && last.toDouble().isFinite() && last.toDouble() >= 0 && last.toDouble() < Long.MAX_VALUE.toDouble()) last.toLong()
                else if (last is String) parseIso8601(last) else 0L
            newest = maxOf(newest, time)
        }
        return Outcome(rows.size, names.take(6).joinToString(", "), newest)
    }

}

/** RDAP ownership via the rdap.org bootstrap, as in the desktop build. */
object Rdap {

    data class Outcome(
        val name: String,
        val org: String,
        val abuseContact: String,
        val cidr: String,
        val registeredEpochSec: Long
    )

    fun check(ip: String, timeoutMs: Int = 10_000): Outcome {
        val response = Http.get("https://rdap.org/ip/$ip", timeoutMs = timeoutMs)
        if (!response.ok) throw IllegalStateException(response.error ?: "request failed")
        val root = runCatching { objectDocument(response.body) }
            .getOrElse { throw IllegalStateException("unparsable response") }

        require(root.strictString("objectClassName") == "ip network" &&
            Ip.isIp(root.strictString("startAddress")) && Ip.isIp(root.strictString("endAddress"))) { "invalid RDAP network" }
        var name = root.optString("name")
        var org = ""
        var abuse = ""
        var registered = 0L

        val entities = root.optJSONArray("entities")
        if (entities != null) {
            for (i in 0 until entities.length()) {
                val entity = entities.optJSONObject(i) ?: continue
                val roles = entity.optJSONArray("roles")?.toStringArray().orEmpty()
                val vcardName = vcardValue(entity, "fn")
                val vcardMail = vcardEmail(entity)
                val handle = entity.optString("handle")
                if (roles.contains("registrant") || name.isBlank()) {
                    if (vcardName.isNotBlank()) {
                        org = vcardName
                        if (name.isBlank()) name = handle
                    }
                }
                if (roles.contains("abuse") && abuse.isBlank()) {
                    abuse = vcardMail.ifBlank { vcardName }
                }
                if (org.isBlank() && vcardName.isNotBlank()) org = vcardName
            }
        }
        if (org.isBlank()) {
            val network = root.optJSONObject("network")
            if (network != null) org = network.optString("name")
        }

        val events = root.optJSONArray("events")
        if (events != null) {
            for (i in 0 until events.length()) {
                val event = events.optJSONObject(i) ?: continue
                if (event.optString("eventAction") == "registration") {
                    registered = parseIso8601(event.optString("eventDate"))
                    break
                }
            }
        }

        val cidr = root.optJSONArray("cidr0_cidrs")?.let { array ->
            (0 until array.length()).mapNotNull { array.optJSONObject(it) }
                .joinToString(", ") { o ->
                    val start = o.optString("v4prefix").ifBlank { o.optString("v6prefix") }
                    val length = o.optInt("length", -1)
                    if (start.isBlank()) "" else "$start/$length"
                }
        }?.ifBlank { null }
            ?: listOfNotNull(
                root.optString("startAddress").ifBlank { null },
                root.optString("endAddress").ifBlank { null }
            ).joinToString(" - ")

        return Outcome(name, org, abuse, cidr, registered)
    }

    private fun vcardValue(entity: JSONObject, key: String): String {
        val vcard = entity.optJSONArray("vcardArray") ?: return ""
        val entries = vcard.optJSONArray(1) ?: return ""
        for (i in 0 until entries.length()) {
            val entry = entries.optJSONArray(i) ?: continue
            if (entry.optString(0) == key) return entry.optString(3)
        }
        return ""
    }

    private fun vcardEmail(entity: JSONObject): String {
        val vcard = entity.optJSONArray("vcardArray") ?: return ""
        val entries = vcard.optJSONArray(1) ?: return ""
        for (i in 0 until entries.length()) {
            val entry = entries.optJSONArray(i) ?: continue
            if (entry.optString(0) == "email") return entry.optString(3)
        }
        return ""
    }

    private fun JSONArray.toStringArray(): List<String> =
        (0 until length()).mapNotNull { optString(it).ifBlank { null } }
}

/** VirusTotal. Optional: only queried when the user provides a key. */
object VirusTotal {

    data class Outcome(val malicious: Int, val suspicious: Int, val total: Int, val reputation: Int)

    fun check(ip: String, apiKey: String, timeoutMs: Int = 10_000): Outcome {
        require(apiKey.isNotBlank()) { "no API key" }
        val response = Http.get(
            "https://www.virustotal.com/api/v3/ip_addresses/$ip",
            headers = mapOf("x-apikey" to apiKey, "Accept" to "application/json"),
            timeoutMs = timeoutMs
        )
        if (!response.ok) throw IllegalStateException(response.error ?: "request failed")
        return parse(response.body, ip)
    }

    fun parse(body: String, ip: String): Outcome {
        val data = objectDocument(body).getJSONObject("data")
        require(data.strictString("type") == "ip_address" && Ip.sameAddress(data.strictString("id"), ip)) { "response address mismatch" }
        val attributes = data.getJSONObject("attributes")
        val stats = attributes.getJSONObject("last_analysis_stats")
        val malicious = stats.strictInt("malicious")
        val suspicious = stats.strictInt("suspicious")
        val harmless = stats.strictInt("harmless")
        val undetected = stats.strictInt("undetected")
        stats.keys().forEach { stats.strictInt(it) }
        val total = malicious.toLong() + suspicious + harmless + undetected
        require(total in 1..Int.MAX_VALUE.toLong()) { "no usable engine verdicts" }
        return Outcome(malicious, suspicious, total.toInt(), attributes.strictInt("reputation", Int.MIN_VALUE))
    }

}

/**
 * ISO-8601 to epoch seconds without pulling in java.time desugaring.
 * Handles "2024-01-31T13:45:00+00:00" and the "Z" form; returns 0 when unparsable so a
 * bad timestamp never masquerades as a real registration date.
 */
fun parseIso8601(value: String?): Long {
    if (value.isNullOrBlank()) return 0L
    return runCatching { java.time.OffsetDateTime.parse(value).toEpochSecond() }.getOrDefault(0L)
}


private fun JSONObject.strictString(key: String): String =
    (get(key) as? String) ?: throw IllegalArgumentException("invalid $key")

private fun JSONObject.strictInt(key: String, minimum: Int = 0, maximum: Int = Int.MAX_VALUE): Int {
    val value = get(key) as? Number ?: throw IllegalArgumentException("invalid $key")
    val n = value.toDouble()
    require(n.isFinite() && n == kotlin.math.floor(n) && n >= minimum && n <= maximum) { "invalid $key" }
    return n.toInt()
}

private fun document(body: String): Any {
    val reader = JSONTokener(body)
    val result = reader.nextValue()
    require(reader.nextClean() == '\u0000') { "trailing response data" }
    return result
}
private fun objectDocument(body: String): JSONObject = document(body) as? JSONObject ?: error("expected object")
