package dev.netlurker.android.intel

import dev.netlurker.android.core.Ip
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * The five DNS blacklists the desktop build queries, with the same zone names.
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
        Zone("Sorbs", "spam.dnsbl.sorbs.net"),
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
    fun check(ip: String): Outcome? {
        val reversed = Ip.reverseForDnsbl(ip) ?: return null
        val hits = mutableListOf<String>()
        val unreachable = mutableListOf<String>()
        var queried = 0
        for (zone in ZONES) {
            queried++
            try {
                InetAddress.getAllByName("$reversed.${zone.suffix}")
                hits += zone.label
            } catch (e: UnknownHostException) {
                // NXDOMAIN — the authoritative answer is "not listed".
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
        val data = JSONObject(response.body).optJSONObject("data")
            ?: throw IllegalStateException("response had no data object")
        val lastReport = data.optString("lastReportedAt")
        return Outcome(
            abuseScore = data.optInt("abuseConfidenceScore", -1),
            totalReports = data.optInt("totalReports", 0),
            lastReportEpochSec = parseIso8601(lastReport),
            isTor = data.optBoolean("isTor"),
            country = data.optString("countryCode"),
            isp = data.optString("isp"),
            usageType = data.optString("usageType")
        )
    }
}

/** CIRCL passive DNS — how many names have historically resolved to this address. */
object PassiveDns {

    data class Outcome(val records: Int, val names: String, val newest: Long)

    fun check(ip: String, timeoutMs: Int = 8_000): Outcome {
        val response = Http.get("https://cve.circl.lu/pdns/query/$ip", timeoutMs = timeoutMs)
        if (!response.ok) throw IllegalStateException(response.error ?: "request failed")
        val array = runCatching { JSONArray(response.body) }
            .getOrElse { throw IllegalStateException("unparsable response") }
        val names = LinkedHashSet<String>()
        var newest = 0L
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val name = obj.optString("rrname")
            if (name.isNotBlank()) names += name
            newest = maxOf(newest, obj.optLong("time_last", 0L))
        }
        return Outcome(
            records = array.length(),
            names = names.take(6).joinToString(", "),
            newest = newest
        )
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
        val root = runCatching { JSONObject(response.body) }
            .getOrElse { throw IllegalStateException("unparsable response") }

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
                if ((roles.contains("abuse") || roles.contains("technical")) && abuse.isBlank()) {
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
        val attributes = JSONObject(response.body).optJSONObject("data")
            ?.optJSONObject("attributes")
            ?: throw IllegalStateException("response had no attributes")
        val stats = attributes.optJSONObject("last_analysis_stats")
        val malicious = stats?.optInt("malicious", 0) ?: 0
        val suspicious = stats?.optInt("suspicious", 0) ?: 0
        val harmless = stats?.optInt("harmless", 0) ?: 0
        val undetected = stats?.optInt("undetected", 0) ?: 0
        return Outcome(
            malicious = malicious,
            suspicious = suspicious,
            total = malicious + suspicious + harmless + undetected,
            reputation = attributes.optInt("reputation", 0)
        )
    }
}

/**
 * ISO-8601 to epoch seconds without pulling in java.time desugaring.
 * Handles "2024-01-31T13:45:00+00:00" and the "Z" form; returns 0 when unparsable so a
 * bad timestamp never masquerades as a real registration date.
 */
fun parseIso8601(value: String?): Long {
    if (value.isNullOrBlank()) return 0L
    val match = TIMESTAMP.find(value) ?: return 0L
    val (year, month, day, hour, minute, second) = match.destructured
    return runCatching {
        val calendar = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"))
        calendar.clear()
        calendar.set(
            year.toInt(), month.toInt() - 1, day.toInt(),
            hour.toInt(), minute.toInt(), second.toInt()
        )
        calendar.timeInMillis / 1000L
    }.getOrDefault(0L)
}

private val TIMESTAMP = Regex("""(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})""")
