package dev.netlurker.android.data

import android.content.Context
import dev.netlurker.android.core.BannerInfo
import dev.netlurker.android.core.CertInfo
import dev.netlurker.android.core.GeoInfo
import dev.netlurker.android.core.IntelResult
import dev.netlurker.android.core.IntelStatus
import dev.netlurker.android.core.Ip
import dev.netlurker.android.core.JsonWriter
import dev.netlurker.android.core.RiskEngine
import dev.netlurker.android.core.Target
import dev.netlurker.android.core.ThreatInfo
import dev.netlurker.android.core.nowEpochSec
import dev.netlurker.android.intel.AbuseIpDb
import dev.netlurker.android.intel.BannerProbe
import dev.netlurker.android.intel.Dnsbl
import dev.netlurker.android.intel.GeoApi
import dev.netlurker.android.intel.PassiveDns
import dev.netlurker.android.intel.Rdap
import dev.netlurker.android.intel.ReverseDns
import dev.netlurker.android.intel.TlsProbe
import dev.netlurker.android.intel.VirusTotal
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Enriches investigated destinations. One coroutine per target, results published as they
 * arrive so the UI can show "querying…" per row instead of a blank screen.
 *
 * The honesty contract is enforced here, in one place:
 *  - a source that is switched off reports DISABLED with the reason, never an empty value;
 *  - a source that needs a key and has none reports DISABLED, not "no threats found";
 *  - a failed request reports FAILED with the underlying error and is never cached;
 *  - a cached answer is always shown with the timestamp it was fetched at.
 */
class IntelRepository(
    context: Context,
    private val settings: Settings,
    private val scope: CoroutineScope
) {

    private val cacheDir = java.io.File(context.applicationContext.filesDir, "intel")

    private val geoCache = DiskCache(cacheDir, "geo.tsv")
    private val threatCache = DiskCache(cacheDir, "threat.tsv")
    private val rdapCache = DiskCache(cacheDir, "rdap.tsv")
    private val certCache = DiskCache(cacheDir, "cert.tsv")
    private val bannerCache = DiskCache(cacheDir, "banner.tsv")

    /** Retry bookkeeping: how many times each source failed for a given address. */
    private val attempts = HashMap<String, HashMap<String, Int>>()
    private val nextTryAt = HashMap<String, Long>()

    private var hostsSnapshot = HostsFile.Snapshot(readable = false, entries = 0)
    private var hostsReadAtMs = 0L

    private val geoThrottle = Mutex()
    private var lastGeoRequestAt = 0L

    private val _targets = MutableStateFlow<List<Target>>(emptyList())
    val targets: StateFlow<List<Target>> = _targets.asStateFlow()

    private val _status = MutableStateFlow("")
    val status: StateFlow<String> = _status.asStateFlow()

    init {
        listOf(geoCache, threatCache, rdapCache, certCache, bannerCache).forEach { it.load() }
    }

    fun cacheSizes(): Map<String, Int> = mapOf(
        "geo" to geoCache.size(),
        "threat" to threatCache.size(),
        "rdap" to rdapCache.size(),
        "cert" to certCache.size(),
        "banner" to bannerCache.size()
    )

    fun clearCaches() {
        geoCache.clear(); threatCache.clear(); rdapCache.clear()
        certCache.clear(); bannerCache.clear()
        attempts.clear(); nextTryAt.clear()
    }

    fun persistCaches() {
        geoCache.save(); threatCache.save(); rdapCache.save()
        certCache.save(); bannerCache.save()
    }

    fun addTarget(input: String, port: Int?): Target {
        val trimmed = input.trim()
        val existing = _targets.value.firstOrNull { it.input.equals(trimmed, true) && it.port == port }
        if (existing != null) return existing
        val target = Target(input = trimmed, ip = trimmed.takeIf { Ip.isIp(it) }, port = port)
        _targets.value = _targets.value + target
        investigate(target.key, force = false)
        return target
    }

    fun removeTarget(key: String) {
        _targets.value = _targets.value.filterNot { it.key == key }
    }

    fun clearTargets() {
        _targets.value = emptyList()
    }

    /** Restores targets from a previous session without re-querying everything. */
    fun restore(targets: List<Target>) {
        _targets.value = targets
    }

    private fun update(key: String, transform: (Target) -> Target) {
        _targets.value = _targets.value.map { if (it.key == key) transform(it) else it }
    }

    /** Runs every enabled source for one target, in the order the desktop build uses. */
    fun investigate(key: String, force: Boolean = false) {
        val target = _targets.value.firstOrNull { it.key == key } ?: return
        val backoffUntil = nextTryAt[key] ?: 0L
        if (!force && backoffUntil > nowEpochSec()) return
        scope.launch(Dispatchers.IO) { runInvestigation(target, force) }
    }

    private suspend fun runInvestigation(target: Target, force: Boolean) {
        val key = target.key
        var current = target

        // --- 1. resolve the input to an address ---------------------------------
        if (current.ip == null) {
            current = current.copy(resolve = IntelResult.pending())
            update(key) { current }
            val resolved = withContext(Dispatchers.IO) {
                runCatching { java.net.InetAddress.getByName(current.input).hostAddress }.getOrNull()
            }
            current = if (resolved.isNullOrBlank()) {
                current.copy(resolve = IntelResult.failed("could not resolve ${current.input}"))
            } else {
                current.copy(ip = resolved, resolve = IntelResult.ok(resolved))
            }
            update(key) { current }
        }

        val ip = current.ip
        if (ip == null) {
            current = current.copy(verdict = RiskEngine.evaluate(current))
            update(key) { current }
            return
        }
        val publicAddress = Ip.isPublic(ip)

        // A destination that only resolves because the hosts file says so is worth saying
        // out loud. Re-read at most once a minute, the same cadence the desktop uses.
        val hostsNow = System.currentTimeMillis()
        if (hostsNow - hostsReadAtMs >= 60_000L) {
            hostsSnapshot = HostsFile.read()
            hostsReadAtMs = hostsNow
        }
        val redirected = hostsSnapshot.redirects(ip)
        if (current.hostsRedirect != redirected) {
            current = current.copy(hostsRedirect = redirected)
            update(key) { current }
        }

        // --- 2. reverse DNS ------------------------------------------------------
        if (force || current.reverseDns.status == IntelStatus.IDLE) {
            current = current.copy(reverseDns = IntelResult.pending())
            update(key) { current }
            val name = withContext(Dispatchers.IO) { ReverseDns.lookup(ip) }
            current = current.copy(
                reverseDns = if (name == null) IntelResult.failed("no PTR record")
                else IntelResult.ok(name)
            )
            update(key) { current }
        }
        val reverseName = current.reverseDns.value

        // --- 3. geolocation ------------------------------------------------------
        current = enrichGeo(current, ip, force)
        update(key) { current }

        // --- 4. threat intelligence ---------------------------------------------
        current = enrichThreat(current, ip, publicAddress, force)
        update(key) { current }

        // --- 5. TLS --------------------------------------------------------------
        current = enrichCert(current, ip, reverseName, force)
        update(key) { current }

        // --- 6. HTTP banner ------------------------------------------------------
        current = enrichBanner(current, ip, force)
        update(key) { current }

        // --- 7. verdict ----------------------------------------------------------
        current = current.copy(verdict = RiskEngine.evaluate(current))
        update(key) { current }
        persistCaches()
    }

    // ---------------------------------------------------------------- geolocation

    private suspend fun enrichGeo(target: Target, ip: String, force: Boolean): Target {
        if (!settings.geoEnabled) {
            return target.copy(geo = IntelResult.disabled("geolocation is turned off"))
        }
        if (!Ip.isPublic(ip)) {
            return target.copy(geo = IntelResult.unavailable("private address — no geolocation exists"))
        }
        if (!force) {
            geoCache.get(ip)?.let { entry ->
                if (nowEpochSec() - entry.atEpochSec < GEO_TTL_SEC) {
                    return target.copy(geo = parseGeo(DiskCache.decode(entry.payload))?.let {
                        IntelResult.ok(it, entry.atEpochSec)
                    } ?: target.geo)
                }
            }
        }
        val response = withContext(Dispatchers.IO) { throttledGeo(ip) }
        return if (response == null) {
            noteFailure(target.key, "geo")
            target.copy(geo = IntelResult.offline("no answer from ip-api.com"))
        } else {
            response.fold(
                onSuccess = { info ->
                    geoCache.put(ip, nowEpochSec(), writeGeo(info))
                    target.copy(geo = IntelResult.ok(info))
                },
                onFailure = { error ->
                    noteFailure(target.key, "geo")
                    if (error is GeoApi.GeoFailure && error.offline) {
                        target.copy(geo = IntelResult.offline(error.message))
                    } else {
                        target.copy(geo = IntelResult.failed(error.message ?: "lookup failed"))
                    }
                }
            )
        }
    }

    /** ip-api's free tier allows 45 requests/minute; this keeps NetLurker inside it. */
    private suspend fun throttledGeo(ip: String): Result<GeoInfo>? =
        geoThrottle.withLock {
            val wait = GEO_MIN_INTERVAL_MS - (System.currentTimeMillis() - lastGeoRequestAt)
            if (wait > 0) kotlinx.coroutines.delay(wait)
            lastGeoRequestAt = System.currentTimeMillis()
            runCatching { GeoApi.single(ip) }
                .mapCatching { it ?: throw IllegalStateException("no record for $ip") }
                .let { result ->
                    if (result.exceptionOrNull() is java.net.UnknownHostException) null else result
                }
        }

    // ------------------------------------------------------- threat intelligence

    private suspend fun enrichThreat(
        target: Target,
        ip: String,
        publicAddress: Boolean,
        force: Boolean
    ): Target {
        if (!settings.threatEnabled) {
            return target.copy(threat = IntelResult.disabled("threat lookups are turned off"))
        }
        if (!publicAddress) {
            return target.copy(threat = IntelResult.unavailable("private address — not listed anywhere"))
        }
        if (!force) {
            threatCache.get(ip)?.let { entry ->
                if (nowEpochSec() - entry.atEpochSec < THREAT_TTL_SEC) {
                    parseThreat(DiskCache.decode(entry.payload))?.let {
                        return target.copy(threat = IntelResult.ok(it, entry.atEpochSec))
                    }
                }
            }
        }

        val sources = mutableListOf<String>()
        var abuseScore = -1
        var totalReports = 0
        var lastReport = 0L
        var tor = false
        var dnsblHits = emptyList<String>()
        var pdnsRecords = 0
        var pdnsNames = ""
        var vtMalicious = 0
        var vtSuspicious = 0
        var vtTotal = 0
        var vtReputation = 0
        var rdapName = ""
        var rdapOrg = ""
        var rdapAbuse = ""
        var rdapCidr = ""
        var rdapRegistered = 0L
        val problems = mutableListOf<String>()

        // DNS blacklists — no key needed.
        val dnsbl = withContext(Dispatchers.IO) { Dnsbl.check(ip) }
        if (dnsbl == null) {
            problems += "DNSBL: IPv6 has no reverse form"
        } else {
            dnsblHits = dnsbl.hits
            sources += "dnsbl(${dnsbl.queried})"
            if (dnsbl.unreachable.isNotEmpty()) {
                problems += "unreachable: " + dnsbl.unreachable.joinToString(", ")
            }
        }

        // AbuseIPDB — needs the user's own key.
        if (settings.abuseIpDbKey.isBlank()) {
            problems += "AbuseIPDB: no API key set"
        } else {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { AbuseIpDb.check(ip, settings.abuseIpDbKey) }
            }
            outcome.fold(
                onSuccess = {
                    abuseScore = it.abuseScore
                    totalReports = it.totalReports
                    lastReport = it.lastReportEpochSec
                    tor = it.isTor
                    sources += "abuseipdb"
                },
                onFailure = { problems += "AbuseIPDB: ${it.message}" }
            )
        }

        // CIRCL passive DNS — no key needed.
        val pdns = withContext(Dispatchers.IO) { runCatching { PassiveDns.check(ip) } }
        pdns.fold(
            onSuccess = {
                pdnsRecords = it.records
                pdnsNames = it.names
                sources += "circl"
            },
            onFailure = { problems += "CIRCL: ${it.message}" }
        )

        // RDAP ownership.
        if (settings.rdapEnabled) {
            val cachedRdap = if (!force) {
                rdapCache.get(ip)?.takeIf { nowEpochSec() - it.atEpochSec < RDAP_TTL_SEC }
            } else null
            if (cachedRdap != null) {
                parseRdap(DiskCache.decode(cachedRdap.payload))?.let { row ->
                    rdapName = row.name
                    rdapOrg = row.org
                    rdapAbuse = row.abuse
                    rdapCidr = row.cidr
                    rdapRegistered = row.registered
                    sources += "rdap(cached)"
                }
            } else {
                val outcome = withContext(Dispatchers.IO) { runCatching { Rdap.check(ip) } }
                outcome.fold(
                    onSuccess = {
                        rdapName = it.name
                        rdapOrg = it.org
                        rdapAbuse = it.abuseContact
                        rdapCidr = it.cidr
                        rdapRegistered = it.registeredEpochSec
                        sources += "rdap"
                        rdapCache.put(
                            ip, nowEpochSec(),
                            writeRdap(it.name, it.org, it.abuseContact, it.cidr, it.registeredEpochSec)
                        )
                    },
                    onFailure = { problems += "RDAP: ${it.message}" }
                )
            }
        } else {
            problems += "RDAP: turned off"
        }

        // VirusTotal — optional.
        if (settings.vtEnabled && settings.virusTotalKey.isNotBlank()) {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { VirusTotal.check(ip, settings.virusTotalKey) }
            }
            outcome.fold(
                onSuccess = {
                    vtMalicious = it.malicious
                    vtSuspicious = it.suspicious
                    vtTotal = it.total
                    vtReputation = it.reputation
                    sources += "virustotal"
                },
                onFailure = { problems += "VirusTotal: ${it.message}" }
            )
        } else if (settings.vtEnabled) {
            problems += "VirusTotal: no API key set"
        } else {
            problems += "VirusTotal: turned off"
        }

        val info = ThreatInfo(
            abuseScore = abuseScore,
            totalReports = totalReports,
            lastReportEpochSec = lastReport,
            isTor = tor,
            dnsblHits = dnsblHits,
            passiveDnsRecords = pdnsRecords,
            passiveDnsNames = pdnsNames,
            rdapName = rdapName,
            rdapOrg = rdapOrg,
            rdapAbuse = rdapAbuse,
            rdapCidr = rdapCidr,
            rdapRegisteredEpochSec = rdapRegistered,
            vtMalicious = vtMalicious,
            vtSuspicious = vtSuspicious,
            vtTotal = vtTotal,
            vtReputation = vtReputation,
            sourcesAnswered = sources
        )
        if (sources.isEmpty()) {
            noteFailure(target.key, "threat")
            return target.copy(threat = IntelResult.failed(problems.joinToString("; ")))
        }
        threatCache.put(ip, nowEpochSec(), writeThreat(info))
        val detail = if (problems.isEmpty()) null else problems.joinToString("; ")
        return target.copy(
            threat = IntelResult(IntelStatus.OK, info, detail, nowEpochSec())
        )
    }

    // ---------------------------------------------------------------------- TLS

    private suspend fun enrichCert(
        target: Target,
        ip: String,
        expectedName: String?,
        force: Boolean
    ): Target {
        if (!settings.tlsEnabled) {
            return target.copy(cert = IntelResult.disabled("TLS inspection is turned off"))
        }
        val port = target.port ?: 443
        val cacheKey = "$ip:$port"
        if (!force) {
            certCache.get(cacheKey)?.let { entry ->
                if (nowEpochSec() - entry.atEpochSec < CERT_TTL_SEC) {
                    parseCert(DiskCache.decode(entry.payload))?.let {
                        return target.copy(cert = IntelResult.ok(it, entry.atEpochSec))
                    }
                }
            }
        }
        val outcome = withContext(Dispatchers.IO) {
            runCatching { TlsProbe.inspect(ip, port, expectedName) }
        }
        return outcome.fold(
            onSuccess = { info ->
                certCache.put(cacheKey, nowEpochSec(), writeCert(info))
                target.copy(cert = IntelResult.ok(info))
            },
            onFailure = { error ->
                val message = error.message.orEmpty()
                // No TLS on this port is a finding, not a failure of the probe.
                if (message.contains("handshake", true) ||
                    message.contains("SSL", true) ||
                    message.contains("protocol", true)
                ) {
                    target.copy(
                        cert = IntelResult(
                            IntelStatus.FAILED, null,
                            "no TLS service on port $port (${error.javaClass.simpleName})",
                            nowEpochSec()
                        )
                    )
                } else {
                    target.copy(cert = IntelResult.failed(message.ifBlank { error.javaClass.simpleName }))
                }
            }
        )
    }

    // ------------------------------------------------------------------- banner

    private suspend fun enrichBanner(target: Target, ip: String, force: Boolean): Target {
        if (!settings.bannerEnabled) {
            return target.copy(banner = IntelResult.disabled("HTTP banner probe is turned off"))
        }
        val port = target.port ?: 80
        val cacheKey = "$ip:$port"
        if (!force) {
            bannerCache.get(cacheKey)?.let { entry ->
                if (nowEpochSec() - entry.atEpochSec < BANNER_TTL_SEC) {
                    parseBanner(DiskCache.decode(entry.payload))?.let {
                        return target.copy(banner = IntelResult.ok(it, entry.atEpochSec))
                    }
                }
            }
        }
        val outcome = withContext(Dispatchers.IO) {
            runCatching { BannerProbe.inspect(ip, port) }
        }
        return outcome.fold(
            onSuccess = { info ->
                bannerCache.put(cacheKey, nowEpochSec(), writeBanner(info))
                target.copy(banner = IntelResult.ok(info))
            },
            onFailure = { error ->
                target.copy(
                    banner = IntelResult.failed(
                        error.message?.ifBlank { error.javaClass.simpleName }
                            ?: error.javaClass.simpleName
                    )
                )
            }
        )
    }

    // ------------------------------------------------------------------ helpers

    private fun noteFailure(key: String, source: String) {
        val perSource = attempts.getOrPut(key) { HashMap() }
        val count = (perSource[source] ?: 0) + 1
        perSource[source] = count
        nextTryAt[key] = nowEpochSec() + DiskCache.backoffSeconds(count)
    }

    fun pendingBackoff(key: String): Long {
        val until = nextTryAt[key] ?: return 0L
        return (until - nowEpochSec()).coerceAtLeast(0L)
    }

    // ------------------------------------------------------------ serialisation

    private fun writeGeo(info: GeoInfo): String = JsonWriter("").apply {
        beginObject()
        name("country"); value(info.country)
        name("countryCode"); value(info.countryCode)
        name("city"); value(info.city)
        name("region"); value(info.region)
        name("isp"); value(info.isp)
        name("org"); value(info.org)
        name("asn"); value(info.asn)
        name("asname"); value(info.asname)
        name("host"); value(info.host)
        name("mobile"); value(info.mobile)
        name("proxy"); value(info.proxy)
        name("hosting"); value(info.hosting)
        endObject()
    }.build()

    private fun parseGeo(payload: String): GeoInfo? = runCatching {
        val o = JSONObject(payload)
        GeoInfo(
            country = o.optString("country"),
            countryCode = o.optString("countryCode"),
            city = o.optString("city"),
            region = o.optString("region"),
            isp = o.optString("isp"),
            org = o.optString("org"),
            asn = o.optString("asn"),
            asname = o.optString("asname"),
            host = o.optString("host"),
            mobile = o.optBoolean("mobile"),
            proxy = o.optBoolean("proxy"),
            hosting = o.optBoolean("hosting")
        )
    }.getOrNull()

    private fun writeThreat(info: ThreatInfo): String = JsonWriter("").apply {
        beginObject()
        name("abuseScore"); value(info.abuseScore)
        name("totalReports"); value(info.totalReports)
        name("lastReport"); value(info.lastReportEpochSec)
        name("tor"); value(info.isTor)
        name("dnsbl"); value(info.dnsblHits.joinToString(","))
        name("pdns"); value(info.passiveDnsRecords)
        name("pdnsNames"); value(info.passiveDnsNames)
        name("vtMal"); value(info.vtMalicious)
        name("vtSus"); value(info.vtSuspicious)
        name("vtTot"); value(info.vtTotal)
        name("vtRep"); value(info.vtReputation)
        name("sources"); value(info.sourcesAnswered.joinToString(","))
        endObject()
    }.build()

    private fun parseThreat(payload: String): ThreatInfo? = runCatching {
        val o = JSONObject(payload)
        ThreatInfo(
            abuseScore = o.optInt("abuseScore", -1),
            totalReports = o.optInt("totalReports"),
            lastReportEpochSec = o.optLong("lastReport"),
            isTor = o.optBoolean("tor"),
            dnsblHits = o.optString("dnsbl").split(",").filter { it.isNotBlank() },
            passiveDnsRecords = o.optInt("pdns"),
            passiveDnsNames = o.optString("pdnsNames"),
            vtMalicious = o.optInt("vtMal"),
            vtSuspicious = o.optInt("vtSus"),
            vtTotal = o.optInt("vtTot"),
            vtReputation = o.optInt("vtRep"),
            sourcesAnswered = o.optString("sources").split(",").filter { it.isNotBlank() }
        )
    }.getOrNull()

    private fun writeRdap(
        name: String,
        org: String,
        abuse: String,
        cidr: String,
        registered: Long
    ): String = JsonWriter("").apply {
        beginObject()
        name("name"); value(name)
        name("org"); value(org)
        name("abuse"); value(abuse)
        name("cidr"); value(cidr)
        name("registered"); value(registered)
        endObject()
    }.build()

    private data class RdapRow(
        val name: String,
        val org: String,
        val abuse: String,
        val cidr: String,
        val registered: Long
    )

    private fun parseRdap(payload: String): RdapRow? = runCatching {
        val o = JSONObject(payload)
        RdapRow(
            o.optString("name"), o.optString("org"), o.optString("abuse"),
            o.optString("cidr"), o.optLong("registered")
        )
    }.getOrNull()

    private fun writeCert(info: CertInfo): String = JsonWriter("").apply {
        beginObject()
        name("subject"); value(info.subject)
        name("issuer"); value(info.issuer)
        name("sans"); value(info.subjectAlternativeNames.joinToString(","))
        name("notBefore"); value(info.notBeforeEpochSec)
        name("notAfter"); value(info.notAfterEpochSec)
        name("serial"); value(info.serial)
        name("sha256"); value(info.sha256Fingerprint)
        name("selfSigned"); value(info.selfSigned)
        name("expired"); value(info.expired)
        name("notYetValid"); value(info.notYetValid)
        name("nameMismatch"); value(info.nameMismatch)
        name("chain"); value(info.chainLength)
        name("protocol"); value(info.protocol)
        name("cipher"); value(info.cipherSuite)
        endObject()
    }.build()

    private fun parseCert(payload: String): CertInfo? = runCatching {
        val o = JSONObject(payload)
        CertInfo(
            subject = o.optString("subject"),
            issuer = o.optString("issuer"),
            subjectAlternativeNames = o.optString("sans").split(",").filter { it.isNotBlank() },
            notBeforeEpochSec = o.optLong("notBefore"),
            notAfterEpochSec = o.optLong("notAfter"),
            serial = o.optString("serial"),
            sha256Fingerprint = o.optString("sha256"),
            selfSigned = o.optBoolean("selfSigned"),
            expired = o.optBoolean("expired"),
            notYetValid = o.optBoolean("notYetValid"),
            nameMismatch = o.optBoolean("nameMismatch"),
            chainLength = o.optInt("chain"),
            protocol = o.optString("protocol"),
            cipherSuite = o.optString("cipher")
        )
    }.getOrNull()

    private fun writeBanner(info: BannerInfo): String = JsonWriter("").apply {
        beginObject()
        name("statusLine"); value(info.statusLine)
        name("server"); value(info.server)
        name("via"); value(info.via)
        name("eol"); value(info.endOfLife)
        name("eolDetail"); value(info.eolDetail)
        name("ms"); value(info.responseMs)
        endObject()
    }.build()

    private fun parseBanner(payload: String): BannerInfo? = runCatching {
        val o = JSONObject(payload)
        BannerInfo(
            statusLine = o.optString("statusLine"),
            server = o.optString("server"),
            via = o.optString("via"),
            endOfLife = o.optBoolean("eol"),
            eolDetail = o.optString("eolDetail"),
            responseMs = o.optLong("ms")
        )
    }.getOrNull()

    private companion object {
        const val GEO_TTL_SEC = 7L * 86_400
        const val THREAT_TTL_SEC = 24L * 3_600
        const val RDAP_TTL_SEC = 30L * 86_400
        const val CERT_TTL_SEC = 6L * 3_600
        const val BANNER_TTL_SEC = 3_600L
        const val GEO_MIN_INTERVAL_MS = 1_500L
    }
}
