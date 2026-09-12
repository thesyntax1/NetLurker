package dev.netlurker.android.core

/** Where a lookup stands. Modelled explicitly so the UI can never mistake "no answer yet"
 *  for "no problem" — the same contract the desktop build documents in its README. */
enum class IntelStatus {
    /** Not requested yet. */
    IDLE,

    /** Requested, in flight. Renders as "querying…". */
    PENDING,

    /** Real answer, with a timestamp. */
    OK,

    /** The request failed. The reason is kept verbatim; never cached. */
    FAILED,

    /** No network at the time of the attempt. Retried with backoff. */
    OFFLINE,

    /** Turned off by the user, or missing an API key. Says which. */
    DISABLED,

    /** This device/Android version cannot produce the value at all. */
    UNAVAILABLE
}

/** A single lookup result. [value] is only ever non-null with [IntelStatus.OK]. */
data class IntelResult<T>(
    val status: IntelStatus,
    val value: T? = null,
    val detail: String? = null,
    val atEpochSec: Long = 0L
) {
    val resolved: Boolean get() = status == IntelStatus.OK || status == IntelStatus.FAILED ||
        status == IntelStatus.OFFLINE || status == IntelStatus.DISABLED ||
        status == IntelStatus.UNAVAILABLE

    companion object {
        fun <T> idle(): IntelResult<T> = IntelResult(IntelStatus.IDLE)
        fun <T> pending(): IntelResult<T> = IntelResult(IntelStatus.PENDING)
        fun <T> ok(value: T, atEpochSec: Long = nowEpochSec()): IntelResult<T> =
            IntelResult(IntelStatus.OK, value, null, atEpochSec)
        fun <T> failed(reason: String): IntelResult<T> =
            IntelResult(IntelStatus.FAILED, null, reason, nowEpochSec())
        fun <T> offline(reason: String? = null): IntelResult<T> =
            IntelResult(IntelStatus.OFFLINE, null, reason, nowEpochSec())
        fun <T> disabled(reason: String): IntelResult<T> =
            IntelResult(IntelStatus.DISABLED, null, reason)
        fun <T> unavailable(reason: String): IntelResult<T> =
            IntelResult(IntelStatus.UNAVAILABLE, null, reason)
    }
}

fun nowEpochSec(): Long = System.currentTimeMillis() / 1000L

enum class RiskLevel { SAFE, INFO, WARN, DANGER }

/**
 * One scored piece of evidence, as a stable key plus arguments. The engine never emits
 * finished sentences: wording belongs to the interface language and lives in resources,
 * which is also what makes the engine testable on a plain JVM.
 */
data class RiskReason(val key: String, val args: List<String> = emptyList(), val points: Int)

/** Score + the evidence behind it. A score without reasons is not shown anywhere. */
data class Verdict(
    val score: Int,
    val level: RiskLevel,
    val reasons: List<RiskReason>,
    val mitigations: List<RiskReason> = emptyList()
) {
    companion object {
        val none = Verdict(0, RiskLevel.SAFE, emptyList())

        fun fromScore(
            score: Int,
            reasons: List<RiskReason>,
            mitigations: List<RiskReason> = emptyList()
        ): Verdict {
            val clamped = score.coerceIn(0, 100)
            val level = when {
                clamped >= 70 -> RiskLevel.DANGER
                clamped >= 45 -> RiskLevel.WARN
                clamped >= 20 -> RiskLevel.INFO
                else -> RiskLevel.SAFE
            }
            return Verdict(clamped, level, reasons, mitigations)
        }
    }
}

data class GeoInfo(
    val country: String = "",
    val countryCode: String = "",
    val city: String = "",
    val region: String = "",
    val org: String = "",
    val isp: String = "",
    val asn: String = "",
    val asname: String = "",
    val host: String = "",
    val hosting: Boolean = false,
    val proxy: Boolean = false,
    val mobile: Boolean = false
) {
    fun location(): String = listOfNotNull(
        city.ifBlank { null },
        region.ifBlank { null },
        country.ifBlank { null }
    ).joinToString(", ")
}

data class ThreatInfo(
    val abuseScore: Int = -1,
    val totalReports: Int = 0,
    val lastReportEpochSec: Long = 0L,
    val isTor: Boolean = false,
    val dnsblHits: List<String> = emptyList(),
    val passiveDnsRecords: Int = 0,
    val passiveDnsNames: String = "",
    val rdapName: String = "",
    val rdapOrg: String = "",
    val rdapAbuse: String = "",
    val rdapCidr: String = "",
    val rdapRegisteredEpochSec: Long = 0L,
    val vtMalicious: Int = 0,
    val vtSuspicious: Int = 0,
    val vtTotal: Int = 0,
    val vtReputation: Int = 0,
    /** Which of the configured sources actually answered, so the UI can show coverage. */
    val sourcesAnswered: List<String> = emptyList()
)

data class CertInfo(
    val subject: String = "",
    val issuer: String = "",
    val subjectAlternativeNames: List<String> = emptyList(),
    val notBeforeEpochSec: Long = 0L,
    val notAfterEpochSec: Long = 0L,
    val serial: String = "",
    val sha256Fingerprint: String = "",
    val selfSigned: Boolean = false,
    val expired: Boolean = false,
    val notYetValid: Boolean = false,
    val nameMismatch: Boolean = false,
    val chainLength: Int = 0,
    val protocol: String = "",
    val cipherSuite: String = ""
)

data class BannerInfo(
    val statusLine: String = "",
    val server: String = "",
    val via: String = "",
    val endOfLife: Boolean = false,
    val eolDetail: String = "",
    val responseMs: Long = 0L
)

/** One investigated destination. Everything below [input] is either real or explicitly
 *  marked unavailable — there is no third option. */
data class Target(
    val input: String,
    val ip: String? = null,
    val port: Int? = null,
    val addedAtMs: Long = System.currentTimeMillis(),
    val resolve: IntelResult<String> = IntelResult.idle(),
    val reverseDns: IntelResult<String> = IntelResult.idle(),
    val geo: IntelResult<GeoInfo> = IntelResult.idle(),
    val threat: IntelResult<ThreatInfo> = IntelResult.idle(),
    val cert: IntelResult<CertInfo> = IntelResult.idle(),
    val banner: IntelResult<BannerInfo> = IntelResult.idle(),
    val verdict: Verdict = Verdict.none,
    val note: String = ""
) {
    val key: String get() = if (port != null) "$ip:$port" else (ip ?: input)
    val display: String get() = ip ?: input
}

/** A row of the Apps tab. Every field comes from the framework; nothing is estimated. */
data class AppTraffic(
    val uid: Int,
    val packageName: String,
    val label: String,
    val rxBytes: Long,
    val txBytes: Long,
    val rateIn: Double = 0.0,
    val rateOut: Double = 0.0,
    val supported: Boolean = true,
    val system: Boolean = false,
    val versionName: String? = null,
    val installer: String? = null,
    val apkPath: String? = null,
    val apkSha256: String? = null,
    val signerSubject: String? = null,
    val signerIssuer: String? = null,
    val signerSha256: String? = null,
    val firstInstallMs: Long = 0L,
    val lastUpdateMs: Long = 0L,
    val targetSdk: Int = 0,
    val requestedPermissions: List<String> = emptyList(),
    val active: Boolean = false,
    val lastChangeMs: Long = 0L
) {
    val totalBytes: Long get() = rxBytes + txBytes
}

data class InterfaceInfo(
    val name: String,
    val displayName: String,
    val addresses: List<String>,
    val mtu: Int,
    val hardwareAddress: String?,
    val up: Boolean,
    val loopback: Boolean,
    val transport: String
)

data class LinkInfo(
    val networkName: String,
    val transport: String,
    val validated: Boolean,
    val metered: Boolean,
    val roaming: Boolean,
    val vpn: Boolean,
    val captivePortal: Boolean,
    val localAddresses: List<String>,
    val dnsServers: List<String>,
    val domains: List<String>,
    val routes: List<String>,
    val mtu: Int
)

data class WifiInfo(
    val available: Boolean,
    val ssid: String?,
    val bssid: String?,
    val rssi: Int?,
    val linkSpeedMbps: Int?,
    val frequencyMhz: Int?,
    val band: String?,
    val security: String?,
    val ip: String?,
    val gateway: String?,
    val detail: String? = null
)

data class CellularInfo(
    val available: Boolean,
    val operator: String?,
    val networkType: String?,
    val roaming: Boolean,
    val detail: String? = null
)

data class RateSample(val atMs: Long, val inBytesPerSec: Double, val outBytesPerSec: Double)

data class AnomalyAlert(
    val subject: String,
    val baseline: Double,
    val current: Double,
    val percent: Int,
    val atMs: Long
)

data class CountItem(val label: String, val sub: String, val value: Double, val count: Int)

data class DeviceSnapshot(
    val model: String,
    val manufacturer: String,
    val androidRelease: String,
    val sdkInt: Int,
    val securityPatch: String,
    val uptimeMs: Long,
    val publicIp: String? = null,
    val publicIpStatus: IntelStatus = IntelStatus.IDLE,
    val publicIpDetail: String? = null
)
