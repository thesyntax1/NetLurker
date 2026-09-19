package dev.netlurker.android.core

/**
 * Stable reason keys. The UI resolves each one to a string resource in the interface
 * language; the CI check asserts that every key here has a translation in all locales.
 */
object ReasonKeys {
    const val PORT_SUSPICIOUS = "risk.port_suspicious"
    const val PORT_UNKNOWN_SERVICE = "risk.port_unknown_service"
    const val PORT_RARE_PRIVILEGED = "risk.port_rare_privileged"
    const val PROXY_OR_VPN = "risk.proxy_or_vpn"
    const val TOR_EXIT = "risk.tor_exit"
    const val DATACENTER_NO_RDNS = "risk.datacenter_no_rdns"
    const val ABUSE_SCORE_HIGH = "risk.abuse_score_high"
    const val ABUSE_SCORE_MEDIUM = "risk.abuse_score_medium"
    const val ABUSE_SCORE_LOW = "risk.abuse_score_low"
    const val DNSBL_LISTED = "risk.dnsbl_listed"
    const val PASSIVE_DNS_MANY = "risk.passive_dns_many"
    const val CERT_SELF_SIGNED_DATACENTER = "risk.cert_self_signed_datacenter"
    const val CERT_SELF_SIGNED = "risk.cert_self_signed"
    const val CERT_EXPIRED = "risk.cert_expired"
    const val CERT_NOT_YET_VALID = "risk.cert_not_yet_valid"
    const val CERT_NAME_MISMATCH = "risk.cert_name_mismatch"
    const val VT_MALICIOUS_HIGH = "risk.vt_malicious_high"
    const val VT_MALICIOUS_LOW = "risk.vt_malicious_low"
    const val VT_SUSPICIOUS = "risk.vt_suspicious"
    const val BANNER_EOL = "risk.banner_eol"
    const val REGISTRATION_YOUNG = "risk.registration_young"
    const val APP_TRAFFIC_ANOMALY = "risk.app_traffic_anomaly"
    const val APP_EXFIL_RATIO = "risk.app_exfil_ratio"
    const val APP_BEACON = "risk.app_beacon"
    const val HOSTS_REDIRECT = "risk.hosts_redirect"

    const val MIT_PRIVATE_NETWORK = "risk.mit_private_network"
    const val MIT_COMMON_WEB_PORT = "risk.mit_common_web_port"
    const val MIT_RDAP_KNOWN_ORG = "risk.mit_rdap_known_org"
    const val MIT_CLEAN_ALL_SOURCES = "risk.mit_clean_all_sources"
    const val MIT_EVIDENCE_INCOMPLETE = "risk.mit_evidence_incomplete"

    /** Every key the engine can emit — the CI check asserts the UI resolves all of them. */
    val ALL: List<String> = listOf(
        PORT_SUSPICIOUS, PORT_UNKNOWN_SERVICE, PORT_RARE_PRIVILEGED, PROXY_OR_VPN, TOR_EXIT,
        DATACENTER_NO_RDNS, ABUSE_SCORE_HIGH, ABUSE_SCORE_MEDIUM, ABUSE_SCORE_LOW, DNSBL_LISTED,
        PASSIVE_DNS_MANY, CERT_SELF_SIGNED_DATACENTER, CERT_SELF_SIGNED, CERT_EXPIRED,
        CERT_NOT_YET_VALID, CERT_NAME_MISMATCH, VT_MALICIOUS_HIGH, VT_MALICIOUS_LOW,
        VT_SUSPICIOUS, BANNER_EOL, REGISTRATION_YOUNG, APP_TRAFFIC_ANOMALY,
        APP_EXFIL_RATIO, APP_BEACON, HOSTS_REDIRECT,
        MIT_PRIVATE_NETWORK, MIT_COMMON_WEB_PORT, MIT_RDAP_KNOWN_ORG, MIT_CLEAN_ALL_SOURCES,
        MIT_EVIDENCE_INCOMPLETE
    )
}

/**
 * Destination heuristics based on the desktop rules in src/netmon.cpp.
 * Windows-only process rules are excluded. Unavailable evidence contributes no
 * score or clean-result mitigation. App-level traffic rules are separate below.
 */
object RiskEngine {

    /** How many days an IP registration counts as "young" for the RDAP signal. */
    const val YOUNG_REGISTRATION_DAYS = 90L
    private const val SECONDS_PER_DAY = 86_400L

    fun evaluate(target: Target, nowEpochSec: Long = nowEpochSec()): Verdict {
        var score = 0
        val reasons = mutableListOf<RiskReason>()
        val mitigations = mutableListOf<RiskReason>()
        val pendingSources = mutableListOf<String>()

        fun add(points: Int, key: String, vararg args: String) {
            score += points
            reasons += RiskReason(key, args.toList(), points)
        }

        fun mitigate(points: Int, key: String, vararg args: String) {
            score -= points
            mitigations += RiskReason(key, args.toList(), points)
        }

        val ip = target.ip
        val isPublicIp = ip != null && Ip.isPublic(ip)

        // --- port ---------------------------------------------------------------
        val port = target.port
        if (port != null) {
            // Desktop rule: SMB, RDP, MS-RPC, NetBIOS and VNC only count when they face the
            // internet. A LAN share on 445 is normal; the same port on a public address is
            // not, so the address decides whether the rule fires at all.
            val internetFacingOnly = Ports.isInternetFacingOnly(port)
            if (Ports.suspicious.containsKey(port) && (!internetFacingOnly || isPublicIp)) {
                val points = Ports.suspicious.getValue(port).first
                // Only the port number travels in the reason; the note itself is resolved
                // by the UI from the localized "port_<n>" entry, so no English sentence is
                // ever pasted into a translated verdict.
                add(points, ReasonKeys.PORT_SUSPICIOUS, port.toString())
            }
            if (Ports.serviceName(port) == null && Ports.threatNote(port) == null) {
                if (port >= 1024) add(10, ReasonKeys.PORT_UNKNOWN_SERVICE, port.toString())
                else add(15, ReasonKeys.PORT_RARE_PRIVILEGED, port.toString())
            }
        }

        // --- geolocation --------------------------------------------------------
        val geo = if (target.geo.status == IntelStatus.OK) target.geo.value else null
        if (target.geo.status != IntelStatus.OK || target.geo.detail != null) pendingSources += "geo"
        if (geo != null) {
            if (geo.proxy) add(30, ReasonKeys.PROXY_OR_VPN)
            if (geo.hosting && geo.host.isBlank() && target.reverseDns.status == IntelStatus.OK &&
                target.reverseDns.value.isNullOrBlank()) {
                add(10, ReasonKeys.DATACENTER_NO_RDNS)
            }
        }

        // --- threat intelligence ------------------------------------------------
        val threat = if (target.threat.status == IntelStatus.OK) target.threat.value else null
        if (target.threat.status != IntelStatus.OK || target.threat.detail != null) pendingSources += "threat"
        if (threat != null) {
            when {
                threat.abuseScore >= 80 -> add(
                    35, ReasonKeys.ABUSE_SCORE_HIGH,
                    threat.abuseScore.toString(), threat.totalReports.toString()
                )
                threat.abuseScore >= 50 -> add(
                    20, ReasonKeys.ABUSE_SCORE_MEDIUM, threat.abuseScore.toString()
                )
                threat.abuseScore >= 25 -> add(
                    8, ReasonKeys.ABUSE_SCORE_LOW, threat.abuseScore.toString()
                )
            }
            if (threat.dnsblHits.isNotEmpty()) {
                add(30, ReasonKeys.DNSBL_LISTED, threat.dnsblHits.joinToString(", "))
            }
            if (threat.isTor && geo?.proxy != true) add(15, ReasonKeys.TOR_EXIT)
            if (threat.passiveDnsRecords >= 50) {
                add(6, ReasonKeys.PASSIVE_DNS_MANY, threat.passiveDnsRecords.toString())
            }
            when {
                threat.vtMalicious >= 5 -> add(
                    35, ReasonKeys.VT_MALICIOUS_HIGH,
                    threat.vtMalicious.toString(), threat.vtTotal.toString()
                )
                threat.vtMalicious >= 2 -> add(
                    20, ReasonKeys.VT_MALICIOUS_LOW,
                    threat.vtMalicious.toString(), threat.vtTotal.toString()
                )
                threat.vtSuspicious >= 5 -> add(
                    10, ReasonKeys.VT_SUSPICIOUS, threat.vtSuspicious.toString()
                )
            }
            if (threat.rdapRegisteredEpochSec in 1..nowEpochSec) {
                val ageDays = (nowEpochSec - threat.rdapRegisteredEpochSec) / SECONDS_PER_DAY
                if (ageDays in 0 until YOUNG_REGISTRATION_DAYS) {
                    add(8, ReasonKeys.REGISTRATION_YOUNG, ageDays.toString())
                } else if (threat.rdapOrg.isNotBlank()) {
                    mitigate(5, ReasonKeys.MIT_RDAP_KNOWN_ORG, threat.rdapOrg)
                }
            }
        }

        // --- TLS ----------------------------------------------------------------
        val cert = if (target.cert.status == IntelStatus.OK) target.cert.value else null
        if (target.cert.status != IntelStatus.OK || target.cert.detail != null) pendingSources += "cert"
        if (cert != null) {
            if (cert.selfSigned) {
                if (geo?.hosting == true) add(22, ReasonKeys.CERT_SELF_SIGNED_DATACENTER)
                else add(8, ReasonKeys.CERT_SELF_SIGNED)
            }
            if (cert.expired) add(18, ReasonKeys.CERT_EXPIRED)
            if (cert.notYetValid) add(12, ReasonKeys.CERT_NOT_YET_VALID)
            if (cert.nameMismatch) add(12, ReasonKeys.CERT_NAME_MISMATCH)
        }

        // The desktop scores a hosts-file override only for public destinations: pointing
        // "localhost" at 127.0.0.1 is normal, pointing a public name at a chosen address is
        // a redirection somebody configured.
        if (target.hostsRedirect && isPublicIp) add(15, ReasonKeys.HOSTS_REDIRECT)

        // --- HTTP banner --------------------------------------------------------
        val banner = if (target.banner.status == IntelStatus.OK) target.banner.value else null
        if (target.banner.status != IntelStatus.OK || target.banner.detail != null) pendingSources += "banner"
        if (banner != null && banner.endOfLife) {
            add(8, ReasonKeys.BANNER_EOL, banner.server.ifBlank { banner.statusLine })
        }

        // --- mitigations --------------------------------------------------------
        if (ip != null && !isPublicIp) mitigate(10, ReasonKeys.MIT_PRIVATE_NETWORK)
        if (port == 443 || port == 80) mitigate(5, ReasonKeys.MIT_COMMON_WEB_PORT, port.toString())

        val answeredSources = listOfNotNull(
            "geo".takeIf { target.geo.status == IntelStatus.OK },
            "threat".takeIf { target.threat.status == IntelStatus.OK },
            "cert".takeIf { target.cert.status == IntelStatus.OK },
            "banner".takeIf { target.banner.status == IntelStatus.OK }
        )
        if (reasons.isEmpty() && answeredSources.isNotEmpty()) {
            mitigate(0, ReasonKeys.MIT_CLEAN_ALL_SOURCES, answeredSources.size.toString())
        }
        if (pendingSources.isNotEmpty()) {
            mitigations += RiskReason(
                ReasonKeys.MIT_EVIDENCE_INCOMPLETE,
                listOf(pendingSources.joinToString(", ")),
                0
            )
        }

        return Verdict.fromScore(score, reasons, mitigations)
    }

    /**
     * Scores available app traffic using anomaly, upload-ratio and heartbeat rules.
     * The sampling unit is an app/UID, not a Windows connection; scores are not
     * calibrated between platforms. Package signature metadata is not scored here.
     */
    fun evaluateApp(
        app: AppTraffic,
        alert: AnomalyAlert?,
        beacon: BeaconDetector.Pattern? = null
    ): Verdict {
        val reasons = mutableListOf<RiskReason>()
        var score = 0

        fun add(points: Int, key: String, vararg args: String) {
            score += points
            reasons += RiskReason(key, args.toList(), points)
        }

        if (alert != null) {
            add(
                25, ReasonKeys.APP_TRAFFIC_ANOMALY,
                app.label, Format.bytesPerSec(alert.current), Format.percent(alert.percent.toDouble())
            )
        }

        // T1041: far more leaving than arriving, at a rate worth noticing. Requires the
        // counters to be supported, because a zero rateIn on an unsupported device is a
        // missing measurement rather than a quiet download.
        if (app.supported && app.rateOut > EXFIL_MIN_BYTES_PER_SEC &&
            app.rateOut > app.rateIn * EXFIL_RATIO
        ) {
            add(
                20, ReasonKeys.APP_EXFIL_RATIO,
                Format.bytesPerSec(app.rateOut), Format.bytesPerSec(app.rateIn)
            )
        }

        if (beacon != null && beacon.periodSec > 0) {
            add(
                if (beacon.periodSec <= BEACON_FAST_PERIOD_SEC) 25 else 12,
                ReasonKeys.APP_BEACON,
                beacon.periodSec.toString(), beacon.hits.toString()
            )
        }

        if (reasons.isEmpty()) return Verdict.none
        return Verdict.fromScore(score.coerceIn(0, 100), reasons)
    }

    /** Above this outbound rate an upload-heavy ratio is worth flagging (desktop: 200 KiB/s). */
    const val EXFIL_MIN_BYTES_PER_SEC = 200.0 * 1024.0

    /** Outbound must exceed inbound by this factor (desktop: 6x). */
    const val EXFIL_RATIO = 6.0

    /** A heartbeat this fast scores higher than a slow one (desktop: 120 s). */
    const val BEACON_FAST_PERIOD_SEC = 120
}
