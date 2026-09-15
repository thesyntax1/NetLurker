package dev.netlurker.android.core

/**
 * Export formats. The desktop build writes JSON, CSV, HTML and TXT with a KPI block and an
 * anomaly section; the same four formats are produced here with the same field names so a
 * report from either platform can be compared side by side.
 *
 * Labels are injected as a resolver function so the export is written in the interface
 * language while the engine itself stays free of any Android dependency.
 */
data class ExportSnapshot(
    val generatedAtMs: Long,
    val appVersion: String,
    val language: String,
    val device: DeviceSnapshot?,
    val link: LinkInfo?,
    val wifi: WifiInfo?,
    val cellular: CellularInfo?,
    val apps: List<AppTraffic>,
    val targets: List<Target>,
    val alerts: List<AnomalyAlert>,
    val kpis: List<Pair<String, String>>,
    val trafficSupported: Boolean,
    val elapsedMs: Long
)

object Export {

    fun json(snapshot: ExportSnapshot): String {
        val w = JsonWriter()
        w.beginObject()
        w.name("netlurker"); w.beginObject()
        w.name("platform"); w.value("android")
        w.name("version"); w.value(snapshot.appVersion)
        w.name("language"); w.value(snapshot.language)
        w.name("generatedAt"); w.value(Format.epochIso(snapshot.generatedAtMs))
        w.name("sessionSeconds"); w.value(snapshot.elapsedMs / 1000L)
        w.endObject()

        w.name("kpis"); w.beginObject()
        for ((key, value) in snapshot.kpis) {
            w.name(key); w.value(value)
        }
        w.endObject()

        w.name("device")
        val device = snapshot.device
        if (device == null) {
            w.value(null as String?)
        } else {
            w.beginObject()
            w.name("model"); w.value(device.model)
            w.name("manufacturer"); w.value(device.manufacturer)
            w.name("android"); w.value(device.androidRelease)
            w.name("sdk"); w.value(device.sdkInt)
            w.name("securityPatch"); w.value(device.securityPatch)
            w.name("uptimeSeconds"); w.value(device.uptimeMs / 1000L)
            w.name("publicIp"); w.value(device.publicIp)
            w.name("publicIpStatus"); w.value(device.publicIpStatus.name)
            w.endObject()
        }

        w.name("network")
        val link = snapshot.link
        if (link == null) {
            w.value(null as String?)
        } else {
            w.beginObject()
            w.name("transport"); w.value(link.transport)
            w.name("validated"); w.value(link.validated)
            w.name("metered"); w.value(link.metered)
            w.name("roaming"); w.value(link.roaming)
            w.name("vpn"); w.value(link.vpn)
            w.name("captivePortal"); w.value(link.captivePortal)
            w.name("mtu"); w.value(link.mtu)
            w.name("addresses"); array(w, link.localAddresses)
            w.name("dns"); array(w, link.dnsServers)
            w.name("routes"); array(w, link.routes)
            w.endObject()
        }

        w.name("trafficCountersSupported"); w.value(snapshot.trafficSupported)

        w.name("applications"); w.beginArray()
        for (app in snapshot.apps) {
            w.beginObject()
            w.name("uid"); w.value(app.uid)
            w.name("package"); w.value(app.packageName)
            w.name("label"); w.value(app.label)
            w.name("system"); w.value(app.system)
            w.name("version"); w.value(app.versionName)
            w.name("installer"); w.value(app.installer)
            w.name("trafficCountersSupported"); w.value(app.supported)
            w.name("rxBytes"); w.value(app.rxBytes.takeIf { app.supported })
            w.name("txBytes"); w.value(app.txBytes.takeIf { app.supported })
            w.name("rxBytesPerSec"); w.value(if (app.supported) app.rateIn else Double.NaN)
            w.name("txBytesPerSec"); w.value(if (app.supported) app.rateOut else Double.NaN)
            w.name("signerSubject"); w.value(app.signerSubject)
            w.name("signerSha256"); w.value(app.signerSha256)
            w.name("apkSha256"); w.value(app.apkSha256)
            w.name("requestedPermissions"); w.value(app.requestedPermissions.size)
            w.endObject()
        }
        w.endArray()

        w.name("destinations"); w.beginArray()
        for (target in snapshot.targets) {
            w.beginObject()
            w.name("input"); w.value(target.input)
            w.name("ip"); w.value(target.ip)
            w.name("port"); w.value(target.port)
            w.name("riskScore"); w.value(target.verdict.score)
            w.name("riskLevel"); w.value(target.verdict.level.name)
            w.name("riskReasons"); array(w, target.verdict.reasons.map { it.key })
            w.name("reverseDnsStatus"); w.value(target.reverseDns.status.name)
            w.name("reverseDns"); w.value(target.reverseDns.value)
            w.name("geoStatus"); w.value(target.geo.status.name)
            w.name("geoDetail"); w.value(target.geo.detail)
            w.name("geoAtEpochSec"); w.value(target.geo.atEpochSec.takeIf { it > 0 })
            target.geo.value?.let { geo ->
                w.name("country"); w.value(geo.country)
                w.name("countryCode"); w.value(geo.countryCode)
                w.name("city"); w.value(geo.city)
                w.name("org"); w.value(geo.org)
                w.name("asn"); w.value(geo.asn)
                w.name("hosting"); w.value(geo.hosting)
                w.name("proxy"); w.value(geo.proxy)
            }
            w.name("threatStatus"); w.value(target.threat.status.name)
            w.name("threatDetail"); w.value(target.threat.detail)
            w.name("threatAtEpochSec"); w.value(target.threat.atEpochSec.takeIf { it > 0 })
            target.threat.value?.let { threat ->
                w.name("abuseScore"); w.value(threat.abuseScore.takeIf { it >= 0 })
                w.name("abuseReports"); w.value(threat.totalReports.takeIf { threat.abuseScore >= 0 })
                w.name("dnsblHits"); array(w, threat.dnsblHits)
                w.name("passiveDnsRecords"); w.value(threat.passiveDnsRecords.takeIf { it >= 0 })
                w.name("rdapOrg"); w.value(threat.rdapOrg)
                w.name("rdapCidr"); w.value(threat.rdapCidr)
                w.name("vtMalicious"); w.value(threat.vtMalicious.takeIf { threat.vtTotal > 0 })
                w.name("vtTotal"); w.value(threat.vtTotal.takeIf { it > 0 })
                w.name("sourcesAnswered"); array(w, threat.sourcesAnswered)
            }
            w.name("certStatus"); w.value(target.cert.status.name)
            w.name("certDetail"); w.value(target.cert.detail)
            w.name("certAtEpochSec"); w.value(target.cert.atEpochSec.takeIf { it > 0 })
            target.cert.value?.let { cert ->
                w.name("certSubject"); w.value(cert.subject)
                w.name("certIssuer"); w.value(cert.issuer)
                w.name("certNotAfter"); w.value(cert.notAfterEpochSec)
                w.name("certSelfSigned"); w.value(cert.selfSigned)
                w.name("certExpired"); w.value(cert.expired)
                w.name("certNameMismatch"); w.value(cert.nameMismatch)
            }
            w.name("bannerStatus"); w.value(target.banner.status.name)
            w.name("bannerDetail"); w.value(target.banner.detail)
            w.name("bannerAtEpochSec"); w.value(target.banner.atEpochSec.takeIf { it > 0 })
            target.banner.value?.let { banner ->
                w.name("server"); w.value(banner.server)
                w.name("bannerEndOfLife"); w.value(banner.endOfLife)
            }
            w.endObject()
        }
        w.endArray()

        w.name("anomalies"); w.beginArray()
        for (alert in snapshot.alerts) {
            w.beginObject()
            w.name("subject"); w.value(alert.subject)
            w.name("baselineBytesPerSec"); w.value(alert.baseline)
            w.name("currentBytesPerSec"); w.value(alert.current)
            w.name("percentAboveBaseline"); w.value(alert.percent)
            w.name("at"); w.value(Format.epochIso(alert.atMs))
            w.endObject()
        }
        w.endArray()

        w.endObject()
        return w.build()
    }

    fun csv(snapshot: ExportSnapshot): String {
        val sb = StringBuilder()
        sb.append("type;name;package;uid;rx_bytes;tx_bytes;rx_bps;tx_bps;")
            .append("signer;apk_sha256;installer;system\r\n")
        for (app in snapshot.apps) {
            sb.append("app;")
                .append(escapeCsv(app.label)).append(';')
                .append(escapeCsv(app.packageName)).append(';')
                .append(app.uid).append(';')
                .append(if (app.supported) app.rxBytes.toString() else "").append(';')
                .append(if (app.supported) app.txBytes.toString() else "").append(';')
                .append(if (app.supported) app.rateIn.toLong().toString() else "").append(';')
                .append(if (app.supported) app.rateOut.toLong().toString() else "").append(';')
                .append(escapeCsv(app.signerSubject.orEmpty())).append(';')
                .append(escapeCsv(app.apkSha256.orEmpty())).append(';')
                .append(escapeCsv(app.installer.orEmpty())).append(';')
                .append(app.system)
                .append("\r\n")
        }
        sb.append("type;destination;ip;port;risk;level;geo_status;country;org;")
            .append("abuse_score;dnsbl;rdap_org;vt;cert_status;cert_issuer;banner\r\n")
        for (target in snapshot.targets) {
            val geo = target.geo.value
            val threat = target.threat.value
            val cert = target.cert.value
            sb.append("destination;")
                .append(escapeCsv(target.input)).append(';')
                .append(escapeCsv(target.ip.orEmpty())).append(';')
                .append(target.port ?: "").append(';')
                .append(target.verdict.score).append(';')
                .append(target.verdict.level.name).append(';')
                .append(target.geo.status.name).append(';')
                .append(escapeCsv(geo?.country.orEmpty())).append(';')
                .append(escapeCsv(geo?.org.orEmpty())).append(';')
                .append(threat?.abuseScore ?: "").append(';')
                .append(escapeCsv(threat?.dnsblHits?.joinToString("|").orEmpty())).append(';')
                .append(escapeCsv(threat?.rdapOrg.orEmpty())).append(';')
                .append(if (threat != null && threat.vtTotal > 0) "${threat.vtMalicious}/${threat.vtTotal}" else "")
                .append(';')
                .append(target.cert.status.name).append(';')
                .append(escapeCsv(cert?.issuer.orEmpty())).append(';')
                .append(escapeCsv(target.banner.value?.server.orEmpty()))
                .append("\r\n")
        }
        sb.append("type;subject;baseline_bps;current_bps;percent;at\r\n")
        for (alert in snapshot.alerts) {
            sb.append("anomaly;")
                .append(escapeCsv(alert.subject)).append(';')
                .append(alert.baseline.toLong()).append(';')
                .append(alert.current.toLong()).append(';')
                .append(alert.percent).append(';')
                .append(Format.epochIso(alert.atMs))
                .append("\r\n")
        }
        return sb.toString()
    }

    fun text(snapshot: ExportSnapshot, label: (String) -> String): String {
        val sb = StringBuilder()
        sb.append(label("export.title")).append('\n')
        sb.append("=".repeat(60)).append('\n')
        sb.append(label("export.generated")).append(": ")
            .append(Format.epochIso(snapshot.generatedAtMs)).append('\n')
        sb.append(label("export.session")).append(": ")
            .append(Format.durationLong(snapshot.elapsedMs / 1000)).append('\n')
        snapshot.device?.let { device ->
            sb.append(label("export.device")).append(": ")
                .append(device.manufacturer).append(' ').append(device.model)
                .append(" (Android ").append(device.androidRelease)
                .append(", API ").append(device.sdkInt).append(")\n")
        }
        sb.append('\n').append(label("export.kpis")).append('\n')
        sb.append("-".repeat(60)).append('\n')
        for ((key, value) in snapshot.kpis) {
            sb.append(key).append(": ").append(value).append('\n')
        }

        sb.append('\n').append(label("export.anomalies"))
            .append(" (").append(snapshot.alerts.size).append(")\n")
        sb.append("-".repeat(60)).append('\n')
        if (snapshot.alerts.isEmpty()) {
            sb.append(label("export.no_anomalies")).append('\n')
        } else {
            for (alert in snapshot.alerts) {
                sb.append("- ").append(alert.subject)
                    .append("  ").append(Format.bytesPerSec(alert.current))
                    .append("  (baseline ").append(Format.bytesPerSec(alert.baseline))
                    .append(", +").append(alert.percent).append("%)\n")
            }
        }

        sb.append('\n').append(label("export.applications"))
            .append(" (").append(snapshot.apps.size).append(")\n")
        sb.append("-".repeat(60)).append('\n')
        if (!snapshot.trafficSupported) {
            sb.append(label("traffic.unsupported")).append('\n')
        }
        for (app in snapshot.apps.sortedByDescending { it.totalBytes }.take(100)) {
            sb.append(String.format(java.util.Locale.ROOT, "%-28s %10s %10s %10s\n",
                app.label.take(28),
                (if (app.supported) Format.bytes(app.totalBytes) else "—"),
                (if (app.supported) Format.bytesPerSec(app.rateIn) else "—"),
                (if (app.supported) Format.bytesPerSec(app.rateOut) else "—")))
        }

        sb.append('\n').append(label("export.destinations"))
            .append(" (").append(snapshot.targets.size).append(")\n")
        sb.append("-".repeat(60)).append('\n')
        for (target in snapshot.targets) {
            sb.append(target.display)
            if (target.port != null) sb.append(':').append(target.port)
            sb.append("  ").append(target.verdict.score).append("/100 ")
                .append(target.verdict.level.name)
            target.geo.value?.let { geo ->
                sb.append("  ").append(geo.country.ifBlank { "?" })
                if (geo.org.isNotBlank()) sb.append(" / ").append(geo.org)
            }
            sb.append('\n')
            for (reason in target.verdict.reasons) {
                sb.append("    - ").append(reason.key)
                if (reason.args.isNotEmpty()) sb.append(" [").append(reason.args.joinToString(", ")).append(']')
                sb.append(" (+").append(reason.points).append(")\n")
            }
            for (mitigation in target.verdict.mitigations) {
                sb.append("    + ").append(mitigation.key).append('\n')
            }
        }
        sb.append('\n').append(label("export.privacy")).append('\n')
        return sb.toString()
    }

    fun html(snapshot: ExportSnapshot, label: (String) -> String): String {
        val sb = StringBuilder()
        sb.append("<!DOCTYPE html>\n<html lang=\"").append(escapeHtml(snapshot.language))
            .append("\">\n<head>\n<meta charset=\"utf-8\">\n")
            .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
            .append("<title>").append(escapeHtml(label("export.title"))).append("</title>\n")
            .append("<style>")
            .append("body{background:#0d1117;color:#e6edf3;font:14px/1.5 system-ui,sans-serif;margin:24px}")
            .append("h1{font-size:20px}h2{font-size:16px;margin-top:28px;color:#8b949e}")
            .append("table{border-collapse:collapse;width:100%;margin-top:8px}")
            .append("th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #29313d;font-size:13px}")
            .append("th{color:#8b949e;font-weight:600}")
            .append(".SAFE{color:#3fb950}.INFO{color:#39c5cf}.WARN{color:#e2a833}.DANGER{color:#f85149}")
            .append(".kpi{display:inline-block;background:#161b22;border:1px solid #29313d;")
            .append("border-radius:8px;padding:10px 14px;margin:4px 8px 4px 0}")
            .append(".kpi b{display:block;font-size:18px}")
            .append("code{color:#8b949e}")
            .append("</style>\n</head>\n<body>\n")
            .append("<h1>").append(escapeHtml(label("export.title"))).append("</h1>\n")
            .append("<p><code>").append(escapeHtml(Format.epochIso(snapshot.generatedAtMs)))
            .append("</code> · ").append(escapeHtml(snapshot.appVersion))
            .append(" · ").append(escapeHtml(label("export.session"))).append(": ")
            .append(Format.durationLong(snapshot.elapsedMs / 1000)).append("</p>\n")

        sb.append("<h2>").append(escapeHtml(label("export.kpis"))).append("</h2>\n<div>")
        for ((key, value) in snapshot.kpis) {
            sb.append("<div class=\"kpi\"><span>").append(escapeHtml(key))
                .append("</span><b>").append(escapeHtml(value)).append("</b></div>")
        }
        sb.append("</div>\n")

        sb.append("<h2>").append(escapeHtml(label("export.anomalies")))
            .append(" (").append(snapshot.alerts.size).append(")</h2>\n")
        if (snapshot.alerts.isEmpty()) {
            sb.append("<p>").append(escapeHtml(label("export.no_anomalies"))).append("</p>\n")
        } else {
            sb.append("<table><tr><th>").append(escapeHtml(label("col.app")))
                .append("</th><th>").append(escapeHtml(label("col.current")))
                .append("</th><th>").append(escapeHtml(label("col.baseline")))
                .append("</th><th>+</th></tr>")
            for (alert in snapshot.alerts) {
                sb.append("<tr><td>").append(escapeHtml(alert.subject))
                    .append("</td><td>").append(Format.bytesPerSec(alert.current))
                    .append("</td><td>").append(Format.bytesPerSec(alert.baseline))
                    .append("</td><td>").append(alert.percent).append("%</td></tr>")
            }
            sb.append("</table>\n")
        }

        sb.append("<h2>").append(escapeHtml(label("export.destinations")))
            .append(" (").append(snapshot.targets.size).append(")</h2>\n")
        sb.append("<table><tr><th>").append(escapeHtml(label("col.destination")))
            .append("</th><th>").append(escapeHtml(label("col.risk")))
            .append("</th><th>").append(escapeHtml(label("col.geo")))
            .append("</th><th>").append(escapeHtml(label("col.org")))
            .append("</th><th>").append(escapeHtml(label("col.evidence"))).append("</th></tr>")
        for (target in snapshot.targets.sortedByDescending { it.verdict.score }) {
            val geo = target.geo.value
            sb.append("<tr><td>").append(escapeHtml(target.display))
            if (target.port != null) sb.append(':').append(target.port)
            sb.append("</td><td class=\"").append(target.verdict.level.name).append("\">")
                .append(target.verdict.score).append("/100</td><td>")
                .append(escapeHtml(geo?.country.orEmpty()))
                .append("</td><td>").append(escapeHtml(geo?.org.orEmpty()))
                .append("</td><td>")
            for (reason in target.verdict.reasons) {
                sb.append("• ").append(escapeHtml(reason.key))
                if (reason.args.isNotEmpty()) {
                    sb.append(" [").append(escapeHtml(reason.args.joinToString(", "))).append(']')
                }
                sb.append("<br>")
            }
            sb.append("</td></tr>")
        }
        sb.append("</table>\n")

        sb.append("<h2>").append(escapeHtml(label("export.applications")))
            .append(" (").append(snapshot.apps.size).append(")</h2>\n")
        if (!snapshot.trafficSupported) {
            sb.append("<p>").append(escapeHtml(label("traffic.unsupported"))).append("</p>\n")
        } else {
            sb.append("<table><tr><th>").append(escapeHtml(label("col.app")))
                .append("</th><th>").append(escapeHtml(label("col.total")))
                .append("</th><th>↓</th><th>↑</th><th>")
                .append(escapeHtml(label("col.signer"))).append("</th></tr>")
            for (app in snapshot.apps.sortedByDescending { it.totalBytes }.take(200)) {
                sb.append("<tr><td>").append(escapeHtml(app.label))
                    .append("<br><code>").append(escapeHtml(app.packageName)).append("</code>")
                    .append("</td><td>").append((if (app.supported) Format.bytes(app.totalBytes) else "—"))
                    .append("</td><td>").append((if (app.supported) Format.bytesPerSec(app.rateIn) else "—"))
                    .append("</td><td>").append((if (app.supported) Format.bytesPerSec(app.rateOut) else "—"))
                    .append("</td><td>").append(escapeHtml(app.signerSubject.orEmpty()))
                    .append("</td></tr>")
            }
            sb.append("</table>\n")
        }

        sb.append("<p><code>").append(escapeHtml(label("export.privacy"))).append("</code></p>\n")
        sb.append("</body>\n</html>\n")
        return sb.toString()
    }

    private fun array(writer: JsonWriter, values: List<String>) {
        writer.beginArray()
        for (value in values) writer.value(value)
        writer.endArray()
    }

    internal fun escapeCsv(value: String): String {
        val first = value.firstOrNull { !it.isWhitespace() && it.code >= 32 }
        val text = if (first in listOf('=', '+', '-', '@')) "'$value" else value
        if (text.none { it == ';' || it == '"' || it == '\n' || it == '\r' }) return text
        return '"' + text.replace("\"", "\"\"") + '"'
    }

    fun escapeHtml(value: String): String = buildString(value.length) {
        for (ch in value) {
            when (ch) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\'' -> append("&#39;")
                else -> append(ch)
            }
        }
    }
}
