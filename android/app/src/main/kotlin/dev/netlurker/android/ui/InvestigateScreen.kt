package dev.netlurker.android.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import dev.netlurker.android.MainViewModel
import dev.netlurker.android.ai.AiClient
import dev.netlurker.android.core.Format
import dev.netlurker.android.core.IntelStatus
import dev.netlurker.android.core.Ports
import dev.netlurker.android.core.Target
import kotlinx.coroutines.launch

/**
 * Investigate: the destinations tab.
 *
 * On Windows NetLurker discovers destinations from the kernel socket table. An unrooted
 * Android app is denied that table, so this tab does not pretend to discover anything: it
 * investigates what you give it (an address, a host, a port) and shows only what the
 * lookups actually returned. The panel says plainly what each source answered, what is
 * still querying, and what is switched off.
 */
@Composable
fun InvestigateScreen(viewModel: MainViewModel) {
    val s = strings()
    val targets by viewModel.intel.targets.collectAsState()
    var input by remember { mutableStateOf("") }
    var expanded by remember { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(top = 10.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                placeholder = {
                    Text(s("investigate.placeholder"), color = NL.TextFaint,
                        style = MaterialTheme.typography.bodySmall)
                },
                textStyle = MaterialTheme.typography.bodyMedium,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = {
                    if (input.isNotBlank()) {
                        viewModel.intel.addTarget(parseInput(input).first, parseInput(input).second)
                        input = ""
                    }
                }),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = NL.Accent,
                    unfocusedBorderColor = NL.Border,
                    focusedTextColor = NL.Text,
                    unfocusedTextColor = NL.Text,
                    cursorColor = NL.Accent
                )
            )
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = {
                if (input.isNotBlank()) {
                    val (host, port) = parseInput(input)
                    viewModel.intel.addTarget(host, port)
                    input = ""
                }
            }) {
                Text(s("investigate.add"), color = NL.Accent, style = MaterialTheme.typography.labelMedium)
            }
        }

        Text(
            text = s("investigate.hint"),
            color = NL.TextFaint,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(bottom = 6.dp)
        )

        if (targets.isEmpty()) {
            EmptyState(
                title = s("investigate.empty.title"),
                detail = s("investigate.empty.detail")
            )
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(targets, key = { it.key }) { target ->
                    TargetCard(
                        target = target,
                        viewModel = viewModel,
                        expanded = expanded == target.key,
                        onToggle = { expanded = if (expanded == target.key) null else target.key }
                    )
                }
                item { Spacer(Modifier.height(16.dp)) }
            }
        }
    }
}

/** Accepts "1.2.3.4", "example.com", "example.com:8443". */
internal fun parseInput(raw: String): Pair<String, Int?> {
    val trimmed = raw.trim()
    val lastColon = trimmed.lastIndexOf(':')
    if (lastColon > 0 && lastColon < trimmed.length - 1) {
        val portText = trimmed.substring(lastColon + 1)
        if (portText.all { it.isDigit() } && portText.length <= 5) {
            val port = portText.toIntOrNull()
            if (port != null && port in 1..65535) {
                return trimmed.substring(0, lastColon) to port
            }
        }
    }
    return trimmed to null
}

@Composable
private fun TargetCard(
    target: Target,
    viewModel: MainViewModel,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    val s = strings()
    val context = LocalContext.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val aiClient = remember { AiClient(viewModel.settings) }
    var report by remember { mutableStateOf<String?>(null) }
    var reportPending by remember { mutableStateOf(false) }

    Column(
        Modifier
            .fillMaxWidth()
            .background(NL.Surface, RoundedCornerShape(10.dp))
            .border(
                1.dp,
                if (target.verdict.score >= 45) NL.riskScore(target.verdict.score).copy(alpha = 0.5f)
                else NL.Border,
                RoundedCornerShape(10.dp)
            )
            .clickable { onToggle() }
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = target.display + (target.port?.let { ":$it" } ?: ""),
                    color = NL.Text,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                val geo = target.geo.value
                Text(
                    text = when {
                        target.geo.status == IntelStatus.PENDING -> s("status.querying")
                        target.geo.status == IntelStatus.OK && geo != null ->
                            listOf(
                                geo.country.ifBlank { "?" },
                                geo.org.ifBlank { null }
                            ).filterNotNull().joinToString(" · ")
                        else -> s("geo.status.${target.geo.status.name.lowercase()}")
                    },
                    color = NL.TextDim,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            RiskBadge(target.verdict.score, target.verdict.level)
        }

        Spacer(Modifier.height(6.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            SourceDot(s("source.rdns"), target.reverseDns.status)
            SourceDot(s("source.geo"), target.geo.status)
            SourceDot(s("source.threat"), target.threat.status)
            SourceDot(s("source.cert"), target.cert.status)
            SourceDot(s("source.banner"), target.banner.status)
        }

        if (!expanded) return@Column

        Spacer(Modifier.height(10.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(NL.Border)
        )
        Spacer(Modifier.height(10.dp))

        InfoRow(s("field.input"), target.input, mono = true)
        target.resolve.value?.let { InfoRow(s("field.resolved"), it, mono = true) }
        target.port?.let { port ->
            InfoRow(
                s("field.service"),
                Ports.serviceName(port) ?: s("field.service.unknown")
            )
        }
        InfoRow(
            s("field.reverse_dns"),
            target.reverseDns.value ?: statusText(target.reverseDns.status, target.reverseDns.detail),
            valueColor = if (target.reverseDns.status == IntelStatus.OK) NL.Text else statusColor(target.reverseDns.status),
            mono = true
        )

        SectionHeader(s("section.geolocation"))
        when (target.geo.status) {
            IntelStatus.OK -> target.geo.value?.let { geo ->
                InfoRow(s("field.location"), geo.location().ifBlank { "—" })
                InfoRow(s("field.country"), "${geo.country.ifBlank { "—" }} (${geo.countryCode})")
                InfoRow(s("field.org"), geo.org.ifBlank { "—" })
                InfoRow(s("field.asn"), listOf(geo.asn, geo.asname).filter { it.isNotBlank() }
                    .joinToString(" ").ifBlank { "—" }, mono = true)
                InfoRow(s("field.flags"), buildString {
                    if (geo.hosting) append(s("flag.datacenter")).append("  ")
                    if (geo.proxy) append(s("flag.proxy")).append("  ")
                    if (geo.mobile) append(s("flag.mobile"))
                }.ifBlank { s("flag.none") })
                target.geo.detail?.let {
                    InfoRow(s("field.note"), it, valueColor = NL.Yellow)
                }
            }
            else -> InfoRow(
                s("section.geolocation"),
                statusText(target.geo.status, target.geo.detail),
                valueColor = statusColor(target.geo.status)
            )
        }

        if (target.hostsRedirect) {
            InfoRow(s("field.hosts"), s("hosts.redirected"), valueColor = NL.Yellow)
        }

        SectionHeader(s("section.threat"))
        when (target.threat.status) {
            IntelStatus.OK -> target.threat.value?.let { threat ->
                InfoRow(
                    s("field.abuseipdb"),
                    if (threat.abuseScore >= 0) "${threat.abuseScore}/100 · ${threat.totalReports} ${s("field.reports")}"
                    else s("field.abuseipdb.no_key"),
                    valueColor = when {
                        threat.abuseScore >= 80 -> NL.Red
                        threat.abuseScore >= 50 -> NL.Yellow
                        threat.abuseScore >= 25 -> NL.Orange
                        else -> NL.Text
                    }
                )
                InfoRow(
                    s("field.dnsbl"),
                    if (threat.dnsblHits.isEmpty()) s("field.dnsbl.clean")
                    else threat.dnsblHits.joinToString(", "),
                    valueColor = if (threat.dnsblHits.isEmpty()) NL.Green else NL.Red
                )
                InfoRow(
                    s("field.passive_dns"),
                    if (threat.passiveDnsRecords == 0) "0"
                    else "${threat.passiveDnsRecords}" +
                        (threat.passiveDnsNames.takeIf { it.isNotBlank() }?.let { " · $it" } ?: "")
                )
                if (threat.rdapOrg.isNotBlank() || threat.rdapCidr.isNotBlank()) {
                    InfoRow(s("field.ownership"), threat.rdapOrg.ifBlank { "—" })
                    if (threat.rdapCidr.isNotBlank()) InfoRow(s("field.cidr"), threat.rdapCidr, mono = true)
                    if (threat.rdapAbuse.isNotBlank()) InfoRow(s("field.abuse_contact"), threat.rdapAbuse, mono = true)
                    if (threat.rdapRegisteredEpochSec > 0) {
                        InfoRow(
                            s("field.registered"),
                            Format.epochIso(threat.rdapRegisteredEpochSec * 1000L)
                        )
                    }
                }
                if (threat.vtTotal > 0) {
                    InfoRow(
                        s("field.virustotal"),
                        "${threat.vtMalicious}/${threat.vtTotal} · ${s("field.reputation")} ${threat.vtReputation}",
                        valueColor = if (threat.vtMalicious > 0) NL.Red else NL.Green
                    )
                }
                InfoRow(
                    s("field.sources"),
                    threat.sourcesAnswered.joinToString(", ").ifBlank { "—" },
                    valueColor = NL.TextDim, mono = true
                )
                target.threat.detail?.let {
                    InfoRow(s("field.note"), it, valueColor = NL.Yellow)
                }
            }
            else -> InfoRow(
                s("section.threat"),
                statusText(target.threat.status, target.threat.detail),
                valueColor = statusColor(target.threat.status)
            )
        }

        SectionHeader(s("section.certificate"))
        when (target.cert.status) {
            IntelStatus.OK -> target.cert.value?.let { cert ->
                InfoRow(s("field.subject"), cert.subject, mono = true)
                InfoRow(s("field.issuer"), cert.issuer, mono = true)
                InfoRow(
                    s("field.validity"),
                    "${Format.epochIso(cert.notBeforeEpochSec * 1000L)} → " +
                        Format.epochIso(cert.notAfterEpochSec * 1000L)
                )
                InfoRow(s("field.fingerprint"), cert.sha256Fingerprint, mono = true)
                val flags = buildList {
                    if (cert.selfSigned) add(s("cert.self_signed"))
                    if (cert.expired) add(s("cert.expired"))
                    if (cert.notYetValid) add(s("cert.not_yet_valid"))
                    if (cert.nameMismatch) add(s("cert.name_mismatch"))
                }
                InfoRow(
                    s("field.findings"),
                    if (flags.isEmpty()) s("cert.clean") else flags.joinToString(" · "),
                    valueColor = if (flags.isEmpty()) NL.Green else NL.Red
                )
                InfoRow(s("field.tls"), "${cert.protocol} · ${cert.cipherSuite}", mono = true)
            }
            else -> InfoRow(
                s("section.certificate"),
                statusText(target.cert.status, target.cert.detail),
                valueColor = statusColor(target.cert.status)
            )
        }

        SectionHeader(s("section.banner"))
        when (target.banner.status) {
            IntelStatus.OK -> target.banner.value?.let { banner ->
                InfoRow(s("field.status_line"), banner.statusLine.ifBlank { "—" }, mono = true)
                InfoRow(s("field.server"), banner.server.ifBlank { "—" }, mono = true)
                if (banner.endOfLife) {
                    InfoRow(s("field.eol"), banner.eolDetail, valueColor = NL.Orange)
                }
                InfoRow(s("field.latency"), "${banner.responseMs} ms")
            }
            else -> InfoRow(
                s("section.banner"),
                statusText(target.banner.status, target.banner.detail),
                valueColor = statusColor(target.banner.status)
            )
        }

        SectionHeader(s("section.verdict"))
        VerdictPanel(target.verdict)

        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            TextButton(onClick = { viewModel.intel.investigate(target.key, force = true) }) {
                Text(s("action.recheck"), color = NL.Accent, style = MaterialTheme.typography.labelSmall)
            }
            TextButton(
                onClick = {
                    reportPending = true
                    scope.launch {
                        val result = aiClient.analyse(
                            target = target,
                            appCount = viewModel.apps.value.size,
                            languageName = languageName(),
                            label = s.resolver()
                        )
                        report = result.text
                        reportPending = false
                    }
                },
                enabled = !reportPending
            ) {
                Text(
                    text = if (reportPending) s("status.querying") else s("action.ai_analyze"),
                    color = NL.Purple,
                    style = MaterialTheme.typography.labelSmall
                )
            }
            TextButton(onClick = { openBrowser(context, "https://www.virustotal.com/gui/ip-address/${target.ip ?: target.input}") }) {
                Text("VirusTotal", color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            }
            TextButton(onClick = { openBrowser(context, "https://www.abuseipdb.com/check/${target.ip ?: target.input}") }) {
                Text("AbuseIPDB", color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            TextButton(onClick = { openBrowser(context, "https://cve.circl.lu/pdns/query/${target.ip ?: target.input}") }) {
                Text(s("action.passive_dns"), color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            }
            TextButton(onClick = { openBrowser(context, "https://rdap.org/ip/${target.ip ?: target.input}") }) {
                Text("RDAP", color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            }
            TextButton(onClick = { viewModel.intel.removeTarget(target.key) }) {
                Text(s("action.remove"), color = NL.Red, style = MaterialTheme.typography.labelSmall)
            }
        }

        report?.let { text ->
            Spacer(Modifier.height(8.dp))
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(NL.RowAlt, RoundedCornerShape(8.dp))
                    .border(1.dp, NL.Purple.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                Text(
                    text = s("report.title"),
                    color = NL.Purple,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(6.dp))
                Text(text = text, color = NL.Text, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun SourceDot(label: String, status: IntelStatus) {
    val color = statusColor(status)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .width(8.dp)
                .height(8.dp)
                .background(color, RoundedCornerShape(4.dp))
        )
        Spacer(Modifier.width(3.dp))
        Text(
            text = label,
            color = NL.TextFaint,
            style = MaterialTheme.typography.labelSmall
        )
        Spacer(Modifier.width(8.dp))
    }
}

private fun languageName(): String = when (java.util.Locale.getDefault().language) {
    "tr" -> "Turkish"
    "es" -> "Spanish"
    "de" -> "German"
    "fr" -> "French"
    "ja" -> "Japanese"
    "zh" -> "Simplified Chinese"
    "pt" -> "Portuguese"
    else -> "English"
}

internal fun openBrowser(context: android.content.Context, url: String) {
    runCatching {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }
}
