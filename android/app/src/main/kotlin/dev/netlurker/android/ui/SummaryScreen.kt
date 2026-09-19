package dev.netlurker.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.netlurker.android.MainViewModel
import dev.netlurker.android.core.Format
import dev.netlurker.android.core.RiskLevel

/**
 * Summary: KPIs, the risk distribution of what has been investigated, and the top talkers.
 *
 * The desktop build's Net Graph draws process ↔ destination edges. Android does not expose
 * which app opened which socket, so this screen draws the two things it can prove — how
 * much each application moved, and where the investigated destinations are — and says in
 * one line why the edge graph is absent rather than drawing edges nobody measured.
 */
@Composable
fun SummaryScreen(viewModel: MainViewModel) {
    val s = strings()
    val snapshot by viewModel.snapshot.collectAsState()
    val apps by viewModel.apps.collectAsState()
    val alerts by viewModel.alerts.collectAsState()
    val targets by viewModel.intel.targets.collectAsState()

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 12.dp)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(top = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            KpiTile(
                label = s("kpi.download"),
                value = Format.bytesPerSec(snapshot?.rateInBytesPerSec ?: 0.0),
                color = NL.Accent,
                modifier = Modifier.weight(1f),
                sub = Format.bytes(snapshot?.sessionRxBytes ?: 0L)
            )
            KpiTile(
                label = s("kpi.upload"),
                value = Format.bytesPerSec(snapshot?.rateOutBytesPerSec ?: 0.0),
                color = NL.Orange,
                modifier = Modifier.weight(1f),
                sub = Format.bytes(snapshot?.sessionTxBytes ?: 0L)
            )
        }
        Row(
            Modifier.fillMaxWidth().padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            KpiTile(
                label = s("kpi.apps"),
                value = apps.size.toString(),
                modifier = Modifier.weight(1f),
                sub = "${apps.count { it.active }} ${s("kpi.active_now")}"
            )
            KpiTile(
                label = s("kpi.destinations"),
                value = targets.size.toString(),
                modifier = Modifier.weight(1f),
                sub = "${targets.count { it.verdict.score >= 45 }} ${s("kpi.suspicious")}"
            )
            KpiTile(
                label = s("kpi.anomalies"),
                value = alerts.size.toString(),
                color = if (alerts.isEmpty()) NL.Green else NL.Yellow,
                modifier = Modifier.weight(1f),
                sub = s("kpi.session") + " " + Format.durationShort(viewModel.history.elapsedMs / 1000L)
            )
        }

        SectionHeader(s("section.risk_distribution"))
        val levels = listOf(RiskLevel.SAFE, RiskLevel.INFO, RiskLevel.WARN, RiskLevel.DANGER)
        val counts = levels.associateWith { level -> targets.count { it.verdict.level == level } }
        val total = targets.size.coerceAtLeast(1)
        Column(
            Modifier
                .fillMaxWidth()
                .background(NL.Surface, RoundedCornerShape(10.dp))
                .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
                .padding(12.dp)
        ) {
            if (targets.isEmpty()) {
                Text(
                    text = s("summary.no_destinations"),
                    color = NL.TextFaint,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            for (level in levels) {
                val count = counts[level] ?: 0
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = s("risk.level.${level.name.lowercase()}"),
                        color = NL.risk(level),
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.width(96.dp)
                    )
                    Box(
                        Modifier
                            .weight(1f)
                            .height(12.dp)
                            .background(NL.RowAlt, RoundedCornerShape(6.dp))
                    ) {
                        if (count > 0) {
                            Box(
                                Modifier
                                    .fillMaxWidth((count.toFloat() / total).coerceIn(0.03f, 1f))
                                    .height(12.dp)
                                    .background(NL.risk(level), RoundedCornerShape(6.dp))
                            )
                        }
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = count.toString(),
                        color = NL.TextDim,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.width(28.dp)
                    )
                }
            }
        }

        SectionHeader(s("section.top_talkers"))
        BarList(
            items = viewModel.history.topApps(apps, 10).map { it.label to it.value },
            formatter = { Format.bytes(it.toLong()) }
        )

        SectionHeader(s("section.top_countries"))
        val countries = viewModel.history.topCountries(targets, 8)
        if (countries.isEmpty()) {
            Text(
                text = s("summary.no_geo"),
                color = NL.TextFaint,
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            BarList(
                items = countries.map { "${it.label} (${it.count})" to it.value },
                formatter = { it.toInt().toString() }
            )
        }

        SectionHeader(s("section.top_organisations"))
        val orgs = viewModel.history.topOrganisations(targets, 8)
        if (orgs.isEmpty()) {
            Text(
                text = s("summary.no_orgs"),
                color = NL.TextFaint,
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            BarList(items = orgs.map { it.label to it.value }, formatter = { it.toInt().toString() })
        }

        SectionHeader(s("section.most_risky"))
        val risky = targets.sortedByDescending { it.verdict.score }.take(8)
        if (risky.isEmpty()) {
            Text(
                text = s("summary.no_destinations"),
                color = NL.TextFaint,
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            for (target in risky) {
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = target.display + (target.port?.let { ":$it" } ?: ""),
                            color = NL.Text,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium
                        )
                        Text(
                            text = target.geo.value?.let { "${it.country} · ${it.org}" }
                                ?: s("geo.status.${target.geo.status.name.lowercase()}"),
                            color = NL.TextFaint,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                    RiskBadge(target.verdict.score, target.verdict.level)
                }
            }
        }

        SectionHeader(s("section.graph"))
        Column(
            Modifier
                .fillMaxWidth()
                .background(NL.Surface, RoundedCornerShape(10.dp))
                .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
                .padding(12.dp)
        ) {
            Text(
                text = s("graph.no_edges"),
                color = NL.Yellow,
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = s("graph.what_is_shown"),
                color = NL.TextDim,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 6.dp)
            )
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun BarList(items: List<Pair<String, Double>>, formatter: (Double) -> String) {
    if (items.isEmpty()) {
        Text(
            text = strings()("summary.no_data"),
            color = NL.TextFaint,
            style = MaterialTheme.typography.bodySmall
        )
        return
    }
    val max = (items.maxOfOrNull { it.second } ?: 1.0).coerceAtLeast(1.0)
    Column(
        Modifier
            .fillMaxWidth()
            .background(NL.Surface, RoundedCornerShape(10.dp))
            .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        for ((label, value) in items) {
            Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = label,
                    color = NL.Text,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.width(150.dp),
                    maxLines = 1
                )
                Box(Modifier.weight(1f).height(10.dp).background(NL.RowAlt, RoundedCornerShape(5.dp))) {
                    Box(
                        Modifier
                            .fillMaxWidth((value / max).toFloat().coerceIn(0.02f, 1f))
                            .height(10.dp)
                            .background(NL.Cyan, RoundedCornerShape(5.dp))
                    )
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    text = formatter(value),
                    color = NL.TextDim,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.width(76.dp)
                )
            }
        }
    }
}
