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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.netlurker.android.MainViewModel
import dev.netlurker.android.core.Format

/**
 * History: the session record and the anomaly detector.
 *
 * The detector is the desktop build's EMA + 3σ model applied to per-application throughput.
 * It only speaks once it has 24 samples, and its output always shows the baseline next to
 * the spike so the number can be checked rather than taken on faith.
 */
@Composable
fun HistoryScreen(viewModel: MainViewModel) {
    val s = strings()
    val snapshot by viewModel.snapshot.collectAsState()
    val alerts by viewModel.alerts.collectAsState()
    val apps by viewModel.apps.collectAsState()
    @Suppress("UNUSED_VARIABLE")
    val historyRevision by viewModel.historyRevision.collectAsState()
    val baselineCount = viewModel.history.baselineSize()

    // The rolling window lives in the session object; reading it here each recomposition
    // keeps the source of truth in one place.
    val samples = viewModel.history.rateWindowSnapshot()
    val peak = samples.maxOfOrNull { maxOf(it.inBytesPerSec, it.outBytesPerSec) } ?: 0.0

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
                label = s("kpi.session"),
                value = Format.durationLong(viewModel.history.elapsedMs / 1000L),
                modifier = Modifier.weight(1f)
            )
            KpiTile(
                label = s("kpi.anomalies"),
                value = alerts.size.toString(),
                color = if (alerts.isEmpty()) NL.Green else NL.Yellow,
                modifier = Modifier.weight(1f)
            )
            KpiTile(
                label = s("kpi.baselines"),
                value = baselineCount.toString(),
                modifier = Modifier.weight(1f)
            )
        }

        SectionHeader(s("section.rate_history"), trailing = s("history.window"))
        RateSparkline(samples)
        SparklineLegend(peak)

        SectionHeader(s("section.anomalies"), trailing = alerts.size.toString())
        if (alerts.isEmpty()) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(NL.Surface, RoundedCornerShape(10.dp))
                    .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
                    .padding(12.dp)
            ) {
                Text(
                    text = s("anomalies.none"),
                    color = NL.TextDim,
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    text = s("anomalies.warmup", "samples" to "24"),
                    color = NL.TextFaint,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        } else {
            for (alert in alerts) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp)
                        .background(NL.Surface, RoundedCornerShape(10.dp))
                        .border(1.dp, NL.Yellow.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                        .padding(12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = alert.subject,
                            color = NL.Text,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = "+${alert.percent}%",
                            color = NL.Yellow,
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Text(
                        text = "${Format.bytesPerSec(alert.current)}  ·  " +
                            s("anomalies.baseline") + " " + Format.bytesPerSec(alert.baseline) +
                            "  ·  " + Format.clockTime(alert.atMs),
                        color = NL.TextDim,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }

        SectionHeader(s("section.top_apps"), trailing = apps.size.toString())
        val top = viewModel.history.topApps(apps, 15)
        if (top.isEmpty()) {
            Text(
                text = s("history.no_traffic_yet"),
                color = NL.TextFaint,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(vertical = 8.dp)
            )
        } else {
            val max = (top.maxOfOrNull { it.value } ?: 1.0).coerceAtLeast(1.0)
            for (item in top) {
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = item.label,
                        color = NL.Text,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.width(150.dp),
                        maxLines = 1
                    )
                    Column(Modifier.weight(1f)) {
                        Box(
                            Modifier
                                .fillMaxWidth()
                                .height(10.dp)
                                .background(NL.RowAlt, RoundedCornerShape(5.dp))
                        ) {
                            Box(
                                Modifier
                                    .fillMaxWidth((item.value / max).toFloat().coerceIn(0.02f, 1f))
                                    .height(10.dp)
                                    .background(NL.Accent, RoundedCornerShape(5.dp))
                            )
                        }
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = Format.bytes(item.value.toLong()),
                        color = NL.TextDim,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.width(72.dp),
                        textAlign = TextAlign.End
                    )
                }
            }
        }

        SectionHeader(s("section.session_counters"))
        Column(
            Modifier
                .fillMaxWidth()
                .background(NL.Surface, RoundedCornerShape(10.dp))
                .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
                .padding(12.dp)
        ) {
            InfoRow(s("field.session_down"), Format.bytes(snapshot?.sessionRxBytes ?: 0L))
            InfoRow(s("field.session_up"), Format.bytes(snapshot?.sessionTxBytes ?: 0L))
            InfoRow(
                s("field.total_down"),
                Format.bytes(snapshot?.totalRxBytes ?: 0L) + " (" + s("counters.since_boot") + ")"
            )
            InfoRow(
                s("field.total_up"),
                Format.bytes(snapshot?.totalTxBytes ?: 0L) + " (" + s("counters.since_boot") + ")"
            )
            InfoRow(s("field.baselines"), baselineCount.toString())
        }

        Row(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            TextButton(onClick = { viewModel.resetSession() }) {
                Text(s("action.reset_session"), color = NL.Red, style = MaterialTheme.typography.labelSmall)
            }
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = { viewModel.clearBaselines() }) {
                Text(s("action.clear_baselines"), color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}
