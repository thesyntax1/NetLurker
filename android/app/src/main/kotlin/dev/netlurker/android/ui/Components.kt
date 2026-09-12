package dev.netlurker.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.netlurker.android.core.Format
import dev.netlurker.android.core.IntelStatus
import dev.netlurker.android.core.RateSample
import dev.netlurker.android.core.RiskLevel

/** Risk badge: score over 100 plus the level word, in the level's colour. */
@Composable
fun RiskBadge(score: Int, level: RiskLevel, modifier: Modifier = Modifier) {
    val color = NL.riskScore(score)
    Row(
        modifier = modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(6.dp))
            .border(1.dp, color.copy(alpha = 0.6f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = "$score",
            color = color,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.width(6.dp))
        Text(
            text = strings()("risk.level.${level.name.lowercase()}"),
            color = color.copy(alpha = 0.85f),
            style = MaterialTheme.typography.labelSmall
        )
    }
}

/** One KPI tile, as on the desktop status bar. */
@Composable
fun KpiTile(
    label: String,
    value: String,
    color: Color = NL.Text,
    modifier: Modifier = Modifier,
    sub: String? = null
) {
    Column(
        modifier = modifier
            .background(NL.Surface, RoundedCornerShape(10.dp))
            .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Text(
            text = label.uppercase(),
            color = NL.TextFaint,
            style = MaterialTheme.typography.labelSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Spacer(Modifier.height(2.dp))
        Text(
            text = value,
            color = color,
            style = MaterialTheme.typography.titleMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        if (sub != null) {
            Text(text = sub, color = NL.TextDim, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
fun SectionHeader(text: String, trailing: String? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 18.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = text.uppercase(),
            color = NL.Accent,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.weight(1f))
        if (trailing != null) {
            Text(text = trailing, color = NL.TextFaint, style = MaterialTheme.typography.labelSmall)
        }
    }
}

/** Label/value row used in every detail panel. Values are shown verbatim — including the
 *  explicit "unavailable" wording — so a blank line can never be read as "nothing found". */
@Composable
fun InfoRow(label: String, value: String, valueColor: Color = NL.Text, mono: Boolean = false) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = label,
            color = NL.TextDim,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.width(132.dp)
        )
        Text(
            text = value,
            color = valueColor,
            style = if (mono) MaterialTheme.typography.labelMedium else MaterialTheme.typography.bodySmall
        )
    }
}

/** Colour for a lookup status, matching the desktop build's semantics. */
fun statusColor(status: IntelStatus): Color = when (status) {
    IntelStatus.OK -> NL.Text
    IntelStatus.PENDING -> NL.Cyan
    IntelStatus.FAILED -> NL.Red
    IntelStatus.OFFLINE -> NL.Yellow
    IntelStatus.DISABLED -> NL.TextFaint
    IntelStatus.UNAVAILABLE -> NL.TextFaint
    IntelStatus.IDLE -> NL.TextFaint
}

/** Wording for a lookup status. Never returns an empty string. */
@Composable
fun statusText(status: IntelStatus, detail: String? = null): String {
    val s = strings()
    return when (status) {
        IntelStatus.OK -> detail ?: s("status.ok")
        IntelStatus.PENDING -> s("status.querying")
        IntelStatus.FAILED -> s("status.failed") + (detail?.let { " — $it" } ?: "")
        IntelStatus.OFFLINE -> s("status.offline") + (detail?.let { " — $it" } ?: "")
        IntelStatus.DISABLED -> s("status.disabled") + (detail?.let { " — $it" } ?: "")
        IntelStatus.UNAVAILABLE -> s("status.unavailable") + (detail?.let { " — $it" } ?: "")
        IntelStatus.IDLE -> s("status.idle")
    }
}

/**
 * Two-series sparkline over the rolling rate window, drawn like the desktop graph:
 * download in accent blue, upload in orange, on a bordered surface.
 */
@Composable
fun RateSparkline(
    samples: List<RateSample>,
    modifier: Modifier = Modifier,
    heightDp: Int = 56
) {
    val accent = NL.Accent
    val orange = NL.Orange
    val grid = NL.Border
    val faint = NL.TextFaint
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .height(heightDp.dp)
            .background(NL.Surface, RoundedCornerShape(8.dp))
            .border(1.dp, NL.Border, RoundedCornerShape(8.dp))
    ) {
        val width = size.width
        val height = size.height
        if (samples.size < 2) {
            // Nothing to draw yet: the panel next to it says so in words, the canvas
            // carries only the baseline so the empty state is not mistaken for a flat line.
            drawLine(grid, Offset(0f, height - 1f), Offset(width, height - 1f), 1f)
            return@Canvas
        }
        val peak = (samples.maxOf { maxOf(it.inBytesPerSec, it.outBytesPerSec) }).coerceAtLeast(1.0)
        val stepX = width / (samples.size - 1).toFloat()

        // quarter grid
        for (i in 1..3) {
            val y = height * i / 4f
            drawLine(grid.copy(alpha = 0.5f), Offset(0f, y), Offset(width, y), 1f)
        }

        fun pathOf(selector: (RateSample) -> Double): Path {
            val path = Path()
            samples.forEachIndexed { index, sample ->
                val x = index * stepX
                val y = height - (selector(sample) / peak * height * 0.92).toFloat()
                if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            return path
        }
        drawPath(pathOf { it.inBytesPerSec }, accent, style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2f, cap = StrokeCap.Round))
        drawPath(pathOf { it.outBytesPerSec }, orange, style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2f, cap = StrokeCap.Round))

        drawLine(faint.copy(alpha = 0.4f), Offset(0f, height - 1f), Offset(width, height - 1f), 1f)
    }
}

/** Peak label drawn next to the sparkline so the axis is not a mystery. */
@Composable
fun SparklineLegend(peakBytesPerSec: Double) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(10.dp).height(2.dp).background(NL.Accent))
            Spacer(Modifier.width(4.dp))
            Text(strings()("graph.download"), color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            Spacer(Modifier.width(10.dp))
            Box(Modifier.width(10.dp).height(2.dp).background(NL.Orange))
            Spacer(Modifier.width(4.dp))
            Text(strings()("graph.upload"), color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
        }
        Text(
            text = strings()("graph.peak", "value" to Format.bytesPerSec(peakBytesPerSec)),
            color = NL.TextFaint,
            style = MaterialTheme.typography.labelSmall
        )
    }
}

/** Shown whenever a panel has nothing real to display. */
@Composable
fun EmptyState(title: String, detail: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 28.dp, horizontal = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = title, color = NL.TextDim, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(
            text = detail,
            color = NL.TextFaint,
            style = MaterialTheme.typography.bodySmall
        )
    }
}
