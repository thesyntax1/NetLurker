package dev.netlurker.android.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import dev.netlurker.android.core.RiskLevel

/**
 * The desktop palette, copied value for value from src/ui_draw.h so a screenshot of the
 * Windows build and one of the phone look like the same product.
 */
object NL {
    val Bg = Color(0xFF0D1117)
    val Surface = Color(0xFF161B22)
    val SurfaceHi = Color(0xFF1C222B)
    val RowAlt = Color(0xFF11151C)
    val RowHover = Color(0xFF1F2630)
    val RowSel = Color(0xFF1E3354)
    val Border = Color(0xFF29313D)
    val Text = Color(0xFFE6EDF3)
    val TextDim = Color(0xFF8B949E)
    val TextFaint = Color(0xFF646C76)
    val Accent = Color(0xFF388BFD)
    val AccentDim = Color(0xFF1F5299)
    val Green = Color(0xFF3FB950)
    val Yellow = Color(0xFFE2A833)
    val Orange = Color(0xFFDB6D28)
    val Red = Color(0xFFF85149)
    val Purple = Color(0xFFA371F7)
    val Cyan = Color(0xFF39C5CF)

    fun risk(level: RiskLevel): Color = when (level) {
        RiskLevel.SAFE -> Green
        RiskLevel.INFO -> Cyan
        RiskLevel.WARN -> Yellow
        RiskLevel.DANGER -> Red
    }

    /** The desktop build shades the score badge continuously; same ramp here. */
    fun riskScore(score: Int): Color = when {
        score >= 70 -> Red
        score >= 45 -> Yellow
        score >= 20 -> Cyan
        else -> Green
    }
}

private val DarkColors = darkColorScheme(
    primary = NL.Accent,
    onPrimary = NL.Bg,
    primaryContainer = NL.AccentDim,
    onPrimaryContainer = NL.Text,
    secondary = NL.Cyan,
    onSecondary = NL.Bg,
    tertiary = NL.Purple,
    onTertiary = NL.Bg,
    background = NL.Bg,
    onBackground = NL.Text,
    surface = NL.Surface,
    onSurface = NL.Text,
    surfaceVariant = NL.SurfaceHi,
    onSurfaceVariant = NL.TextDim,
    outline = NL.Border,
    outlineVariant = NL.Border,
    error = NL.Red,
    onError = NL.Bg
)

private val NetLurkerTypography = Typography(
    titleLarge = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 18.sp,
        letterSpacing = 0.5.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 14.sp
    ),
    bodyLarge = TextStyle(fontSize = 15.sp),
    bodyMedium = TextStyle(fontSize = 13.sp),
    bodySmall = TextStyle(fontSize = 11.sp),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 12.sp,
        fontWeight = FontWeight.Medium
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 10.sp,
        letterSpacing = 0.4.sp
    )
)

@Composable
fun NetLurkerTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    CompositionLocalProvider(LocalStrings provides Strings(context)) {
        MaterialTheme(
            colorScheme = DarkColors,
            typography = NetLurkerTypography,
            content = content
        )
    }
}
