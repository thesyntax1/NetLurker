package dev.netlurker.android.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.size
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import dev.netlurker.android.MainViewModel
import dev.netlurker.android.core.Export
import dev.netlurker.android.core.Format

/**
 * The shell: title bar with the live rates, five tabs, and the dialogs for settings and
 * export.
 *
 * Tab mapping from the desktop build: Connections -> Investigate (see README-android.md for
 * why an unrooted Android device cannot produce a socket table), Apps -> Apps, History ->
 * History, Summary -> Summary, Net Graph -> the graph section inside Summary.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun MainScreen(viewModel: MainViewModel) {
    val s = strings()
    val context = LocalContext.current
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var showSettings by rememberSaveable { mutableStateOf(false) }
    var showExport by rememberSaveable { mutableStateOf(false) }
    var showPermissions by remember { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    val running by viewModel.running.collectAsState()
    val snapshot by viewModel.snapshot.collectAsState()

    // Android 12+ requires coarse and fine location to be requested together.
    val locationPermissions = remember {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
    }
    val locationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { granted ->
        viewModel.setLocationPermission(granted[Manifest.permission.ACCESS_FINE_LOCATION] == true)
    }
    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* the in-app alert list works either way; nothing to do here */ }

    LaunchedEffect(Unit) {
        val hasLocation = ContextCompat.checkSelfPermission(
            context, Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        viewModel.setLocationPermission(hasLocation)
        if (!hasLocation) showPermissions = true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasNotifications = ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!hasNotifications) notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        viewModel.start()
    }

    Scaffold(
        containerColor = NL.Bg,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            Column {
                TopAppBar(
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = NL.Surface,
                        titleContentColor = NL.Text,
                        actionIconContentColor = NL.TextDim
                    ),
                    title = {
                        Column {
                            Text(
                                text = "NetLurker",
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                                color = NL.Text
                            )
                            Text(
                                text = "↓ ${Format.bytesPerSec(snapshot?.rateInBytesPerSec ?: 0.0)}" +
                                    "   ↑ ${Format.bytesPerSec(snapshot?.rateOutBytesPerSec ?: 0.0)}" +
                                    if (running) "   ●" else "   ⏸",
                                style = MaterialTheme.typography.labelSmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                color = if (running) NL.Green else NL.Yellow
                            )
                        }
                    },
                    actions = {
                        TextButton(onClick = { showSettings = true },
                            modifier = Modifier.semantics { contentDescription = s("settings.title") }) {
                            Text("⚙", color = NL.TextDim, style = MaterialTheme.typography.titleMedium)
                        }
                    }
                )
                FlowRow(
                    modifier = Modifier.padding(horizontal = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextButton(onClick = { if (running) viewModel.stop() else viewModel.start() }) {
                        Text(
                            text = if (running) s("action.pause") else s("action.resume"),
                            color = NL.TextDim,
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                    TextButton(onClick = { showExport = true }) {
                        Text(s("action.export"), color = NL.TextDim, style = MaterialTheme.typography.labelMedium)
                    }
                }
            }
        },
        bottomBar = {
            // Keep the navigation item geometry predictable. The old text-glyph icons
            // had different font metrics, and two-line labels made the captions appear
            // vertically shifted on compact screens and in longer locales.
            NavigationBar(
                modifier = Modifier.drawBehind {
                    drawLine(
                        color = NL.Border,
                        start = Offset(0f, 0f),
                        end = Offset(size.width, 0f),
                        strokeWidth = 1.dp.toPx()
                    )
                },
                containerColor = NL.Surface,
                contentColor = NL.Text,
                tonalElevation = 0.dp
            ) {
                val tabs = listOf(
                    "tab.investigate" to NavIcon.Investigate,
                    "tab.apps" to NavIcon.Apps,
                    "tab.network" to NavIcon.Network,
                    "tab.history" to NavIcon.History,
                    "tab.summary" to NavIcon.Summary
                )
                tabs.forEachIndexed { index, (key, icon) ->
                    val selected = tab == index
                    NavigationBarItem(
                        selected = selected,
                        onClick = { tab = index },
                        alwaysShowLabel = true,
                        modifier = Modifier.semantics {
                            contentDescription = s(key)
                        },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = NL.RowSel,
                            selectedIconColor = NL.Accent,
                            selectedTextColor = NL.Accent,
                            unselectedIconColor = NL.TextFaint,
                            unselectedTextColor = NL.TextFaint
                        ),
                        icon = {
                            NavIconView(
                                icon = icon,
                                tint = if (selected) NL.Accent else NL.TextFaint
                            )
                        },
                        label = {
                            Text(
                                text = s(key),
                                // One measured line keeps every caption on the same
                                // baseline; truncation is preferable to a displaced tab.
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Default,
                                    fontSize = 10.sp,
                                    lineHeight = 14.sp,
                                    letterSpacing = 0.sp,
                                    fontWeight = FontWeight.Medium
                                ),
                                maxLines = 1,
                                softWrap = false,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    )
                }
            }
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()) {
            when (tab) {
                0 -> InvestigateScreen(viewModel)
                1 -> AppsScreen(viewModel)
                2 -> NetworkScreen(viewModel) { locationLauncher.launch(locationPermissions) }
                3 -> HistoryScreen(viewModel)
                else -> SummaryScreen(viewModel)
            }
        }
    }

    if (showSettings) {
        SettingsDialog(viewModel, onRequestLocation = {
            locationLauncher.launch(locationPermissions)
        }, onDismiss = { showSettings = false })
    }
    if (showExport) {
        ExportDialog(
            viewModel,
            onDismiss = { showExport = false },
            onMessage = { message -> scope.launch { snackbar.showSnackbar(message) } }
        )
    }
    if (showPermissions) {
        PermissionRationaleDialog(
            onGrant = {
                showPermissions = false
                locationLauncher.launch(locationPermissions)
            },
            onDismiss = { showPermissions = false }
        )
    }
}

private enum class NavIcon {
    Investigate, Apps, Network, History, Summary
}

/**
 * Small, fixed-size line icons for the bottom navigation. Keeping the geometry in Compose
 * avoids relying on Unicode glyphs: glyph widths and baselines vary by device font and were
 * the source of the old tab-bar drift.
 */
@Composable
private fun NavIconView(icon: NavIcon, tint: androidx.compose.ui.graphics.Color) {
    Canvas(Modifier.size(24.dp)) {
        val unit = minOf(size.width, size.height) / 24f
        val stroke = Stroke(
            width = 1.8f * unit,
            cap = StrokeCap.Round,
            join = StrokeJoin.Round
        )
        val center = Offset(size.width / 2f, size.height / 2f)

        fun point(x: Float, y: Float) = Offset(x * unit, y * unit)
        fun square(left: Float, top: Float, width: Float, height: Float) {
            drawRect(
                color = tint,
                topLeft = point(left, top),
                size = androidx.compose.ui.geometry.Size(width * unit, height * unit),
                style = stroke
            )
        }

        when (icon) {
            NavIcon.Investigate -> {
                drawCircle(tint, radius = 8f * unit, center = center, style = stroke)
                drawCircle(tint, radius = 2.5f * unit, center = center)
                drawLine(tint, point(2f, 12f), point(5f, 12f), stroke.width)
                drawLine(tint, point(19f, 12f), point(22f, 12f), stroke.width)
                drawLine(tint, point(12f, 2f), point(12f, 5f), stroke.width)
                drawLine(tint, point(12f, 19f), point(12f, 22f), stroke.width)
            }
            NavIcon.Apps -> {
                square(3.5f, 3.5f, 7f, 7f)
                square(13.5f, 3.5f, 7f, 7f)
                square(3.5f, 13.5f, 7f, 7f)
                square(13.5f, 13.5f, 7f, 7f)
            }
            NavIcon.Network -> {
                val path = Path().apply {
                    moveTo(6f * unit, 7f * unit)
                    lineTo(18f * unit, 7f * unit)
                    lineTo(6f * unit, 17f * unit)
                    lineTo(18f * unit, 17f * unit)
                }
                drawPath(path, tint, style = stroke)
                drawCircle(tint, radius = 2.5f * unit, center = point(6f, 7f))
                drawCircle(tint, radius = 2.5f * unit, center = point(18f, 7f))
                drawCircle(tint, radius = 2.5f * unit, center = point(6f, 17f))
                drawCircle(tint, radius = 2.5f * unit, center = point(18f, 17f))
            }
            NavIcon.History -> {
                drawCircle(tint, radius = 8.5f * unit, center = center, style = stroke)
                drawLine(tint, center, point(12f, 6f), stroke.width)
                drawLine(tint, center, point(17f, 14f), stroke.width)
                drawLine(tint, point(3f, 7f), point(3f, 3f), stroke.width)
                drawLine(tint, point(3f, 7f), point(7f, 7f), stroke.width)
            }
            NavIcon.Summary -> {
                drawLine(tint, point(3f, 21f), point(21f, 21f), stroke.width)
                drawRect(tint, point(5f, 14f), androidx.compose.ui.geometry.Size(3f * unit, 7f * unit))
                drawRect(tint, point(10.5f, 9f), androidx.compose.ui.geometry.Size(3f * unit, 12f * unit))
                drawRect(tint, point(16f, 5f), androidx.compose.ui.geometry.Size(3f * unit, 16f * unit))
            }
        }
    }
}

/** Writes an export through the Storage Access Framework — the only way an app may create
 *  a file the user can see, and the only way NetLurker writes anything at all. */
fun writeExport(context: Context, uri: android.net.Uri, content: String): Boolean =
    runCatching {
        context.contentResolver.openOutputStream(uri)?.use { stream ->
            stream.write(content.toByteArray(Charsets.UTF_8))
        } ?: return false
        true
    }.getOrDefault(false)

fun exportContent(kind: String, viewModel: MainViewModel): String {
    val strings = Strings(viewModel.getApplication<android.app.Application>())
    val label = strings.resolver()
    val snapshot = viewModel.buildExportSnapshot(
        language = strings.language,
        kpis = viewModel.defaultKpis().map { (key, value) -> label("kpi.$key") to value }
    )
    return when (kind) {
        "json" -> Export.json(snapshot)
        "csv" -> Export.csv(snapshot)
        "html" -> Export.html(snapshot, label)
        else -> Export.text(snapshot, label)
    }
}

/** Row used by several screens: a leading glyph, a title and a trailing value. */
@Composable
fun LabeledValue(label: String, value: String, modifier: Modifier = Modifier) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Text(
            text = label,
            color = NL.TextDim,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.width(120.dp)
        )
        Text(text = value, color = NL.Text, style = MaterialTheme.typography.bodySmall)
    }
}
