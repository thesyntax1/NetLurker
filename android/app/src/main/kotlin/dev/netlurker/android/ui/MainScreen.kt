package dev.netlurker.android.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
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
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: MainViewModel) {
    val s = strings()
    val context = LocalContext.current
    var tab by remember { mutableIntStateOf(0) }
    var showSettings by remember { mutableStateOf(false) }
    var showExport by remember { mutableStateOf(false) }
    var showPermissions by remember { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    val running by viewModel.running.collectAsState()
    val snapshot by viewModel.snapshot.collectAsState()

    val locationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        viewModel.setLocationPermission(granted)
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
                            color = if (running) NL.Green else NL.Yellow
                        )
                    }
                },
                actions = {
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
                    TextButton(onClick = { showSettings = true }) {
                        Text("⚙", color = NL.TextDim, style = MaterialTheme.typography.titleMedium)
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = NL.Surface,
                contentColor = NL.Text,
                tonalElevation = 0.dp
            ) {
                val tabs = listOf(
                    "tab.investigate" to "◎",
                    "tab.apps" to "▤",
                    "tab.network" to "⇄",
                    "tab.history" to "≡",
                    "tab.summary" to "∑"
                )
                tabs.forEachIndexed { index, (key, glyph) ->
                    NavigationBarItem(
                        selected = tab == index,
                        onClick = { tab = index },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = NL.RowSel,
                            selectedIconColor = NL.Accent,
                            selectedTextColor = NL.Accent,
                            unselectedIconColor = NL.TextFaint,
                            unselectedTextColor = NL.TextFaint
                        ),
                        icon = { Text(glyph, style = MaterialTheme.typography.titleMedium) },
                        label = {
                            Text(s(key), style = MaterialTheme.typography.labelSmall)
                        }
                    )
                }
            }
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (tab) {
                0 -> InvestigateScreen(viewModel)
                1 -> AppsScreen(viewModel)
                2 -> NetworkScreen(viewModel) { locationLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION) }
                3 -> HistoryScreen(viewModel)
                else -> SummaryScreen(viewModel)
            }
        }
    }

    if (showSettings) {
        SettingsDialog(viewModel, onRequestLocation = {
            locationLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
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
                locationLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
            },
            onDismiss = { showPermissions = false }
        )
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
    val label = viewModel.getApplication<android.app.Application>()
        .let { Strings(it) }
        .resolver()
    val snapshot = viewModel.buildExportSnapshot(
        language = java.util.Locale.getDefault().language,
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
