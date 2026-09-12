package dev.netlurker.android.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import dev.netlurker.android.MainViewModel
import dev.netlurker.android.data.Settings

/** Full-width scrollable dialog; the content is dense and needs the room. */
@Composable
private fun WideDialog(onDismiss: () -> Unit, content: @Composable () -> Unit) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 24.dp)
                .heightIn(max = 640.dp)
                .background(NL.Bg, RoundedCornerShape(14.dp))
                .border(1.dp, NL.Border, RoundedCornerShape(14.dp))
        ) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp)
            ) {
                content()
            }
        }
    }
}

@Composable
private fun DialogTitle(text: String) {
    Text(
        text = text,
        color = NL.Text,
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold
    )
    Spacer(Modifier.height(12.dp))
}

@Composable
private fun ToggleRow(label: String, detail: String?, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(text = label, color = NL.Text, style = MaterialTheme.typography.bodyMedium)
            if (detail != null) {
                Text(text = detail, color = NL.TextFaint, style = MaterialTheme.typography.bodySmall)
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = NL.Bg,
                checkedTrackColor = NL.Accent,
                uncheckedThumbColor = NL.TextFaint,
                uncheckedTrackColor = NL.SurfaceHi,
                uncheckedBorderColor = NL.Border
            )
        )
    }
}

@Composable
private fun KeyField(label: String, value: String, hint: String, onChange: (String) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text(text = label, color = NL.TextDim, style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            placeholder = { Text(hint, color = NL.TextFaint, style = MaterialTheme.typography.bodySmall) },
            textStyle = MaterialTheme.typography.bodySmall,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = NL.Accent,
                unfocusedBorderColor = NL.Border,
                focusedTextColor = NL.Text,
                unfocusedTextColor = NL.Text,
                cursorColor = NL.Accent
            )
        )
    }
}

/**
 * Settings.
 *
 * The privacy panel is part of the dialog rather than a separate screen because the
 * desktop build treats it the same way: every external service is listed with its current
 * state, so there is never a hidden request leaving the device.
 */
@Composable
fun SettingsDialog(
    viewModel: MainViewModel,
    onRequestLocation: () -> Unit,
    onDismiss: () -> Unit
) {
    val s = strings()
    val settings = viewModel.settings

    // Local mirrors so toggling recomposes immediately; every write goes straight to prefs.
    var geo by remember { mutableStateOf(settings.geoEnabled) }
    var threat by remember { mutableStateOf(settings.threatEnabled) }
    var rdap by remember { mutableStateOf(settings.rdapEnabled) }
    var vt by remember { mutableStateOf(settings.vtEnabled) }
    var tls by remember { mutableStateOf(settings.tlsEnabled) }
    var banner by remember { mutableStateOf(settings.bannerEnabled) }
    var publicIp by remember { mutableStateOf(settings.publicIpEnabled) }
    var notify by remember { mutableStateOf(settings.anomalyNotifications) }
    var refresh by remember { mutableStateOf(settings.refreshMs.toFloat()) }
    var abuseKey by remember { mutableStateOf(settings.abuseIpDbKey) }
    var vtKey by remember { mutableStateOf(settings.virusTotalKey) }
    var aiEndpoint by remember { mutableStateOf(settings.aiEndpoint) }
    var aiModel by remember { mutableStateOf(settings.aiModel) }
    var aiKey by remember { mutableStateOf(settings.aiApiKey) }

    WideDialog(onDismiss = onDismiss) {
        DialogTitle(s("settings.title"))

        SectionHeader(s("section.sources"))
        ToggleRow(
            label = s("settings.geo"),
            detail = s("settings.geo.detail"),
            checked = geo
        ) { geo = it; settings.geoEnabled = it }
        ToggleRow(
            label = s("settings.threat"),
            detail = s("settings.threat.detail"),
            checked = threat
        ) { threat = it; settings.threatEnabled = it }
        ToggleRow(
            label = s("settings.rdap"),
            detail = s("settings.rdap.detail"),
            checked = rdap
        ) { rdap = it; settings.rdapEnabled = it }
        ToggleRow(
            label = s("settings.tls"),
            detail = s("settings.tls.detail"),
            checked = tls
        ) { tls = it; settings.tlsEnabled = it }
        ToggleRow(
            label = s("settings.banner"),
            detail = s("settings.banner.detail"),
            checked = banner
        ) { banner = it; settings.bannerEnabled = it }
        ToggleRow(
            label = s("settings.vt"),
            detail = s("settings.vt.detail"),
            checked = vt
        ) { vt = it; settings.vtEnabled = it }
        ToggleRow(
            label = s("settings.public_ip"),
            detail = s("settings.public_ip.detail"),
            checked = publicIp
        ) {
            publicIp = it
            settings.publicIpEnabled = it
            viewModel.refreshNetwork()
        }
        ToggleRow(
            label = s("settings.notify"),
            detail = s("settings.notify.detail"),
            checked = notify
        ) { notify = it; settings.anomalyNotifications = it }

        SectionHeader(s("section.refresh"))
        Text(
            text = s("settings.refresh", "ms" to refresh.toInt().toString()),
            color = NL.TextDim,
            style = MaterialTheme.typography.bodySmall
        )
        Slider(
            value = refresh,
            onValueChange = { refresh = it },
            onValueChangeFinished = { settings.refreshMs = refresh.toLong() },
            valueRange = 1000f..10000f,
            steps = 8,
            colors = SliderDefaults.colors(
                thumbColor = NL.Accent,
                activeTrackColor = NL.Accent,
                inactiveTrackColor = NL.Border
            )
        )
        TextButton(onClick = onRequestLocation) {
            Text(s("action.grant_location"), color = NL.Accent, style = MaterialTheme.typography.labelSmall)
        }

        SectionHeader(s("section.keys"))
        KeyField(
            label = s("settings.abuse_key"),
            value = abuseKey,
            hint = s("settings.key.optional")
        ) { abuseKey = it; settings.abuseIpDbKey = it }
        KeyField(
            label = s("settings.vt_key"),
            value = vtKey,
            hint = s("settings.key.optional")
        ) { vtKey = it; settings.virusTotalKey = it }

        SectionHeader(s("section.ai"))
        Text(
            text = s("settings.ai.detail"),
            color = NL.TextFaint,
            style = MaterialTheme.typography.bodySmall
        )
        KeyField(
            label = s("settings.ai.endpoint"),
            value = aiEndpoint,
            hint = Settings.DEFAULT_AI_ENDPOINT
        ) { aiEndpoint = it; settings.aiEndpoint = it }
        KeyField(
            label = s("settings.ai.model"),
            value = aiModel,
            hint = Settings.DEFAULT_AI_MODEL
        ) { aiModel = it; settings.aiModel = it }
        KeyField(
            label = s("settings.ai.key"),
            value = aiKey,
            hint = s("settings.key.optional")
        ) { aiKey = it; settings.aiApiKey = it }
        Text(
            text = if (settings.aiConfigured()) s("settings.ai.ready") else s("settings.ai.local"),
            color = if (settings.aiConfigured()) NL.Green else NL.Yellow,
            style = MaterialTheme.typography.bodySmall
        )

        SectionHeader(s("section.cache"))
        val sizes = viewModel.intel.cacheSizes()
        Text(
            text = sizes.entries.joinToString("  ·  ") { "${it.key}: ${it.value}" },
            color = NL.TextDim,
            style = MaterialTheme.typography.labelSmall
        )
        Text(
            text = s("settings.cache.detail"),
            color = NL.TextFaint,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 4.dp)
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { viewModel.intel.clearCaches() }) {
                Text(s("action.clear_cache"), color = NL.Red, style = MaterialTheme.typography.labelSmall)
            }
            TextButton(onClick = { viewModel.persist() }) {
                Text(s("action.save_cache"), color = NL.Accent, style = MaterialTheme.typography.labelSmall)
            }
        }

        SectionHeader(s("section.privacy"))
        Text(
            text = s("privacy.body"),
            color = NL.TextDim,
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(12.dp))
        TextButton(onClick = onDismiss) {
            Text(s("action.close"), color = NL.Accent, style = MaterialTheme.typography.labelMedium)
        }
    }
}

/**
 * Export through the Storage Access Framework: the user picks the location, NetLurker asks
 * for no storage permission and cannot write anywhere else.
 */
@Composable
fun ExportDialog(
    viewModel: MainViewModel,
    onDismiss: () -> Unit,
    onMessage: (String) -> Unit
) {
    val s = strings()
    val context = LocalContext.current

    // One launcher per format: the document contract takes its MIME type at construction.
    val jsonLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri -> finishExport(uri, "json") }
    val csvLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv")
    ) { uri -> finishExport(uri, "csv") }
    val htmlLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/html")
    ) { uri -> finishExport(uri, "html") }
    val txtLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri -> finishExport(uri, "txt") }

    fun finishExport(uri: android.net.Uri?, kind: String) {
        if (uri == null) return
        val ok = writeExport(context, uri, exportContent(kind, viewModel))
        onMessage(if (ok) s("export.done") else s("export.failed"))
        onDismiss()
    }

    WideDialog(onDismiss = onDismiss) {
        DialogTitle(s("export.dialog.title"))
        Text(
            text = s("export.dialog.detail"),
            color = NL.TextFaint,
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExportButton("JSON") { jsonLauncher.launch(suggestName("json")) }
            ExportButton("CSV") { csvLauncher.launch(suggestName("csv")) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExportButton("HTML") { htmlLauncher.launch(suggestName("html")) }
            ExportButton("TXT") { txtLauncher.launch(suggestName("txt")) }
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onDismiss) {
            Text(s("action.close"), color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun ExportButton(label: String, onClick: () -> Unit) {
    TextButton(
        onClick = onClick,
        modifier = Modifier
            .background(NL.Surface, RoundedCornerShape(8.dp))
            .border(1.dp, NL.Border, RoundedCornerShape(8.dp))
            .width(120.dp)
    ) {
        Text(label, color = NL.Accent, style = MaterialTheme.typography.labelMedium)
    }
}

private fun suggestName(extension: String): String {
    val stamp = java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.ROOT)
        .format(java.util.Date())
    return "netlurker-$stamp.$extension"
}

/** Explains why the location permission is asked for, and what happens if it is denied. */
@Composable
fun PermissionRationaleDialog(onGrant: () -> Unit, onDismiss: () -> Unit) {
    val s = strings()
    WideDialog(onDismiss = onDismiss) {
        DialogTitle(s("permission.title"))
        Text(
            text = s("permission.body"),
            color = NL.TextDim,
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onDismiss) {
                Text(s("action.skip"), color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            }
            TextButton(onClick = onGrant) {
                Text(s("action.grant"), color = NL.Accent, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
