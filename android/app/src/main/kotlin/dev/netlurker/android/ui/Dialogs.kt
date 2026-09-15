package dev.netlurker.android.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.widthIn
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
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import kotlinx.coroutines.launch
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
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

/** The form scrolls independently; primary actions never live at the end of that scroll. */
@Composable
internal fun WideDialog(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    footer: (@Composable () -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)
    ) {
        Column(
            modifier
                .widthIn(max = 640.dp)
                .fillMaxWidth()
                .imePadding()
                .safeDrawingPadding()
                .padding(12.dp)
                .heightIn(max = 640.dp)
                .background(NL.Bg, RoundedCornerShape(14.dp))
                .border(1.dp, NL.Border, RoundedCornerShape(14.dp))
                .testTag("dialog-surface")
        ) {
            Column(
                Modifier.weight(1f, fill = false).fillMaxWidth()
                    .verticalScroll(rememberScrollState()).padding(16.dp),
                content = content
            )
            if (footer != null) {
                Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) { footer() }
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
private fun ToggleRow(label: String, detail: String?, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
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
            enabled = enabled,
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
private fun KeyField(label: String, value: String, hint: String, secret: Boolean = false, enabled: Boolean = true, tag: String = label, onChange: (String) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = Modifier.fillMaxWidth().testTag(tag),
            label = { Text(label) },
            enabled = enabled,
            visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None,
            keyboardOptions = KeyboardOptions(keyboardType = if (secret) KeyboardType.Password else KeyboardType.Text),
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
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsDialog(
    viewModel: MainViewModel,
    onRequestLocation: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    var draft by remember { mutableStateOf(viewModel.settings.snapshot()) }
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var cacheSizes by remember { mutableStateOf(viewModel.intel.cacheSizes()) }
    val scope = rememberCoroutineScope()
    val keyboard = LocalSoftwareKeyboardController.current
    val s = remember(context, configuration, draft.language) { Strings(context, draft.language) }
    val dismiss = { if (!saving) onDismiss() }

    CompositionLocalProvider(LocalStrings provides s) {
        WideDialog(onDismiss = dismiss, modifier = modifier, footer = {
            error?.let { Text(s(it), color = NL.Red, style = MaterialTheme.typography.bodySmall) }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = dismiss, enabled = !saving, modifier = Modifier.weight(1f).testTag("settings-cancel")) {
                    Text(s("action.cancel"))
                }
                Button(onClick = {
                    val values = draft.normalized()
                    error = values.validationError()
                    if (error == null) {
                        keyboard?.hide()
                        saving = true
                        scope.launch {
                            val saved = viewModel.saveSettings(values)
                            saving = false
                            if (saved) onDismiss() else error = "settings.error.save"
                        }
                    }
                }, enabled = !saving, modifier = Modifier.weight(1f).testTag("settings-save")) {
                    Text(if (saving) s("settings.saving") else s("action.save"))
                }
            }
        }) {
            DialogTitle(s("settings.title"))

            SectionHeader(s("settings.language"))
            var languageMenu by remember { mutableStateOf(false) }
            Box {
                TextButton(onClick = { languageMenu = true }, enabled = !saving) {
                    Text(Strings.supportedLanguages.first { it.first == s.language }.second, color = NL.Accent)
                }
                DropdownMenu(expanded = languageMenu, onDismissRequest = { languageMenu = false }) {
                    Strings.supportedLanguages.forEach { (code, label) ->
                        DropdownMenuItem(
                            text = { Text(label, color = if (s.language == code) NL.Accent else NL.Text) },
                            onClick = {
                                draft = draft.copy(language = code)
                                languageMenu = false
                            }
                        )
                    }
                }
            }

            SectionHeader(s("section.sources"))
            ToggleRow(
                label = s("settings.geo"),
                detail = s("settings.geo.detail"),
                checked = draft.geo,
                enabled = !saving
            ) { draft = draft.copy(geo = it) }
            ToggleRow(
                label = s("settings.threat"),
                detail = s("settings.threat.detail"),
                checked = draft.threat,
                enabled = !saving
            ) { draft = draft.copy(threat = it) }
            ToggleRow(
                label = s("settings.rdap"),
                detail = s("settings.rdap.detail"),
                checked = draft.rdap,
                enabled = !saving
            ) { draft = draft.copy(rdap = it) }
            ToggleRow(
                label = s("settings.tls"),
                detail = s("settings.tls.detail"),
                checked = draft.tls,
                enabled = !saving
            ) { draft = draft.copy(tls = it) }
            ToggleRow(
                label = s("settings.banner"),
                detail = s("settings.banner.detail"),
                checked = draft.banner,
                enabled = !saving
            ) { draft = draft.copy(banner = it) }
            ToggleRow(
                label = s("settings.vt"),
                detail = s("settings.vt.detail"),
                checked = draft.vt,
                enabled = !saving
            ) { draft = draft.copy(vt = it) }
            ToggleRow(
                label = s("settings.public_ip"),
                detail = s("settings.public_ip.detail"),
                checked = draft.publicIp,
                enabled = !saving
            ) {
                draft = draft.copy(publicIp = it)
            }
            ToggleRow(
                label = s("settings.notify"),
                detail = s("settings.notify.detail"),
                checked = draft.notify,
                enabled = !saving
            ) { draft = draft.copy(notify = it) }

            SectionHeader(s("section.refresh"))
            Text(
                text = s("settings.refresh", "ms" to draft.refreshMs.toString()),
                color = NL.TextDim,
                style = MaterialTheme.typography.bodySmall
            )
            Slider(
                value = draft.refreshMs.toFloat(),
                enabled = !saving,
                onValueChange = { draft = draft.copy(refreshMs = it.toLong()) },
                valueRange = 1000f..30000f,
                steps = 28,
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
                value = draft.abuseKey,
                enabled = !saving,
                secret = true,
                tag = "settings.abuse_key",
                hint = s("settings.key.optional")
            ) { draft = draft.copy(abuseKey = it) }
            KeyField(
                label = s("settings.vt_key"),
                value = draft.vtKey,
                enabled = !saving,
                secret = true,
                tag = "settings.vt_key",
                hint = s("settings.key.optional")
            ) { draft = draft.copy(vtKey = it) }

            SectionHeader(s("section.ai"))
            Text(
                text = s("settings.ai.detail"),
                color = NL.TextFaint,
                style = MaterialTheme.typography.bodySmall
            )
            KeyField(
                label = s("settings.ai.endpoint"),
                value = draft.aiEndpoint,
                enabled = !saving,
                secret = false,
                tag = "settings.ai.endpoint",
                hint = Settings.DEFAULT_AI_ENDPOINT
            ) { draft = draft.copy(aiEndpoint = it) }
            KeyField(
                label = s("settings.ai.model"),
                value = draft.aiModel,
                enabled = !saving,
                secret = false,
                tag = "settings.ai.model",
                hint = Settings.DEFAULT_AI_MODEL
            ) { draft = draft.copy(aiModel = it) }
            KeyField(
                label = s("settings.ai.key"),
                value = draft.aiKey,
                enabled = !saving,
                secret = true,
                tag = "settings.ai.key",
                hint = s("settings.key.optional")
            ) { draft = draft.copy(aiKey = it) }
            Text(
                text = if (draft.aiConfigured()) s("settings.ai.ready") else s("settings.ai.local"),
                color = if (draft.aiConfigured()) NL.Green else NL.Yellow,
                style = MaterialTheme.typography.bodySmall
            )

            SectionHeader(s("section.cache"))
            Text(
                text = cacheSizes.entries.joinToString("  ·  ") { "${it.key}: ${it.value}" },
                color = NL.TextDim,
                style = MaterialTheme.typography.labelSmall
            )
            Text(
                text = s("settings.cache.detail"),
                color = NL.TextFaint,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp)
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = {
                    scope.launch {
                        viewModel.clearIntelCaches()
                        cacheSizes = viewModel.intel.cacheSizes()
                    }
                }, enabled = !saving) {
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
        }
    }
}

/**
 * Export through the Storage Access Framework: the user picks the location, NetLurker asks
 * for no storage permission and cannot write anywhere else.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ExportDialog(
    viewModel: MainViewModel,
    onDismiss: () -> Unit,
    onMessage: (String) -> Unit
) {
    val s = strings()
    val context = LocalContext.current


    fun finishExport(uri: android.net.Uri?, kind: String) {
        if (uri == null) return
        val ok = writeExport(context, uri, exportContent(kind, viewModel))
        onMessage(if (ok) s("export.done") else s("export.failed"))
        onDismiss()
    }

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

    WideDialog(onDismiss = onDismiss) {
        DialogTitle(s("export.dialog.title"))
        Text(
            text = s("export.dialog.detail"),
            color = NL.TextFaint,
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(12.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExportButton("JSON") { jsonLauncher.launch(suggestName("json")) }
            ExportButton("CSV") { csvLauncher.launch(suggestName("csv")) }
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
@OptIn(ExperimentalLayoutApi::class)
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
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onDismiss) {
                Text(s("action.skip"), color = NL.TextDim, style = MaterialTheme.typography.labelSmall)
            }
            TextButton(onClick = onGrant) {
                Text(s("action.grant"), color = NL.Accent, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
