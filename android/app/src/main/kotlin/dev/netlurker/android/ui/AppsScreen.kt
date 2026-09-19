package dev.netlurker.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.netlurker.android.MainViewModel
import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.core.Verdict
import dev.netlurker.android.core.Format

/**
 * Package details and available UID counters. Other apps' counters are restricted
 * on modern Android; this screen does not attribute remote destinations to packages.
 */
@Composable
fun AppsScreen(viewModel: MainViewModel) {
    val s = strings()
    val apps by viewModel.apps.collectAsState()
    val snapshot by viewModel.snapshot.collectAsState()
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("all") }
    var sort by remember { mutableStateOf("traffic") }
    var expanded by remember { mutableStateOf<Int?>(null) }

    Column(Modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(top = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            KpiTile(
                label = s("kpi.apps"),
                value = apps.size.toString(),
                modifier = Modifier.weight(1f),
                sub = "${apps.count { it.active }} ${s("kpi.active_now")}"
            )
            KpiTile(
                label = "↓",
                value = Format.bytesPerSec(snapshot?.rateInBytesPerSec ?: 0.0),
                color = NL.Accent,
                modifier = Modifier.weight(1f),
                sub = Format.bytes(snapshot?.sessionRxBytes ?: 0L)
            )
            KpiTile(
                label = "↑",
                value = Format.bytesPerSec(snapshot?.rateOutBytesPerSec ?: 0.0),
                color = NL.Orange,
                modifier = Modifier.weight(1f),
                sub = Format.bytes(snapshot?.sessionTxBytes ?: 0L)
            )
        }

        if (!viewModel.trafficSupported || apps.any { !it.supported }) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
                    .background(NL.Yellow.copy(alpha = 0.12f), RoundedCornerShape(8.dp))
                    .border(1.dp, NL.Yellow.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                    .padding(10.dp)
            ) {
                Text(
                    text = s("traffic.unsupported"),
                    color = NL.Yellow,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            singleLine = true,
            placeholder = {
                Text(s("apps.search"), color = NL.TextFaint, style = MaterialTheme.typography.bodySmall)
            },
            textStyle = MaterialTheme.typography.bodyMedium,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = NL.Accent,
                unfocusedBorderColor = NL.Border,
                focusedTextColor = NL.Text,
                unfocusedTextColor = NL.Text,
                cursorColor = NL.Accent
            )
        )

        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FilterChipRow(
                options = listOf(
                    "all" to s("filter.all"),
                    "active" to s("filter.active"),
                    "user" to s("filter.user"),
                    "system" to s("filter.system")
                ),
                selected = filter,
                onSelect = { filter = it }
            )
        }
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(bottom = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            FilterChipRow(
                options = listOf(
                    "traffic" to s("sort.traffic"),
                    "rate" to s("sort.rate"),
                    "name" to s("sort.name")
                ),
                selected = sort,
                onSelect = { sort = it }
            )
        }

        val visible = remember(apps, query, filter, sort) {
            apps.asSequence()
                .filter { app ->
                    query.isBlank() ||
                        app.label.contains(query, true) ||
                        app.packageName.contains(query, true)
                }
                .filter { app ->
                    when (filter) {
                        "active" -> app.active
                        "user" -> !app.system
                        "system" -> app.system
                        else -> true
                    }
                }
                .sortedWith(
                    when (sort) {
                        "rate" -> compareByDescending<AppTraffic> { it.rateIn + it.rateOut }
                        "name" -> compareBy { it.label.lowercase() }
                        else -> compareByDescending { it.totalBytes }
                    }
                )
                .toList()
        }

        if (visible.isEmpty()) {
            EmptyState(title = s("apps.empty.title"), detail = s("apps.empty.detail"))
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                items(visible, key = { it.uid }) { app ->
                    AppRow(
                        app = app,
                        verdict = viewModel.appVerdict(app),
                        expanded = expanded == app.uid,
                        onToggle = { expanded = if (expanded == app.uid) null else app.uid },
                        onHash = { viewModel.onApkHash(app) }
                    )
                }
                item { Spacer(Modifier.height(16.dp)) }
            }
        }
    }
}

@Composable
private fun FilterChipRow(
    options: List<Pair<String, String>>,
    selected: String,
    onSelect: (String) -> Unit
) {
    for ((id, label) in options) {
        FilterChip(
            selected = selected == id,
            onClick = { onSelect(id) },
            label = { Text(label, style = MaterialTheme.typography.labelSmall) },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = NL.RowSel,
                selectedLabelColor = NL.Accent,
                containerColor = NL.Surface,
                labelColor = NL.TextDim
            ),
            border = FilterChipDefaults.filterChipBorder(
                enabled = true,
                selected = selected == id,
                borderColor = NL.Border,
                selectedBorderColor = NL.Accent
            )
        )
    }
}

@Composable
private fun AppRow(
    app: AppTraffic,
    verdict: Verdict,
    expanded: Boolean,
    onToggle: () -> Unit,
    onHash: () -> Unit
) {
    val s = strings()
    Column(
        Modifier
            .fillMaxWidth()
            .background(NL.Surface, RoundedCornerShape(10.dp))
            .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
            .clickable { onToggle() }
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(8.dp)
                    .background(
                        if (app.active) NL.Green else NL.TextFaint.copy(alpha = 0.4f),
                        CircleShape
                    )
            )
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = app.label,
                    color = NL.Text,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = app.packageName,
                    color = NL.TextFaint,
                    style = MaterialTheme.typography.labelSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = if (app.supported) Format.bytes(app.totalBytes) else "—",
                    color = NL.Text,
                    style = MaterialTheme.typography.labelMedium
                )
                Text(
                    text = if (app.supported) "↓ ${Format.bytesPerSec(app.rateIn)}  ↑ ${Format.bytesPerSec(app.rateOut)}"
                        else s("status.unavailable"),
                    color = if (app.active) NL.Green else NL.TextFaint,
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }

        if (verdict.reasons.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            VerdictPanel(verdict)
        }

        if (!expanded) return@Column

        Spacer(Modifier.height(8.dp))
        Box(Modifier.fillMaxWidth().height(1.dp).background(NL.Border))
        Spacer(Modifier.height(8.dp))

        InfoRow(s("field.uid"), app.uid.toString(), mono = true)
        InfoRow(s("field.version"), app.versionName ?: "—", mono = true)
        InfoRow(s("field.target_sdk"), if (app.targetSdk > 0) app.targetSdk.toString() else "—")
        InfoRow(
            s("field.installer"),
            app.installer ?: s("field.installer.unknown"),
            valueColor = if (app.installer == null) NL.TextFaint else NL.Text,
            mono = true
        )
        InfoRow(s("field.type"), if (app.system) s("app.type.system") else s("app.type.user"))
        if (app.firstInstallMs > 0) {
            InfoRow(s("field.installed"), Format.epochIso(app.firstInstallMs))
        }
        if (app.lastUpdateMs > 0) {
            InfoRow(s("field.updated"), Format.epochIso(app.lastUpdateMs))
        }
        InfoRow(
            s("field.signer"),
            app.signerSubject ?: s("field.signer.unavailable"),
            valueColor = if (app.signerSubject == null) NL.TextFaint else NL.Text,
            mono = true
        )
        app.signerIssuer?.let { InfoRow(s("field.signer_issuer"), it, mono = true) }
        app.signerSha256?.let { InfoRow(s("field.signer_hash"), it, mono = true) }
        InfoRow(
            s("field.apk_hash"),
            app.apkSha256 ?: s("field.apk_hash.pending"),
            valueColor = if (app.apkSha256 == null) NL.TextFaint else NL.Text,
            mono = true
        )
        if (app.apkSha256 == null && app.apkPath != null) {
            TextButton(onClick = onHash) {
                Text(s("action.compute_hash"), color = NL.Accent, style = MaterialTheme.typography.labelSmall)
            }
        }
        InfoRow(
            s("field.permissions"),
            s("field.permissions.count", "count" to app.requestedPermissions.size.toString())
        )
        if (app.requestedPermissions.isNotEmpty()) {
            val dangerous = app.requestedPermissions.filter {
                it.contains("LOCATION") || it.contains("CAMERA") || it.contains("MICROPHONE") ||
                    it.contains("READ_CONTACTS") || it.contains("READ_SMS") ||
                    it.contains("CALL_PHONE") || it.contains("READ_CALL_LOG")
            }
            if (dangerous.isNotEmpty()) {
                InfoRow(
                    s("field.permissions.sensitive"),
                    dangerous.joinToString(", ") { it.substringAfterLast('.') },
                    valueColor = NL.Yellow
                )
            }
        }
        app.apkPath?.let { InfoRow(s("field.apk_path"), it, mono = true) }
    }
}
