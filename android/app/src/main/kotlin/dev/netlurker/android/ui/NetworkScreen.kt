package dev.netlurker.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.netlurker.android.MainViewModel
import dev.netlurker.android.core.Format
import dev.netlurker.android.core.IntelStatus

/**
 * Network: what this device is attached to.
 *
 * Every value here is read from the framework at the moment it is displayed. Where the
 * framework refuses to answer — SSID without location permission, network type without the
 * phone permission — the card states that instead of showing a placeholder that could be
 * mistaken for a reading.
 */
@Composable
fun NetworkScreen(viewModel: MainViewModel, onRequestLocation: () -> Unit) {
    val s = strings()
    val link by viewModel.link.collectAsState()
    val wifi by viewModel.wifi.collectAsState()
    val cellular by viewModel.cellular.collectAsState()
    val interfaces by viewModel.interfaces.collectAsState()
    val device by viewModel.device.collectAsState()

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 12.dp)
    ) {
        SectionHeader(s("section.link"), trailing = link?.transport)
        Panel {
            if (link == null) {
                InfoRow(s("section.link"), s("link.none"), valueColor = NL.Yellow)
            } else {
                InfoRow(s("field.transport"), link!!.transport)
                InfoRow(
                    s("field.validated"),
                    if (link!!.validated) s("value.yes") else s("value.no"),
                    valueColor = if (link!!.validated) NL.Green else NL.Yellow
                )
                InfoRow(
                    s("field.metered"),
                    if (link!!.metered) s("value.yes") else s("value.no"),
                    valueColor = if (link!!.metered) NL.Yellow else NL.Text
                )
                InfoRow(s("field.roaming"), if (link!!.roaming) s("value.yes") else s("value.no"))
                InfoRow(
                    s("field.vpn"),
                    if (link!!.vpn) s("value.yes") else s("value.no"),
                    valueColor = if (link!!.vpn) NL.Purple else NL.Text
                )
                InfoRow(
                    s("field.captive_portal"),
                    if (link!!.captivePortal) s("value.yes") else s("value.no"),
                    valueColor = if (link!!.captivePortal) NL.Red else NL.Text
                )
                InfoRow(s("field.addresses"), link!!.localAddresses.joinToString(", ").ifBlank { "—" }, mono = true)
                InfoRow(s("field.dns"), link!!.dnsServers.joinToString(", ").ifBlank { "—" }, mono = true)
                if (link!!.domains.isNotEmpty()) {
                    InfoRow(s("field.search_domains"), link!!.domains.joinToString(", "), mono = true)
                }
                InfoRow(s("field.mtu"), if (link!!.mtu > 0) link!!.mtu.toString() else "—")
                if (link!!.routes.isNotEmpty()) {
                    SectionHeader(s("field.routes"), trailing = link!!.routes.size.toString())
                    for (route in link!!.routes.take(12)) {
                        Text(
                            text = route,
                            color = NL.TextDim,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(vertical = 1.dp)
                        )
                    }
                }
            }
        }

        SectionHeader(s("section.wifi"))
        Panel {
            val info = wifi
            if (info == null || !info.available) {
                InfoRow(s("section.wifi"), s("wifi.unavailable"), valueColor = NL.TextFaint)
            } else {
                InfoRow(
                    s("field.ssid"),
                    info.ssid ?: s("wifi.ssid.hidden"),
                    valueColor = if (info.ssid == null) NL.Yellow else NL.Text
                )
                info.bssid?.let { InfoRow(s("field.bssid"), it, mono = true) }
                info.rssi?.let {
                    InfoRow(
                        s("field.signal"),
                        "$it dBm (${signalQuality(it)})",
                        valueColor = if (it > -60) NL.Green else if (it > -75) NL.Yellow else NL.Red
                    )
                }
                info.linkSpeedMbps?.let { InfoRow(s("field.link_speed"), "$it Mbps") }
                info.band?.let { InfoRow(s("field.band"), it) }
                info.frequencyMhz?.let { InfoRow(s("field.frequency"), "$it MHz") }
                info.ip?.let { InfoRow(s("field.ip"), it, mono = true) }
                info.gateway?.let { InfoRow(s("field.gateway"), it, mono = true) }
                info.detail?.let {
                    InfoRow(s("field.note"), it, valueColor = NL.Yellow)
                }
                if (info.ssid == null) {
                    TextButton(onClick = onRequestLocation) {
                        Text(
                            s("action.grant_location"),
                            color = NL.Accent,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
            }
        }

        SectionHeader(s("section.cellular"))
        Panel {
            val info = cellular
            if (info == null || !info.available) {
                InfoRow(s("section.cellular"), s("cellular.unavailable"), valueColor = NL.TextFaint)
            } else {
                InfoRow(s("field.operator"), info.operator ?: "—")
                InfoRow(s("field.network_type"), info.networkType ?: "—")
                InfoRow(s("field.roaming"), if (info.roaming) s("value.yes") else s("value.no"))
                info.detail?.let { InfoRow(s("field.note"), it, valueColor = NL.Yellow) }
            }
        }

        SectionHeader(s("section.interfaces"), trailing = interfaces.size.toString())
        Panel {
            if (interfaces.isEmpty()) {
                InfoRow(s("section.interfaces"), s("interfaces.none"), valueColor = NL.TextFaint)
            }
            for (iface in interfaces) {
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    Text(
                        text = if (iface.up) "▲" else "▽",
                        color = if (iface.up) NL.Green else NL.TextFaint,
                        style = MaterialTheme.typography.labelSmall
                    )
                    Spacer(Modifier.padding(start = 6.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = "${iface.name}  ·  ${iface.transport}" +
                                (iface.hardwareAddress?.let { "  ·  $it" } ?: ""),
                            color = if (iface.up) NL.Text else NL.TextDim,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Medium
                        )
                        Text(
                            text = iface.addresses.joinToString(", ").ifBlank { s("interfaces.no_address") } +
                                if (iface.mtu > 0) "   mtu ${iface.mtu}" else "",
                            color = NL.TextFaint,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
            }
        }

        SectionHeader(s("section.device"))
        Panel {
            device?.let { info ->
                InfoRow(s("field.model"), "${info.manufacturer} ${info.model}")
                InfoRow(s("field.android"), "Android ${info.androidRelease} (API ${info.sdkInt})")
                InfoRow(s("field.security_patch"), info.securityPatch)
                InfoRow(s("field.uptime"), Format.durationLong(info.uptimeMs / 1000L))
                InfoRow(
                    s("field.public_ip"),
                    when (info.publicIpStatus) {
                        IntelStatus.OK -> info.publicIp ?: "—"
                        IntelStatus.PENDING -> s("status.querying")
                        IntelStatus.DISABLED -> s("public_ip.disabled")
                        else -> info.publicIpDetail ?: s("status.failed")
                    },
                    valueColor = statusColor(info.publicIpStatus),
                    mono = true
                )
                TextButton(onClick = {
                    viewModel.settings.publicIpEnabled = !viewModel.settings.publicIpEnabled
                    viewModel.refreshNetwork()
                }) {
                    Text(
                        text = if (viewModel.settings.publicIpEnabled) s("action.public_ip.off")
                        else s("action.public_ip.on"),
                        color = NL.Accent,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
        }

        Row(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
            TextButton(onClick = { viewModel.refreshNetwork() }) {
                Text(s("action.refresh"), color = NL.Accent, style = MaterialTheme.typography.labelMedium)
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun Panel(content: @Composable () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(NL.Surface, RoundedCornerShape(10.dp))
            .border(1.dp, NL.Border, RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        content()
    }
}

/** Signal grade, resolved through the catalog so it follows the interface language. */
@Composable
private fun signalQuality(rssi: Int): String {
    val s = strings()
    return when {
        rssi >= -50 -> s("signal.excellent")
        rssi >= -60 -> s("signal.good")
        rssi >= -70 -> s("signal.fair")
        rssi >= -80 -> s("signal.weak")
        else -> s("signal.very_weak")
    }
}
