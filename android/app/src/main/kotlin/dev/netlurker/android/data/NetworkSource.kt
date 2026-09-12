package dev.netlurker.android.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import dev.netlurker.android.core.CellularInfo
import dev.netlurker.android.core.InterfaceInfo
import dev.netlurker.android.core.Ip
import dev.netlurker.android.core.LinkInfo
import dev.netlurker.android.core.WifiInfo
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Everything the framework will honestly tell us about the device's own network state.
 *
 * Each accessor degrades to an explicit "unavailable" with the reason instead of returning
 * a plausible-looking default: on Android a missing SSID usually means the location
 * permission was denied, and reporting "unknown network" as if it were a scanned SSID
 * would be exactly the fabrication this app refuses.
 */
class NetworkSource(private val context: Context) {

    private val cm: ConnectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun activeLink(): LinkInfo? {
        val network = cm.activeNetwork ?: return null
        val capabilities = cm.getNetworkCapabilities(network) ?: return null
        val link = runCatching { cm.getLinkProperties(network) }.getOrNull()

        val localAddresses = link?.linkAddresses?.mapNotNull { address ->
            address.address?.hostAddress?.let { Ip.stripZone(it) + "/" + address.prefixLength }
        }.orEmpty()

        // LinkProperties hands the DNS search path back as one delimited string; split it
        // here so the UI never has to know about the platform's formatting.
        val searchDomains: List<String> = link?.domains
            ?.split(',', ';', ' ')
            ?.mapNotNull { domain -> domain.trim().takeIf { candidate -> candidate.isNotEmpty() } }
            ?: emptyList()

        return LinkInfo(
            networkName = transportName(capabilities),
            transport = transportName(capabilities),
            validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            // The roaming capability constant only exists from API 28; below that the
            // framework cannot answer, so report "not roaming" rather than guessing.
            roaming = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
            vpn = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            captivePortal = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            localAddresses = localAddresses,
            dnsServers = link?.dnsServers?.mapNotNull { it.hostAddress?.let(Ip::stripZone) }.orEmpty(),
            domains = searchDomains,
            routes = link?.routes?.mapNotNull { route ->
                val host = route.destination?.address?.hostAddress?.let(Ip::stripZone)
                val prefixLength = route.destination?.prefixLength ?: 0
                val gateway = route.gateway?.hostAddress
                val text = if (host == null) "default" else "$host/$prefixLength"
                if (gateway.isNullOrBlank()) text else "$text via $gateway"
            }.orEmpty(),
            // LinkProperties.getMtu() landed in API 29. Below that the value is unknown
            // and stays 0, which the network panel renders as an explicit dash.
            mtu = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) link?.mtu ?: 0 else 0
        )
    }

    fun interfaces(): List<InterfaceInfo> {
        val out = mutableListOf<InterfaceInfo>()
        val all = runCatching { NetworkInterface.getNetworkInterfaces().toList() }
            .getOrDefault(emptyList())
        for (iface in all) {
            val addresses = iface.interfaceAddresses.mapNotNull { address ->
                address.address?.let { addr ->
                    val host = addr.hostAddress ?: return@mapNotNull null
                    val text = Ip.stripZone(host)
                    if (addr is Inet4Address) "$text/${address.networkPrefixLength}" else text
                }
            }
            val hardware = runCatching { iface.hardwareAddress?.let { formatMac(it) } }.getOrNull()
            out += InterfaceInfo(
                name = iface.name,
                displayName = iface.displayName ?: iface.name,
                addresses = addresses,
                mtu = runCatching { iface.getMTU() }.getOrDefault(0),
                hardwareAddress = hardware,
                up = runCatching { iface.isUp }.getOrDefault(false),
                loopback = runCatching { iface.isLoopback }.getOrDefault(false),
                transport = guessTransport(iface.name)
            )
        }
        return out.sortedWith(compareBy<InterfaceInfo> { !it.up }.thenBy { it.name })
    }

    fun wifi(locationGranted: Boolean): WifiInfo {
        val manager = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return WifiInfo(
                available = false, ssid = null, bssid = null, rssi = null, linkSpeedMbps = null,
                frequencyMhz = null, band = null, security = null, ip = null, gateway = null,
                detail = "Wi-Fi service unavailable on this device"
            )
        if (!manager.isWifiEnabled) {
            return WifiInfo(
                available = true, ssid = null, bssid = null, rssi = null, linkSpeedMbps = null,
                frequencyMhz = null, band = null, security = null, ip = null, gateway = null,
                detail = "Wi-Fi is turned off"
            )
        }
        val info = currentWifiInfo()
        if (info == null) {
            return WifiInfo(
                available = true, ssid = null, bssid = null, rssi = null, linkSpeedMbps = null,
                frequencyMhz = null, band = null, security = null, ip = null, gateway = null,
                detail = "not connected to a Wi-Fi network"
            )
        }
        val rawSsid = info.ssid
        val ssid = when {
            rawSsid.isNullOrBlank() -> null
            rawSsid == "<unknown ssid>" -> null
            rawSsid == "0x" -> null
            else -> rawSsid.trim('"')
        }
        val detail = when {
            ssid != null -> null
            !locationGranted -> "SSID hidden: Android requires location permission to read it"
            else -> "SSID not reported by the system"
        }
        val frequency = info.frequency
        val linkProperties = cm.activeNetwork?.let { runCatching { cm.getLinkProperties(it) }.getOrNull() }
        val ip = linkProperties?.linkAddresses
            ?.firstOrNull { it.address is Inet4Address }
            ?.address?.hostAddress?.let { Ip.stripZone(it) }
        return WifiInfo(
            available = true,
            ssid = ssid,
            bssid = info.bssid,
            rssi = info.rssi,
            linkSpeedMbps = info.linkSpeed,
            frequencyMhz = frequency.takeIf { it > 0 },
            band = bandOf(frequency),
            security = null,
            ip = ip,
            gateway = linkProperties?.routes
                ?.firstOrNull { it.destination?.prefixLength == 0 }
                ?.gateway?.hostAddress?.let { Ip.stripZone(it) },
            detail = detail
        )
    }

    @Suppress("DEPRECATION")
    private fun currentWifiInfo(): android.net.wifi.WifiInfo? = runCatching {
        val network = cm.activeNetwork ?: return@runCatching null
        val capabilities = cm.getNetworkCapabilities(network) ?: return@runCatching null
        if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return@runCatching null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            capabilities.transportInfo as? android.net.wifi.WifiInfo
        } else {
            val manager = context.applicationContext
                .getSystemService(Context.WIFI_SERVICE) as? WifiManager
            manager?.connectionInfo
        }
    }.getOrNull()

    fun cellular(): CellularInfo {
        val manager = context.getSystemService(Context.TELEPHONY_SERVICE)
            as? android.telephony.TelephonyManager
            ?: return CellularInfo(false, null, null, false, "no telephony radio on this device")
        val operator = runCatching { manager.networkOperatorName }.getOrNull()?.ifBlank { null }
        // dataNetworkType needs API 24 and minSdk is 26, so the deprecated voice-era
        // networkType fallback is dead code here.
        val type = runCatching {
            @Suppress("MissingPermission")
            manager.dataNetworkType
        }.getOrNull()
        val roaming = runCatching { manager.isNetworkRoaming }.getOrNull()
        val detail = if (type == null && operator == null) {
            "network identity not readable without the phone permission"
        } else null
        return CellularInfo(
            available = true,
            operator = operator,
            networkType = type?.let { networkTypeName(it) },
            roaming = roaming ?: false,
            detail = detail
        )
    }

    private fun transportName(capabilities: NetworkCapabilities): String = when {
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "Bluetooth"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_LOWPAN) -> "LoWPAN"
        else -> "unknown"
    }

    private fun guessTransport(name: String): String = when {
        name.startsWith("wlan") || name.startsWith("ap") || name.startsWith("swlan") -> "Wi-Fi"
        name.startsWith("rmnet") || name.startsWith("ccmni") || name.startsWith("v4-rmnet") -> "Cellular"
        name.startsWith("eth") -> "Ethernet"
        name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("wg") -> "VPN/tunnel"
        name == "lo" -> "loopback"
        else -> "other"
    }

    private fun formatMac(bytes: ByteArray): String? {
        if (bytes.isEmpty() || bytes.all { it == 0.toByte() }) return null
        return bytes.joinToString(":") { String.format(java.util.Locale.ROOT, "%02x", it) }
    }

    private fun bandOf(frequencyMhz: Int): String? = when {
        frequencyMhz <= 0 -> null
        frequencyMhz in 2400..2500 -> "2.4 GHz"
        frequencyMhz in 4900..5900 -> "5 GHz"
        frequencyMhz in 5925..7125 -> "6 GHz"
        else -> "$frequencyMhz MHz"
    }

    private fun networkTypeName(type: Int): String = when (type) {
        1 -> "GPRS"
        2 -> "EDGE"
        3 -> "UMTS"
        4 -> "CDMA"
        5 -> "EVDO_0"
        6 -> "EVDO_A"
        7 -> "1xRTT"
        8 -> "HSDPA"
        9 -> "HSUPA"
        10 -> "HSPA"
        11 -> "iDen"
        12 -> "EVDO_B"
        13 -> "LTE"
        14 -> "eHRPD"
        15 -> "HSPA+"
        16 -> "GSM"
        17 -> "TD_SCDMA"
        18 -> "IWLAN"
        19 -> "LTE_CA"
        20 -> "NR (5G)"
        else -> "type $type"
    }
}
