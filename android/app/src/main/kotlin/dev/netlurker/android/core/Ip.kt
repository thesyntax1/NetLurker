package dev.netlurker.android.core

import java.net.InetAddress

/**
 * Address handling. Kept dependency-free and side-effect free except for the explicit
 * [parse] helper, so it is fully unit-testable off-device.
 */
object Ip {

    private val v4PrivatePrefixes = listOf(
        "10.", "192.168.", "127.", "169.254.", "0."
    )

    fun isIPv4(s: String): Boolean {
        val parts = s.split('.')
        if (parts.size != 4) return false
        return parts.all { p ->
            p.isNotEmpty() && p.length <= 3 && p.all { it.isDigit() } &&
                p.toIntOrNull()?.let { it in 0..255 } == true &&
                !(p.length > 1 && p.startsWith("0"))
        }
    }

    fun isIPv6(s: String): Boolean = s.contains(':') && !s.contains('/') &&
        runCatching { InetAddress.getByName(s) }.isSuccess

    fun isIp(s: String): Boolean = isIPv4(s) || isIPv6(s)

    /**
     * True for addresses that are routable on the public internet. Anything private,
     * loopback, link-local, multicast or CGNAT returns false — those get a negative
     * weight in the risk score instead of being scored like an internet destination.
     */
    fun isPublic(s: String): Boolean {
        if (s.isBlank()) return false
        if (isIPv4(s)) {
            if (v4PrivatePrefixes.any { s.startsWith(it) }) return false
            // 172.16.0.0/12
            if (s.startsWith("172.")) {
                val second = s.split('.')[1].toIntOrNull() ?: return false
                if (second in 16..31) return false
            }
            // 100.64.0.0/10 carrier-grade NAT
            if (s.startsWith("100.")) {
                val second = s.split('.')[1].toIntOrNull() ?: return false
                if (second in 64..127) return false
            }
            val first = s.split('.')[0].toIntOrNull() ?: return false
            if (first >= 224) return false // multicast + reserved
            return true
        }
        if (!isIPv6(s)) return false
        val lower = s.lowercase()
        if (lower == "::" || lower == "::1") return false
        if (lower.startsWith("fe80")) return false // link local
        if (lower.startsWith("fc") || lower.startsWith("fd")) return false // unique local
        if (lower.startsWith("ff")) return false // multicast
        // IPv4-mapped IPv6 (::ffff:192.168.1.1)
        val mapped = lower.substringAfterLast(":")
        if (isIPv4(mapped)) return isPublic(mapped)
        return true
    }

    fun isPrivate(s: String): Boolean = isIp(s) && !isPublic(s)

    /**
     * DNSBL queries need the octets reversed: 1.2.3.4 -> 4.3.2.1.<zone>.
     * IPv6 would need nibble expansion; DNSBL zones do not list IPv6 ranges, so the
     * caller simply skips them rather than inventing a query.
     */
    fun reverseForDnsbl(s: String): String? {
        if (!isIPv4(s)) return null
        return s.split('.').reversed().joinToString(".")
    }

    /** Normalises an interface address such as "fe80::1%wlan0" to "fe80::1". */
    fun stripZone(s: String): String = s.substringBefore('%')

    fun parseOrNull(s: String): InetAddress? = runCatching { InetAddress.getByName(s) }.getOrNull()
}
