package dev.netlurker.android.intel

import android.annotation.SuppressLint
import dev.netlurker.android.core.BannerInfo
import dev.netlurker.android.core.CertInfo
import java.net.InetAddress
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Reverse DNS. Returns null when the address has no PTR record, which is reported as
 * "no reverse DNS" rather than being silently replaced with the IP address.
 */
object ReverseDns {
    fun lookup(ip: String, timeoutMs: Int = 5_000): String? {
        return runCatching {
            val address = InetAddress.getByName(ip)
            val name = address.canonicalHostName
            if (name.isBlank() || name == ip) null else name
        }.getOrNull()
    }
}

/**
 * TLS inspection: one handshake to the target, then the certificate chain is read off the
 * session. This replaces the hand-written ClientHello the desktop build had to send
 * because WinHTTP would not hand over a rejected chain; on Android the framework does,
 * so the probe is shorter but observes exactly the same properties.
 *
 * The trust manager accepts everything on purpose. This is an inspection tool: refusing an
 * unknown chain would hide precisely the certificates the user wants to see. Nothing
 * fetched here is trusted for any other purpose and no data from the handshake is stored
 * beyond what the UI shows.
 */
object TlsProbe {

    private const val TLS_PORTS_FALLBACK = 443

    @SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager")
    private object InspectorTrustManager : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /**
     * @param expectedName the name the address should present (typically reverse DNS).
     *   When null the name check is skipped rather than reported as a mismatch.
     */
    fun inspect(
        host: String,
        port: Int = TLS_PORTS_FALLBACK,
        expectedName: String? = null,
        timeoutMs: Int = 8_000
    ): CertInfo {
        val context = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(InspectorTrustManager), java.security.SecureRandom())
        }
        var socket: SSLSocket? = null
        try {
            socket = context.socketFactory.createSocket() as SSLSocket
            socket.soTimeout = timeoutMs
            // Do not let the platform verify the name: an expired or mismatched
            // certificate is the finding, not a reason to abort the probe.
            socket.useClientMode = true
            socket.connect(java.net.InetSocketAddress(host, port), timeoutMs)
            socket.startHandshake()
            val session = socket.session
            val chain = session.peerCertificates.filterIsInstance<X509Certificate>()
            val leaf = chain.firstOrNull()
                ?: throw IllegalStateException("handshake produced no certificate")

            val now = System.currentTimeMillis()
            val sanNames = subjectAlternativeDnsNames(leaf)
            val cn = commonName(leaf.subjectX500Principal.name)
            val mismatch = if (expectedName.isNullOrBlank()) false else {
                val candidates = if (sanNames.isNotEmpty()) sanNames else listOfNotNull(cn)
                candidates.none { matchesName(it, expectedName) }
            }
            val selfSigned = leaf.subjectX500Principal.name == leaf.issuerX500Principal.name ||
                runCatching { leaf.verify(leaf.publicKey); true }.getOrDefault(false)

            return CertInfo(
                subject = leaf.subjectX500Principal.name,
                issuer = leaf.issuerX500Principal.name,
                subjectAlternativeNames = sanNames,
                notBeforeEpochSec = leaf.notBefore.time / 1000L,
                notAfterEpochSec = leaf.notAfter.time / 1000L,
                serial = leaf.serialNumber.toString(16),
                sha256Fingerprint = sha256Hex(leaf.encoded),
                selfSigned = selfSigned,
                expired = leaf.notAfter.time < now,
                notYetValid = leaf.notBefore.time > now,
                nameMismatch = mismatch,
                chainLength = chain.size,
                protocol = session.protocol ?: "",
                cipherSuite = session.cipherSuite ?: ""
            )
        } finally {
            runCatching { socket?.close() }
        }
    }

    private fun subjectAlternativeDnsNames(cert: X509Certificate): List<String> {
        val names = runCatching { cert.subjectAlternativeNames }.getOrNull() ?: return emptyList()
        val out = mutableListOf<String>()
        for (entry in names) {
            if (entry.size < 2) continue
            // 2 = dNSName, 7 = iPAddress
            val type = entry[0] as? Int ?: continue
            val value = entry[1]?.toString() ?: continue
            if (type == 2 || type == 7) out += value
        }
        return out
    }

    private fun commonName(distinguishedName: String): String? {
        for (part in distinguishedName.split(',')) {
            val trimmed = part.trim()
            if (trimmed.startsWith("CN=", ignoreCase = true)) return trimmed.substring(3)
        }
        return null
    }

    /** RFC 6125 style match: a single leading wildcard may replace one label. */
    fun matchesName(pattern: String, name: String): Boolean {
        val p = pattern.lowercase().trim()
        val n = name.lowercase().trim()
        if (p == n) return true
        if (!p.startsWith("*.")) return false
        val suffix = p.substring(1) // ".example.com"
        if (!n.endsWith(suffix)) return false
        val label = n.removeSuffix(suffix)
        return label.isNotEmpty() && !label.contains('.')
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { String.format(java.util.Locale.ROOT, "%02x", it) }
    }
}

/**
 * HTTP banner: a single HEAD request, reading the status line and Server/Via headers.
 * End-of-life detection uses the same signature list as the desktop build (src/banner.cpp).
 */
object BannerProbe {

    private val endOfLifeSignatures = listOf(
        "microsoft-iis/5", "microsoft-iis/6", "microsoft-iis/7.0", "microsoft-iis/7.5",
        "apache/1.", "apache/2.0", "apache/2.2",
        "nginx/0.", "nginx/1.0", "nginx/1.2", "nginx/1.4", "nginx/1.6", "nginx/1.8",
        "openssl/0.9", "openssl/1.0.0", "openssl/1.0.1",
        "php/5.", "php/7.0", "php/7.1", "php/7.2", "php/7.3", "php/7.4",
        "lighttpd/1.4.2", "tomcat/4", "tomcat/5", "tomcat/6", "tomcat/7",
        "jboss", "resin/3", "coyote/1.0"
    )

    fun inspect(host: String, port: Int, timeoutMs: Int = 6_000): BannerInfo {
        val scheme = if (port == 443 || port == 8443) "https" else "http"
        val url = if ((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
            "$scheme://$host/"
        } else {
            "$scheme://$host:$port/"
        }
        val response = Http.head(url, timeoutMs = timeoutMs)
        if (!response.ok && response.status == 0) {
            throw IllegalStateException(response.error ?: "no response")
        }
        val server = response.headers["server"].orEmpty()
        val via = response.headers["via"].orEmpty()
        val statusLine = response.headers["statusLine"].orEmpty()
        val eol = matchesEndOfLife(server.ifBlank { via })
        return BannerInfo(
            statusLine = statusLine.ifBlank { "HTTP ${response.status}" },
            server = server,
            via = via,
            endOfLife = eol,
            eolDetail = if (eol) endOfLifeSignatures.firstOrNull {
                server.lowercase().contains(it) || via.lowercase().contains(it)
            }.orEmpty() else "",
            responseMs = response.elapsedMs
        )
    }

    /**
     * True when the banner names software the desktop build treats as end of life.
     *
     * The signature list is the desktop's, but a plain substring search would accuse
     * current software: "nginx/1.2" is a prefix of "nginx/1.25.3". A signature that ends
     * in a digit must therefore not run straight into another digit, so nginx 1.2.9 still
     * matches while 1.25.3 does not. A following dot is a version separator and is fine —
     * that is what lets "apache/2.2" match "Apache/2.2.15". Signatures that already end in
     * a dot ("apache/1.") cannot over-match at all.
     */
    fun matchesEndOfLife(server: String): Boolean {
        if (server.isBlank()) return false
        val lower = server.lowercase()
        return endOfLifeSignatures.any { signature ->
            val at = lower.indexOf(signature)
            at >= 0 && (signature.endsWith('.') || at + signature.length >= lower.length ||
                !lower[at + signature.length].isDigit())
        }
    }
}
