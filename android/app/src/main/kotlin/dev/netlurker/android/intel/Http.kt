package dev.netlurker.android.intel

import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import javax.net.ssl.HttpsURLConnection

/**
 * The only HTTP client in the app: [HttpURLConnection], no third-party dependency.
 *
 * Every failure is returned as a string the UI shows verbatim. A failed lookup is never
 * turned into an empty value that could be mistaken for "no threat found" — that is the
 * desktop build's contract and it is the whole reason this app can be trusted.
 */
object Http {

    data class Response(
        val ok: Boolean,
        val status: Int,
        val body: String,
        val error: String?,
        val elapsedMs: Long,
        val headers: Map<String, String> = emptyMap()
    ) {
        /** True when the failure was connectivity rather than a server answer. */
        val offline: Boolean
            get() = error != null && (error.startsWith("offline:") || error.startsWith("timeout:"))
    }

    const val USER_AGENT = "NetLurker-Android/1.0 (on-device network intelligence; no telemetry)"
    const val DEFAULT_TIMEOUT_MS = 8_000

    fun get(
        url: String,
        headers: Map<String, String> = emptyMap(),
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): Response = request("GET", url, null, null, headers, timeoutMs)

    fun head(
        url: String,
        headers: Map<String, String> = emptyMap(),
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): Response = request("HEAD", url, null, null, headers, timeoutMs)

    fun post(
        url: String,
        body: String,
        contentType: String = "application/json",
        headers: Map<String, String> = emptyMap(),
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): Response = request("POST", url, body, contentType, headers, timeoutMs)

    fun request(
        method: String,
        url: String,
        body: String?,
        contentType: String?,
        headers: Map<String, String>,
        timeoutMs: Int
    ): Response {
        val started = System.currentTimeMillis()
        var connection: HttpURLConnection? = null
        return try {
            val endpoint = URL(url)
            val host = endpoint.host.lowercase(java.util.Locale.ROOT)
            val localEndpoint = host in setOf("localhost", "127.0.0.1", "::1", "[::1]")
            // ip-api's free batch endpoint is the one documented cleartext exception.
            // Keep this allowlist here as well as in network_security_config.xml: a future
            // caller must not accidentally turn a plaintext GET/POST into a general policy.
            val approvedCleartext = endpoint.protocol == "http" && host == "ip-api.com"
            require(endpoint.protocol == "https" || localEndpoint || approvedCleartext) {
                "HTTPS is required except for the approved ip-api.com free endpoint"
            }
            connection = endpoint.openConnection() as HttpURLConnection
            connection.requestMethod = method
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            // Never forward an API key or request body to a redirected host.
            connection.instanceFollowRedirects = headers.isEmpty() && body == null
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setRequestProperty("Accept", "application/json, text/plain, */*")
            for ((k, v) in headers) connection.setRequestProperty(k, v)
            if (body != null) {
                connection.doOutput = true
                if (contentType != null) connection.setRequestProperty("Content-Type", contentType)
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.use {
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (out.size() <= 2 * 1024 * 1024) {
                    val read = it.read(buffer, 0, minOf(buffer.size, 2 * 1024 * 1024 + 1 - out.size()))
                    if (read < 0) break
                    out.write(buffer, 0, read)
                }
                val bytes = out.toByteArray()
                if (bytes.size > 2 * 1024 * 1024) throw IOException("response exceeds 2 MiB limit")
                bytes.toString(Charsets.UTF_8)
            } ?: ""
            val responseHeaders = LinkedHashMap<String, String>()
            for ((key, values) in connection.headerFields) {
                if (key == null) {
                    values?.firstOrNull()?.let { responseHeaders["statusLine"] = it }
                } else {
                    responseHeaders[key.lowercase()] = values.joinToString(", ")
                }
            }
            Response(
                ok = status in 200..299,
                status = status,
                body = text,
                error = if (status in 200..299) null else "HTTP $status",
                elapsedMs = System.currentTimeMillis() - started,
                headers = responseHeaders
            )
        } catch (e: SocketTimeoutException) {
            Response(false, 0, "", "timeout: ${describe(e)}", System.currentTimeMillis() - started)
        } catch (e: UnknownHostException) {
            Response(false, 0, "", "offline: ${e.message ?: "host not resolvable"}",
                System.currentTimeMillis() - started)
        } catch (e: IOException) {
            Response(false, 0, "", describe(e), System.currentTimeMillis() - started)
        } catch (e: RuntimeException) {
            Response(false, 0, "", describe(e), System.currentTimeMillis() - started)
        } finally {
            connection?.disconnect()
        }
    }

    /** Certificate of the remote endpoint, when the connection was HTTPS. */
    fun tlsOf(url: String): HttpsURLConnection? =
        runCatching { URL(url).openConnection() as? HttpsURLConnection }.getOrNull()

    private fun describe(e: Exception): String {
        val name = e.javaClass.simpleName
        val message = e.message?.take(160)?.trim().orEmpty()
        return if (message.isEmpty()) name else "$name: $message"
    }
}
