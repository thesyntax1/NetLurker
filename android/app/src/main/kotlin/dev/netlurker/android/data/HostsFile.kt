package dev.netlurker.android.data

import dev.netlurker.android.core.Ip
import java.io.File

/**
 * The device's hosts file.
 *
 * The desktop build reads `%SystemRoot%\System32\drivers\etc\hosts` for the same reason this
 * does: an entry there is a deliberate, human-or-malware-authored override of name
 * resolution, and a destination that only resolves because of it deserves to say so. On
 * Android the file is `/system/etc/hosts`; it is world-readable on stock images, but a vendor
 * may tighten it, so every failure path is reported instead of being read as "no redirects".
 *
 * The parsing rules match the desktop line for line: strip the comment, take the first token
 * as the address, ignore the loopback entries every hosts file carries, and count a line only
 * when it actually maps a name.
 */
object HostsFile {

    const val DEFAULT_PATH = "/system/etc/hosts"

    /** Everything the hosts file can tell us, including the fact that it told us nothing. */
    data class Snapshot(
        val readable: Boolean,
        val entries: Int,
        val redirectedIps: Set<String> = emptySet(),
        val namesByIp: Map<String, List<String>> = emptyMap(),
        val detail: String? = null
    ) {
        val empty: Boolean get() = readable && entries == 0

        fun redirects(ip: String): Boolean = redirectedIps.contains(Ip.stripZone(ip))

        fun namesFor(ip: String): List<String> = namesByIp[Ip.stripZone(ip)].orEmpty()
    }

    private val loopback = setOf("127.0.0.1", "::1", "localhost")

    /** Parses hosts content. Pure, so the rules are covered by unit tests on a plain JVM. */
    fun parse(text: String): Snapshot {
        val ips = LinkedHashSet<String>()
        val names = LinkedHashMap<String, MutableList<String>>()
        var entries = 0

        for (rawLine in text.split('\n')) {
            val line = rawLine.substringBefore('#').trim()
            if (line.isEmpty()) continue
            val tokens = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
            val address = tokens.firstOrNull() ?: continue
            if (tokens.size < 2) continue
            if (loopback.contains(address)) continue
            ips.add(address)
            names.getOrPut(address) { mutableListOf() }.addAll(tokens.drop(1))
            entries++
        }
        return Snapshot(
            readable = true,
            entries = entries,
            redirectedIps = ips,
            namesByIp = names
        )
    }

    /** Reads and parses the file, reporting why it could not when it could not. */
    fun read(path: String = DEFAULT_PATH, maxBytes: Long = 1_048_576L): Snapshot {
        val file = File(path)
        return try {
            if (!file.exists()) {
                Snapshot(readable = false, entries = 0, detail = "$path does not exist on this device")
            } else if (!file.canRead()) {
                Snapshot(readable = false, entries = 0, detail = "$path is not readable by this app")
            } else {
                val text = file.inputStream().use { stream ->
                    val buffer = ByteArray(maxBytes.toInt())
                    val read = stream.read(buffer)
                    if (read <= 0) "" else String(buffer, 0, read, Charsets.UTF_8)
                }
                parse(text)
            }
        } catch (e: Exception) {
            Snapshot(
                readable = false,
                entries = 0,
                detail = e.message?.take(160) ?: e.javaClass.simpleName
            )
        }
    }
}
