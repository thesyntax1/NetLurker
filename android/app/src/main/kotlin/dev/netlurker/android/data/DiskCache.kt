package dev.netlurker.android.data

import java.io.File

/**
 * Tab-separated on-disk cache, one file per lookup source.
 *
 * Two rules carry over from the desktop build and are the reason the app can be trusted:
 *
 *  1. A failed lookup is never written here. Retrying costs a request; caching a failure
 *     would make a transient network problem look like a permanent verdict.
 *  2. Retries use exponential backoff (20 s, doubling, capped at 10 min) so a dead
 *     endpoint cannot turn into a request loop on a metered connection.
 */
class DiskCache(directory: File, private val fileName: String) {

    data class Entry(val atEpochSec: Long, val payload: String) {
        fun isFresh(now: Long, ttl: Long): Boolean = atEpochSec > 0 && atEpochSec <= now && now - atEpochSec < ttl
    }

    private val file = File(directory, fileName)
    private val temporaryFile = File(directory, "$fileName.tmp")
    private val entries = LinkedHashMap<String, Entry>()
    private var dirty = false

    @Synchronized
    fun load() {
        entries.clear()
        if (!file.exists()) return
        runCatching {
            file.forEachLine { line ->
                val parts = line.split('\t')
                if (parts.size >= 3) {
                    val at = parts[1].toLongOrNull() ?: return@forEachLine
                    entries[decode(parts[0])] = Entry(at, parts.drop(2).joinToString("\t"))
                }
            }
        }
    }

    @Synchronized
    fun get(key: String): Entry? = entries[key]

    @Synchronized
    fun contains(key: String): Boolean = entries.containsKey(key)

    @Synchronized
    fun put(key: String, atEpochSec: Long, payload: String) {
        entries[key] = Entry(atEpochSec, encode(payload))
        dirty = true
    }

    @Synchronized
    fun remove(key: String) {
        if (entries.remove(key) != null) dirty = true
    }

    @Synchronized
    fun size(): Int = entries.size

    @Synchronized
    fun keys(): Set<String> = entries.keys.toSet()

    @Synchronized
    fun clear() {
        entries.clear()
        dirty = true
        save()
    }

    @Synchronized
    fun save() {
        if (!dirty) return
        runCatching {
            file.parentFile?.mkdirs()
            temporaryFile.printWriter(Charsets.UTF_8).use { writer ->
                for ((key, entry) in entries) {
                    writer.write(encode(key))
                    writer.write('\t'.code)
                    writer.write(entry.atEpochSec.toString())
                    writer.write('\t'.code)
                    writer.write(entry.payload)
                    writer.write('\n'.code)
                }
            }
            // A process kill during a direct write can leave a truncated cache. Replace the
            // old snapshot only after the complete temporary file has been closed.
            if (!temporaryFile.renameTo(file)) {
                file.delete()
                check(temporaryFile.renameTo(file)) { "could not replace cache ${file.name}" }
            }
            dirty = false
        }
    }

    /** Keys and payloads must stay on one line; tabs and newlines are escaped, not stripped. */
    private fun encode(payload: String): String =
        payload.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")

    companion object {
        fun decode(payload: String): String = buildString {
            var index = 0
            while (index < payload.length) {
                val ch = payload[index]
                if (ch == '\\' && index + 1 < payload.length) {
                    when (payload[index + 1]) {
                        't' -> append('\t')
                        'n' -> append('\n')
                        'r' -> append('\r')
                        '\\' -> append('\\')
                        else -> append(payload[index + 1])
                    }
                    index += 2
                } else {
                    append(ch)
                    index++
                }
            }
        }

        /** Desktop retry schedule: 20 s, 40 s, 80 s … capped at 10 minutes. */
        fun backoffSeconds(attempts: Int): Long {
            if (attempts <= 0) return 20L
            var delay = 20L
            repeat((attempts - 1).coerceAtMost(10)) { delay *= 2 }
            return delay.coerceAtMost(600L)
        }
    }
}
