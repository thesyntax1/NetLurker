package dev.netlurker.android.core

import java.util.Locale

/**
 * Formatting helpers, ported from the desktop build (src/common.cpp) so that an export
 * opened on Windows and the same export opened on a phone read identically.
 *
 * Every numeric format is pinned to [Locale.ROOT]: on a Turkish locale the default
 * formatter would emit "1,5 MB" and break both the CSV contract and the unit tests.
 */
object Format {

    /** Desktop `FormatBytesPerSec`: a rate of ~0 is a dash, never "0 B/s". */
    fun bytesPerSec(bps: Double): String = when {
        bps <= 0.5 -> "-"
        bps < 1024.0 -> root("%.0f B/s", bps)
        bps < 1024.0 * 1024 -> root("%.1f KB/s", bps / 1024.0)
        else -> root("%.2f MB/s", bps / (1024.0 * 1024))
    }

    /** Desktop `FormatBytes`. */
    fun bytes(b: Long): String = when {
        b < 0 -> "?"
        b < 1024L -> root("%d B", b)
        b < 1024L * 1024 -> root("%.1f KB", b / 1024.0)
        b < 1024L * 1024 * 1024 -> root("%.1f MB", b / (1024.0 * 1024))
        else -> root("%.2f GB", b / (1024.0 * 1024 * 1024))
    }

    /** Desktop `FormatDurationShort`. */
    fun durationShort(seconds: Long): String = when {
        seconds < 60 -> root("%d s", seconds)
        seconds < 3600 -> root("%d min", seconds / 60)
        seconds < 86400 -> root("%d h", seconds / 3600)
        else -> root("%d d", seconds / 86400)
    }

    /** Desktop `FormatDurationLong`. */
    fun durationLong(seconds: Long): String = when {
        seconds < 60 -> root("%d s", seconds)
        seconds < 3600 -> root("%d min %d s", seconds / 60, seconds % 60)
        else -> root("%d h %d min", seconds / 3600, (seconds % 3600) / 60)
    }

    /** Age of a lookup, e.g. the "5 min ago" stamp next to a cached geo answer. */
    fun age(nowEpochSec: Long, atEpochSec: Long): String {
        if (atEpochSec <= 0) return ""
        val delta = nowEpochSec - atEpochSec
        return when {
            delta < 0 -> durationShort(0)
            delta < 60 -> root("%d s", delta)
            delta < 3600 -> root("%d min", delta / 60)
            delta < 86400 -> root("%d h", delta / 3600)
            else -> root("%d d", delta / 86400)
        }
    }

    /** UTC timestamp for exports, so a report is unambiguous across time zones. */
    fun epochIso(epochMs: Long): String {
        val format = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT)
        format.timeZone = java.util.TimeZone.getTimeZone("UTC")
        return format.format(java.util.Date(epochMs))
    }

    /** Local clock time, for rows in the UI. */
    fun clockTime(epochMs: Long): String {
        val format = java.text.SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        return format.format(java.util.Date(epochMs))
    }

    fun percent(p: Double): String = root("%.0f%%", p)

    fun score(score: Int): String = root("%d/100", score)

    /** Hex with the usual separator, uppercase, e.g. for MACs and fingerprints. */
    fun hex(bytes: ByteArray, separator: String = ":"): String =
        bytes.joinToString(separator) { root("%02x", it).uppercase(Locale.ROOT) }

    private fun root(pattern: String, vararg args: Any?): String =
        String.format(Locale.ROOT, pattern, *args)
}
