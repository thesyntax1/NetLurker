package dev.netlurker.android.core

import kotlin.math.sqrt

/**
 * Per-subject traffic baseline: exponential moving average plus an EWMA of the variance,
 * ported line for line from the desktop build's anomaly detector (src/main.cpp).
 *
 *   alpha  = 0.15
 *   var    = (1 - a) * var + a * (rate - ema)^2
 *   ema    = (1 - a) * ema + a * rate
 *   warm   = n >= 24 samples
 *   outlier = warm && last > floor && (last > ema + 3*sqrt(var) || last > ema * 3)
 *
 * The desktop build feeds it "new connections per minute" and uses a floor of 6. On
 * Android an unrooted app cannot see connections, so the same detector is fed "bytes per
 * second per application" instead, with the floor raised accordingly — the statistics are
 * unchanged, only the unit and its floor are.
 */
class BaselineTracker(
    private val alpha: Double = 0.15,
    private val warmupSamples: Int = 24,
    private val floor: Double = 6.0
) {
    data class Stat(
        var ema: Double = 0.0,
        var variance: Double = 0.0,
        var samples: Int = 0,
        var lastRate: Double = 0.0
    ) {
        val standardDeviation: Double get() = sqrt(variance)
        val warmedUp: Boolean get() = samples >= warmupSamples
    }

    private val stats = LinkedHashMap<String, Stat>()

    val subjects: Set<String> get() = stats.keys.toSet()

    fun stat(subject: String): Stat? = stats[subject]

    fun size(): Int = stats.size

    /** Feeds one observation and reports whether it is an outlier. */
    fun observe(subject: String, rate: Double, warmupSamplesOverride: Int = warmupSamples): Boolean {
        val existing = stats[subject]
        if (existing == null) {
            stats[subject] = Stat(ema = rate, variance = 0.0, samples = 1, lastRate = rate)
            return false
        }
        with(existing) {
            variance = (1 - alpha) * variance + alpha * (rate - ema) * (rate - ema)
            ema = (1 - alpha) * ema + alpha * rate
            samples++
            lastRate = rate
        }
        return isOutlier(existing, warmupSamplesOverride)
    }

    /** Pure predicate, exposed so the threshold can be asserted in tests. */
    fun isOutlier(stat: Stat, warmupSamplesOverride: Int = warmupSamples): Boolean {
        if (stat.samples < warmupSamplesOverride) return false
        if (stat.lastRate <= floor) return false
        val sigma = sqrt(stat.variance)
        return stat.lastRate > stat.ema + 3.0 * sigma || stat.lastRate > stat.ema * 3.0
    }

    fun clear() = stats.clear()

    /** Flat form used for the on-disk cache: subject, ema, variance, samples. */
    fun serialize(): List<String> = stats.map { (k, v) ->
        listOf(k, fmt(v.ema), fmt(v.variance), v.samples.toString()).joinToString("\t")
    }

    fun restore(lines: List<String>) {
        stats.clear()
        for (line in lines) {
            val parts = line.split('\t')
            if (parts.size < 4) continue
            val ema = parts[1].toDoubleOrNull() ?: continue
            val variance = parts[2].toDoubleOrNull() ?: continue
            val samples = parts[3].toIntOrNull() ?: continue
            if (parts[0].isBlank()) continue
            stats[parts[0]] = Stat(ema, variance, samples, 0.0)
        }
    }

    private fun fmt(d: Double): String = String.format(java.util.Locale.ROOT, "%.4f", d)
}
