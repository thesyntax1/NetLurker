package dev.netlurker.android.data

import dev.netlurker.android.core.AnomalyAlert
import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.core.BaselineTracker
import dev.netlurker.android.core.CountItem
import dev.netlurker.android.core.RateSample
import dev.netlurker.android.core.Target

/**
 * The session record: what moved, when, and what stood out.
 *
 * Mirrors the desktop build's History class: a rolling rate window (2 minutes), per-subject
 * baselines, and the top-N lists the Summary tab is built from. Nothing here is invented —
 * if the session has only run for ten seconds, the totals say ten seconds.
 */
class SessionHistory {

    private val rateWindow = ArrayDeque<RateSample>()
    private val appRates = LinkedHashMap<String, ArrayDeque<RateSample>>()

    /** Traffic floor for the anomaly detector: 4 KiB/s. Below that a phone is idle. */
    private val baseline = BaselineTracker(warmupSamples = 24, floor = 4096.0)

    private val alerts = LinkedHashMap<String, AnomalyAlert>()
    private val firstSampleAtMs = System.currentTimeMillis()

    var sessionInBytes = 0L
        private set
    var sessionOutBytes = 0L
        private set
    var closedCount = 0
        private set

    val elapsedMs: Long get() = System.currentTimeMillis() - firstSampleAtMs

    val alertsSnapshot: List<AnomalyAlert> get() = alerts.values.sortedByDescending { it.atMs }

    fun rateWindowSnapshot(): List<RateSample> = rateWindow.toList()

    fun appRateWindow(label: String): List<RateSample> = appRates[label]?.toList().orEmpty()

    fun baselineOf(label: String): BaselineTracker.Stat? = baseline.stat(label)

    fun baselineSize(): Int = baseline.size()

    fun clearBaselines() {
        baseline.clear()
        alerts.clear()
    }

    fun restoreBaselines(lines: List<String>) = baseline.restore(lines)

    fun serializeBaselines(): List<String> = baseline.serialize()

    /**
     * Records one poll. Returns the anomalies detected in this sample.
     *
     * @param perApp byte totals per application, as measured by [TrafficSource]
     * @param intervalMs the real elapsed time between polls, so rates stay honest when the
     *   poller is throttled by doze mode.
     */
    fun record(
        totalInBytes: Long,
        totalOutBytes: Long,
        perApp: Map<String, Long>,
        intervalMs: Long
    ): List<AnomalyAlert> {
        val now = System.currentTimeMillis()
        if (intervalMs > 0) {
            val seconds = intervalMs / 1000.0
            val rateIn = (totalInBytes - sessionInBytes).coerceAtLeast(0L) / seconds
            val rateOut = (totalOutBytes - sessionOutBytes).coerceAtLeast(0L) / seconds
            pushSample(rateWindow, RateSample(now, rateIn, rateOut))
        }
        sessionInBytes = totalInBytes
        sessionOutBytes = totalOutBytes

        val fresh = mutableListOf<AnomalyAlert>()
        for ((label, total) in perApp) {
            val previous = appTotals[label]
            appTotals[label] = total
            if (previous == null || intervalMs <= 0) continue
            val delta = total - previous
            if (delta < 0) continue // counter reset — do not treat it as traffic
            val rate = delta * 1000.0 / intervalMs
            pushSample(
                appRates.getOrPut(label) { ArrayDeque() },
                RateSample(now, 0.0, rate)
            )
            if (baseline.observe(label, rate)) {
                val stat = baseline.stat(label) ?: continue
                val percent = if (stat.ema > 0.5) ((rate / stat.ema - 1.0) * 100.0).toInt() else 0
                val alert = AnomalyAlert(
                    subject = label,
                    baseline = stat.ema,
                    current = rate,
                    percent = percent,
                    atMs = now
                )
                alerts[label] = alert
                fresh += alert
            }
        }
        return fresh
    }

    fun noteAppRate(label: String, rate: Double) {
        baseline.observe(label, rate)
    }

    fun topApps(apps: List<AppTraffic>, limit: Int): List<CountItem> =
        apps.filter { it.totalBytes > 0 }
            .sortedByDescending { it.totalBytes }
            .take(limit)
            .map {
                CountItem(
                    label = it.label,
                    sub = it.packageName,
                    value = it.totalBytes.toDouble(),
                    count = (it.rateIn + it.rateOut).toInt()
                )
            }

    fun topCountries(targets: List<Target>, limit: Int): List<CountItem> {
        val grouped = LinkedHashMap<String, Int>()
        for (target in targets) {
            val geo = target.geo.value ?: continue
            val label = geo.country.ifBlank { continue }
            grouped[label] = (grouped[label] ?: 0) + 1
        }
        return grouped.entries.sortedByDescending { it.value }.take(limit).map {
            CountItem(it.key, "destinations", it.value.toDouble(), it.value)
        }
    }

    fun topOrganisations(targets: List<Target>, limit: Int): List<CountItem> {
        val grouped = LinkedHashMap<String, Int>()
        for (target in targets) {
            val org = target.geo.value?.org?.ifBlank { null }
                ?: target.threat.value?.rdapOrg?.ifBlank { null }
                ?: continue
            grouped[org] = (grouped[org] ?: 0) + 1
        }
        return grouped.entries.sortedByDescending { it.value }.take(limit).map {
            CountItem(it.key, "destinations", it.value.toDouble(), it.value)
        }
    }

    fun topPorts(targets: List<Target>, limit: Int): List<CountItem> {
        val grouped = LinkedHashMap<Int, Int>()
        for (target in targets) {
            val port = target.port ?: continue
            grouped[port] = (grouped[port] ?: 0) + 1
        }
        return grouped.entries.sortedByDescending { it.value }.take(limit).map {
            CountItem(
                it.key.toString(),
                dev.netlurker.android.core.Ports.serviceName(it.key) ?: "unknown service",
                it.value.toDouble(),
                it.value
            )
        }
    }

    fun noteClosed(count: Int = 1) {
        closedCount += count
    }

    private val appTotals = HashMap<String, Long>()

    private fun pushSample(window: ArrayDeque<RateSample>, sample: RateSample) {
        window.addLast(sample)
        while (window.isNotEmpty() && sample.atMs - window.first().atMs > WINDOW_MS) {
            window.removeFirst()
        }
        while (window.size > MAX_SAMPLES) window.removeFirst()
    }

    fun reset() {
        rateWindow.clear()
        appRates.clear()
        appTotals.clear()
        baseline.clear()
        alerts.clear()
        sessionInBytes = 0
        sessionOutBytes = 0
        closedCount = 0
    }

    private companion object {
        const val WINDOW_MS = 120_000L
        const val MAX_SAMPLES = 2048
    }
}
