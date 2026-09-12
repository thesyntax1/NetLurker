package dev.netlurker.android.data

import android.net.TrafficStats
import dev.netlurker.android.core.AppTraffic

/**
 * Per-application traffic counters read from [TrafficStats].
 *
 * What this is: cumulative byte counters maintained by the kernel for every UID, readable
 * by any app without permission. What it is not: a socket table. Android 10 and newer
 * block untrusted apps from reading /proc/net, so NetLurker cannot list which addresses a
 * given app is talking to — and it says so instead of guessing. See README-android.md.
 *
 * Counters are "since boot", so the numbers NetLurker shows are deltas measured between
 * polls: real rates, but only for the interval measured. A negative delta means the
 * counter was reset (reboot or iface reset) and the sample is discarded rather than shown.
 */
class TrafficSource {

    private var lastSampleAtMs = 0L
    private val lastRx = HashMap<Int, Long>()
    private val lastTx = HashMap<Int, Long>()
    private var sessionRx = 0L
    private var sessionTx = 0L

    val supported: Boolean
        get() = TrafficStats.getTotalRxBytes() != TrafficStats.UNSUPPORTED.toLong()

    data class Snapshot(
        val totalRxBytes: Long,
        val totalTxBytes: Long,
        val rateInBytesPerSec: Double,
        val rateOutBytesPerSec: Double,
        val sessionRxBytes: Long,
        val sessionTxBytes: Long,
        val elapsedMs: Long
    ) {
        val rateTotalBytesPerSec: Double get() = rateInBytesPerSec + rateOutBytesPerSec
    }

    fun snapshot(): Snapshot {
        val now = System.currentTimeMillis()
        val rx = TrafficStats.getTotalRxBytes()
        val tx = TrafficStats.getTotalTxBytes()
        val elapsed = if (lastSampleAtMs == 0L) 0L else now - lastSampleAtMs
        var rateIn = 0.0
        var rateOut = 0.0
        if (lastSampleAtMs != 0L && elapsed > 0 && rx >= lastTotalRx && tx >= lastTotalTx) {
            rateIn = (rx - lastTotalRx) * 1000.0 / elapsed
            rateOut = (tx - lastTotalTx) * 1000.0 / elapsed
            sessionRx += (rx - lastTotalRx).coerceAtLeast(0L)
            sessionTx += (tx - lastTotalTx).coerceAtLeast(0L)
        }
        lastTotalRx = rx
        lastTotalTx = tx
        lastSampleAtMs = now
        return Snapshot(
            totalRxBytes = rx,
            totalTxBytes = tx,
            rateInBytesPerSec = rateIn,
            rateOutBytesPerSec = rateOut,
            sessionRxBytes = sessionRx,
            sessionTxBytes = sessionTx,
            elapsedMs = elapsed
        )
    }

    private var lastTotalRx = 0L
    private var lastTotalTx = 0L

    /** Mobile-only counters, when the framework exposes them. */
    fun mobileRxBytes(): Long = TrafficStats.getMobileRxBytes()
    fun mobileTxBytes(): Long = TrafficStats.getMobileTxBytes()

    /**
     * Applies freshly measured rates onto the app rows. Rows whose counter went backwards
     * (reboot, counter reset) get a zero rate rather than a nonsense negative one.
     */
    fun applyRates(apps: List<AppTraffic>, nowMs: Long = System.currentTimeMillis()): List<AppTraffic> {
        val elapsed = if (lastSampleAtMs == 0L) 0L else (nowMs - lastSampleAtMs)
        return apps.map { app ->
            val rx = TrafficStats.getUidRxBytes(app.uid)
            val tx = TrafficStats.getUidTxBytes(app.uid)
            if (rx == TrafficStats.UNSUPPORTED.toLong() && tx == TrafficStats.UNSUPPORTED.toLong()) {
                return@map app.copy(rxBytes = 0, txBytes = 0, rateIn = 0.0, rateOut = 0.0, supported = false)
            }
            val previousRx = lastRx[app.uid]
            val previousTx = lastTx[app.uid]
            var rateIn = 0.0
            var rateOut = 0.0
            var changed = false
            if (previousRx != null && elapsed > 0 && rx >= previousRx) {
                rateIn = (rx - previousRx) * 1000.0 / elapsed
                if (rx != previousRx) changed = true
            }
            if (previousTx != null && elapsed > 0 && tx >= previousTx) {
                rateOut = (tx - previousTx) * 1000.0 / elapsed
                if (tx != previousTx) changed = true
            }
            lastRx[app.uid] = rx
            lastTx[app.uid] = tx
            app.copy(
                rxBytes = rx.coerceAtLeast(0L),
                txBytes = tx.coerceAtLeast(0L),
                rateIn = rateIn,
                rateOut = rateOut,
                supported = true,
                active = changed || rateIn > 0.5 || rateOut > 0.5,
                lastChangeMs = if (changed) nowMs else app.lastChangeMs
            )
        }
    }

    /** Number of apps whose counters moved during the last interval. */
    fun activeCount(): Int = lastRx.keys.size

    fun resetSession() {
        sessionRx = 0
        sessionTx = 0
        lastRx.clear()
        lastTx.clear()
        lastSampleAtMs = 0L
        lastTotalRx = 0L
        lastTotalTx = 0L
    }
}
