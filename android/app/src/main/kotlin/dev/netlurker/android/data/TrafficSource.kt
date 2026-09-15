package dev.netlurker.android.data

import android.net.TrafficStats
import dev.netlurker.android.core.AppTraffic

/**
 * Per-application traffic counters read from [TrafficStats].
 *
 * What this is: cumulative byte counters maintained by the kernel for every UID, readable
 * only for the calling UID on Android 7+ (other UIDs return UNSUPPORTED). What it is not: a socket table. Android 10 and newer
 * block untrusted apps from reading /proc/net, so NetLurker cannot list which addresses a
 * given app is talking to — and it says so instead of guessing. See README-android.md.
 *
 * Counters are "since boot", so the numbers NetLurker shows are deltas measured between
 * polls: real rates, but only for the interval measured. A negative delta means the
 * counter was reset (reboot or iface reset) and the sample is discarded rather than shown.
 */
class TrafficSource(
    private val clock: () -> Long = { android.os.SystemClock.elapsedRealtime() },
    private val totalRx: () -> Long = { TrafficStats.getTotalRxBytes() },
    private val totalTx: () -> Long = { TrafficStats.getTotalTxBytes() },
    private val uidRx: (Int) -> Long = { TrafficStats.getUidRxBytes(it) },
    private val uidTx: (Int) -> Long = { TrafficStats.getUidTxBytes(it) }
) {

    private var lastSampleAtMs: Long? = null
    private var lastUidSampleAtMs: Long? = null
    private val lastRx = HashMap<Int, Long>()
    private val lastTx = HashMap<Int, Long>()
    private var sessionRx = 0L
    private var sessionTx = 0L

    val supported: Boolean
        get() = totalRx() >= 0 && totalTx() >= 0

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
        val now = clock()
        val rx = totalRx()
        val tx = totalTx()
        val elapsed = lastSampleAtMs?.let { (now - it).coerceAtLeast(0L) } ?: 0L
        var rateIn = 0.0
        var rateOut = 0.0
        if (elapsed > 0 && lastTotalRx >= 0 && lastTotalTx >= 0 &&
            rx >= lastTotalRx && tx >= lastTotalTx) {
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
    fun applyRates(apps: List<AppTraffic>, nowMs: Long = clock()): List<AppTraffic> {
        val elapsed = lastUidSampleAtMs?.let { (nowMs - it).coerceAtLeast(0L) } ?: 0L
        lastUidSampleAtMs = nowMs
        val uidCounts = apps.groupingBy { it.uid }.eachCount()
        val visibleUids = uidCounts.keys
        lastRx.keys.retainAll(visibleUids)
        lastTx.keys.retainAll(visibleUids)
        return apps.map { app ->
            // A shared UID counter cannot identify which package generated those bytes.
            // Do not attribute all bytes to each package, or a delta to whichever row ran first.
            val ambiguous = uidCounts.getValue(app.uid) > 1
            val rx = if (ambiguous) -1L else uidRx(app.uid)
            val tx = if (ambiguous) -1L else uidTx(app.uid)
            if (rx < 0 || tx < 0) {
                lastRx.remove(app.uid)
                lastTx.remove(app.uid)
                return@map app.copy(rxBytes = 0, txBytes = 0, rateIn = 0.0, rateOut = 0.0,
                    supported = false, active = false)
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
                lastChangeMs = if (changed) System.currentTimeMillis() else app.lastChangeMs
            )
        }
    }

    fun resetSession() {
        sessionRx = 0
        sessionTx = 0
        lastRx.clear()
        lastTx.clear()
        lastSampleAtMs = null
        lastUidSampleAtMs = null
        lastTotalRx = 0L
        lastTotalTx = 0L
    }
}
