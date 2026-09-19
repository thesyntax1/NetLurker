package dev.netlurker.android.core

import kotlin.math.sqrt

/**
 * Regularity detector, ported from the desktop build's beacon analysis.
 *
 * On Windows NetLurker timestamps every *new connection* a process opens to a given remote
 * and looks for a metronome. An unrooted Android app cannot see connections at all, but the
 * same shape is visible one level up: an application that wakes, moves data, and goes quiet
 * again on a fixed cycle. The statistics are deliberately identical to the desktop's, so a
 * verdict means the same thing on both platforms — at least four events, a mean gap between
 * 2 s and 900 s, and a coefficient of variation below 0.25, which is what separates a
 * heartbeat from ordinary bursty traffic.
 */
class BeaconDetector(
    private val maxEvents: Int = 24,
    private val maxAgeMs: Long = 1_800_000L,
    private val minHits: Int = 4,
    private val minMeanSec: Double = 2.0,
    private val maxMeanSec: Double = 900.0,
    private val maxJitter: Double = 0.25
) {

    /** A confirmed heartbeat: how many cycles were seen and how long each one is. */
    data class Pattern(val hits: Int, val periodSec: Int)

    private val events = LinkedHashMap<String, ArrayDeque<Long>>()

    fun record(subject: String, atMs: Long) {
        val list = events.getOrPut(subject) { ArrayDeque() }
        list.addLast(atMs)
        while (list.size > maxEvents) list.removeFirst()
    }

    /** Drops events older than the retention window, and subjects left with none. */
    fun prune(nowMs: Long) {
        val iterator = events.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            while (entry.value.isNotEmpty() && nowMs - entry.value.first() > maxAgeMs) {
                entry.value.removeFirst()
            }
            if (entry.value.isEmpty()) iterator.remove()
        }
    }

    /**
     * Returns a pattern only when the gaps are genuinely regular. Bursty-but-random traffic
     * returns null rather than a weak guess, because a false beacon accusation is worse than
     * saying nothing.
     */
    fun pattern(subject: String): Pattern? {
        val list = events[subject] ?: return null
        if (list.size < minHits) return null

        val gaps = ArrayList<Double>(list.size - 1)
        var previous = list.first()
        for (at in list) {
            if (at == previous) continue
            gaps.add((at - previous) / 1000.0)
            previous = at
        }
        if (gaps.isEmpty()) return null

        val mean = gaps.sum() / gaps.size
        if (mean < minMeanSec || mean > maxMeanSec) return null

        val variance = gaps.sumOf { (it - mean) * (it - mean) } / gaps.size
        if (sqrt(variance) / mean >= maxJitter) return null

        return Pattern(list.size, Math.round(mean).toInt())
    }

    fun hits(subject: String): Int = events[subject]?.size ?: 0

    fun subjects(): Set<String> = events.keys.toSet()

    fun size(): Int = events.size
}
