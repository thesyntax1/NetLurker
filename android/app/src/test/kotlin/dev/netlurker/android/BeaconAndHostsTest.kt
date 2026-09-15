package dev.netlurker.android

import dev.netlurker.android.core.AnomalyAlert
import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.core.BeaconDetector
import dev.netlurker.android.core.ReasonKeys
import dev.netlurker.android.core.RiskEngine
import dev.netlurker.android.core.RiskLevel
import dev.netlurker.android.data.HostsFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The two desktop rules that Android can reproduce without a socket table: the heartbeat
 * detector (netmon.cpp:948) and the hosts-file redirect (dns.cpp LoadHosts()). Both are
 * arithmetic over data the platform really hands us, so both are pinned here — including
 * the cases that must NOT fire, which is where a scoring rule does its damage.
 */
class BeaconAndHostsTest {

    // ------------------------------------------------------------------------------------
    // BeaconDetector — thresholds copied from the desktop lambda
    // ------------------------------------------------------------------------------------

    @Test
    fun `a steady heartbeat is detected with its period`() {
        val detector = BeaconDetector()
        val start = 1_700_000_000_000L
        repeat(6) { detector.record("app", start + it * 30_000L) }

        val pattern = detector.pattern("app")
        assertEquals(6, pattern!!.hits)
        assertEquals(30, pattern.periodSec)
    }

    @Test
    fun `jittered traffic is not a heartbeat`() {
        val detector = BeaconDetector()
        val start = 1_700_000_000_000L
        // Gaps alternate 5 s / 55 s: mean 30 s but sd/mean is 0.82, far above the 0.25 cap.
        val gaps = listOf(5_000L, 55_000L, 5_000L, 55_000L, 5_000L, 55_000L)
        var at = start
        for (gap in gaps) {
            detector.record("app", at)
            at += gap
        }
        assertNull(detector.pattern("app"))
    }

    @Test
    fun `three bursts are not enough evidence`() {
        val detector = BeaconDetector()
        val start = 1_700_000_000_000L
        repeat(3) { detector.record("app", start + it * 30_000L) }
        assertNull(detector.pattern("app"))
    }

    @Test
    fun `a period outside the plausible range is rejected`() {
        val tooFast = BeaconDetector()
        val start = 1_700_000_000_000L
        // 500 ms apart: mean 0.5 s, below the 2 s floor.
        repeat(5) { tooFast.record("app", start + it * 500L) }
        assertNull(tooFast.pattern("app"))

        val tooSlow = BeaconDetector()
        // 20 minutes apart: mean 1200 s, above the 900 s ceiling.
        repeat(5) { tooSlow.record("app", start + it * 1_200_000L) }
        assertNull(tooSlow.pattern("app"))
    }

    @Test
    fun `bursts older than half an hour are forgotten`() {
        val detector = BeaconDetector()
        val start = 1_700_000_000_000L
        repeat(5) { detector.record("app", start + it * 30_000L) }
        assertEquals(5, detector.pattern("app")!!.hits)

        // The window is 30 minutes; one hour later the same subject has no history.
        detector.prune(start + 3_600_000L)
        assertNull(detector.pattern("app"))
        assertEquals(0, detector.size())
    }

    @Test
    fun `only the most recent events are kept`() {
        val detector = BeaconDetector(maxEvents = 24)
        val start = 1_700_000_000_000L
        repeat(40) { detector.record("app", start + it * 30_000L) }
        assertEquals(24, detector.pattern("app")!!.hits)
    }

    @Test
    fun `subjects are tracked independently`() {
        val detector = BeaconDetector()
        val start = 1_700_000_000_000L
        repeat(6) { detector.record("steady", start + it * 30_000L) }
        detector.record("chatty", start)
        detector.record("chatty", start + 400_000L)

        assertEquals(30, detector.pattern("steady")!!.periodSec)
        assertNull(detector.pattern("chatty"))
        assertNull(detector.pattern("never seen"))
        assertEquals(2, detector.size())
    }

    // ------------------------------------------------------------------------------------
    // HostsFile — parsing, not reading: the file itself is not reachable from a unit test
    // ------------------------------------------------------------------------------------

    @Test
    fun `hosts entries are parsed and counted`() {
        val snapshot = HostsFile.parse(
            """
            # comment line
            127.0.0.1	localhost
            ::1 ip6-localhost

            0.0.0.0 ads.example tracker.example
            198.51.100.7  sinkhole.example  # trailing comment
            """.trimIndent()
        )
        assertEquals(2, snapshot.entries)
        assertTrue(snapshot.redirects("0.0.0.0"))
        assertTrue(snapshot.redirects("198.51.100.7"))
        // The loopback lines the desktop skips are not redirections.
        assertFalse(snapshot.redirects("127.0.0.1"))
        assertFalse(snapshot.redirects("::1"))
        assertFalse(snapshot.redirects("93.184.216.34"))
    }

    @Test
    fun `names are kept per address so the ui can show what was redirected`() {
        val snapshot = HostsFile.parse("0.0.0.0 ads.example tracker.example\n0.0.0.0 other.example")
        assertEquals(setOf("ads.example", "tracker.example", "other.example"),
            snapshot.namesByIp["0.0.0.0"]!!.toSet())
        assertEquals(
            "ads.example, tracker.example, other.example",
            snapshot.namesFor("0.0.0.0")
        )
    }

    @Test
    fun `blank and malformed lines are ignored rather than counted`() {
        val snapshot = HostsFile.parse("\n\n   \n# only a comment\nnotanip\n127.0.0.1\n")
        assertEquals(0, snapshot.entries)
        assertTrue(snapshot.redirectedIps.isEmpty())
    }

    @Test
    fun `carriage returns from a windows-edited hosts file do not leak into addresses`() {
        val snapshot = HostsFile.parse("0.0.0.0 ads.example\r\n198.51.100.7 sink.example\r\n")
        assertEquals(2, snapshot.entries)
        assertTrue(snapshot.redirects("0.0.0.0"))
        assertEquals("ads.example", snapshot.namesByIp["0.0.0.0"]!!.single())
    }

    @Test
    fun `an unreadable file reports itself instead of pretending to be empty`() {
        val snapshot = HostsFile.read("/proc/definitely-not-a-hosts-file")
        assertFalse(snapshot.readable)
        assertTrue(snapshot.redirectedIps.isEmpty())
        assertTrue(snapshot.entries == 0)
    }

    // ------------------------------------------------------------------------------------
    // evaluateApp — the application-level verdict
    // ------------------------------------------------------------------------------------

    private fun app(
        rateIn: Double = 0.0,
        rateOut: Double = 0.0,
        supported: Boolean = true
    ) = AppTraffic(
        uid = 10123,
        packageName = "com.example.app",
        label = "Example",
        rxBytes = 0,
        txBytes = 0,
        rateIn = rateIn,
        rateOut = rateOut,
        supported = supported
    )

    private fun keysOf(app: AppTraffic, alert: AnomalyAlert?, beacon: BeaconDetector.Pattern?) =
        RiskEngine.evaluateApp(app, alert, beacon).reasons.map { it.key }

    @Test
    fun `an upload-dominated ratio above the floor is flagged`() {
        val verdict = RiskEngine.evaluateApp(
            app(rateIn = 10.0 * 1024, rateOut = 300.0 * 1024), null, null
        )
        assertEquals(20, verdict.score)
        assertEquals(ReasonKeys.APP_EXFIL_RATIO, verdict.reasons.single().key)
        assertEquals(20, verdict.reasons.single().points)
    }

    @Test
    fun `a heavy upload below the rate floor is not flagged`() {
        // 100 KiB/s out against nothing coming in: a clear ratio, too quiet to matter.
        assertTrue(keysOf(app(rateIn = 0.0, rateOut = 100.0 * 1024), null, null).isEmpty())
    }

    @Test
    fun `an upload under six times the download is not flagged`() {
        // 300 KiB/s out against 100 KiB/s in: only 3x.
        assertTrue(keysOf(app(rateIn = 100.0 * 1024, rateOut = 300.0 * 1024), null, null).isEmpty())
    }

    @Test
    fun `unsupported counters never produce a ratio finding`() {
        // A zero rateIn on a device that does not report counters is a missing measurement,
        // not a silent download.
        val verdict = RiskEngine.evaluateApp(
            app(rateIn = 0.0, rateOut = 300.0 * 1024, supported = false), null, null
        )
        assertTrue(verdict.reasons.isEmpty())
    }

    @Test
    fun `a fast heartbeat scores higher than a slow one`() {
        val fast = RiskEngine.evaluateApp(app(), null, BeaconDetector.Pattern(hits = 8, periodSec = 45))
        assertEquals(25, fast.reasons.single().points)
        assertEquals(ReasonKeys.APP_BEACON, fast.reasons.single().key)

        val slow = RiskEngine.evaluateApp(app(), null, BeaconDetector.Pattern(hits = 8, periodSec = 600))
        assertEquals(12, slow.reasons.single().points)
    }

    @Test
    fun `findings accumulate and the level follows the total`() {
        val alert = AnomalyAlert(
            subject = "Example", baseline = 4096.0, current = 512.0 * 1024,
            percent = 12400, atMs = 0L
        )
        val verdict = RiskEngine.evaluateApp(
            app(rateIn = 1024.0, rateOut = 300.0 * 1024),
            alert,
            BeaconDetector.Pattern(hits = 9, periodSec = 60)
        )
        // 25 anomaly + 20 exfiltration ratio + 25 fast heartbeat
        assertEquals(70, verdict.score)
        assertEquals(RiskLevel.DANGER, verdict.level)
        assertEquals(
            listOf(
                ReasonKeys.APP_TRAFFIC_ANOMALY,
                ReasonKeys.APP_EXFIL_RATIO,
                ReasonKeys.APP_BEACON
            ),
            verdict.reasons.map { it.key }
        )
    }

    @Test
    fun `an idle application gets no verdict at all`() {
        val verdict = RiskEngine.evaluateApp(app(), null, null)
        assertEquals(RiskEngine.evaluateApp(app(), null, null), dev.netlurker.android.core.Verdict.none)
        assertEquals(0, verdict.score)
        assertEquals(RiskLevel.SAFE, verdict.level)
    }
}
