package dev.netlurker.android

import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.data.TrafficSource
import dev.netlurker.android.intel.Dnsbl
import dev.netlurker.android.intel.parseIso8601
import dev.netlurker.android.ui.parseInput
import java.net.UnknownHostException
import org.junit.Assert.*
import org.junit.Test

class DataAccuracyTest {
    @Test
    fun `device sampling does not overwrite the UID sampling clock`() {
        var now = 1000L
        var rx = 1000L
        var tx = 4000L
        val source = TrafficSource({ now }, { rx }, { tx }, { rx }, { tx })
        val apps = listOf(AppTraffic(uid = 1001, packageName = "test.app", label = "Test"))
        source.snapshot()
        assertEquals(0.0, source.applyRates(apps).single().rateIn, 0.001)
        now += 2000
        rx += 2000
        tx += 6000
        val device = source.snapshot() // This used to zero the UID elapsed interval.
        val app = source.applyRates(apps).single()
        assertEquals(1000.0, device.rateInBytesPerSec, 0.001)
        assertEquals(1000.0, app.rateIn, 0.001)
        assertEquals(3000.0, app.rateOut, 0.001)
        assertTrue(app.active)
    }

    @Test
    fun `unsupported counters and counter resets cannot create traffic spikes`() {
        var now = 0L
        var rx = -1L
        var tx = -1L
        val source = TrafficSource({ now }, { rx }, { tx }, { rx }, { tx })
        val apps = listOf(AppTraffic(uid = 1001, packageName = "test.app", label = "Test", active = true))
        source.snapshot()
        assertFalse(source.applyRates(apps).single().supported)
        now = 2000
        rx = 1_000_000
        tx = 2_000_000
        assertEquals(0.0, source.snapshot().rateInBytesPerSec, 0.001)
        assertEquals(0.0, source.applyRates(apps).single().rateIn, 0.001)
        now += 2000
        rx = 100
        tx = 200
        assertEquals(0.0, source.snapshot().rateInBytesPerSec, 0.001)
        assertEquals(0.0, source.applyRates(apps).single().rateIn, 0.001)
        tx = -1 // One unavailable direction invalidates the whole measurement.
        assertFalse(source.applyRates(apps).single().supported)
        assertFalse(source.applyRates(apps).single().active)
    }

    @Test
    fun `DNSBL refusal and hijacking responses are never listings`() {
        for (answer in listOf("127.255.255.252", "127.255.255.254", "127.255.255.255", "8.8.8.8")) {
            val result = Dnsbl.check("8.8.4.4") { listOf(answer) }!!
            assertTrue(result.hits.isEmpty())
            assertFalse(result.clean)
            assertEquals(Dnsbl.ZONES.size, result.unreachable.size)
        }
        val failed = Dnsbl.check("8.8.4.4") { throw UnknownHostException("ambiguous DNS failure") }!!
        assertFalse(failed.clean)
        assertTrue(failed.hits.isEmpty())
        assertEquals(Dnsbl.ZONES.size, Dnsbl.check("8.8.4.4") { listOf("127.0.0.2") }!!.hits.size)
    }

    @Test
    fun `ISO dates respect offsets and reject impossible calendar dates`() {
        assertEquals(1_700_000_000L, parseIso8601("2023-11-15T01:13:20+03:00"))
        assertEquals(1_700_000_000L, parseIso8601("2023-11-14T17:13:20-05:00"))
        assertEquals(0L, parseIso8601("2023-02-30T12:00:00Z"))
        assertEquals(0L, parseIso8601("junk 2023-11-14T22:13:20Z"))
    }

    @Test
    fun `IPv6 hextets are not mistaken for port numbers`() {
        assertEquals("2001:db8::443" to null, parseInput("2001:db8::443"))
        assertEquals("2001:db8::1" to 8443, parseInput("[2001:db8::1]:8443"))
        assertEquals("::1" to null, parseInput("[::1]"))
        assertEquals("[::1]:99999" to null, parseInput("[::1]:99999"))
    }
}
