package dev.netlurker.android

import dev.netlurker.android.core.AnomalyAlert
import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.core.BannerInfo
import dev.netlurker.android.core.BaselineTracker
import dev.netlurker.android.core.DeviceSnapshot
import dev.netlurker.android.core.Export
import dev.netlurker.android.core.ExportSnapshot
import dev.netlurker.android.core.Format
import dev.netlurker.android.core.IntelResult
import dev.netlurker.android.core.Ip
import dev.netlurker.android.core.JsonWriter
import dev.netlurker.android.core.LinkInfo
import dev.netlurker.android.core.Ports
import dev.netlurker.android.core.Target
import dev.netlurker.android.core.ThreatInfo
import dev.netlurker.android.intel.BannerProbe
import dev.netlurker.android.intel.parseIso8601
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Formatting must match the desktop build byte for byte, or exports stop comparing. */
class FormatTest {

    @Test
    fun `bytes per second matches the desktop table`() {
        assertEquals("-", Format.bytesPerSec(0.0))
        assertEquals("-", Format.bytesPerSec(0.5))
        assertEquals("512 B/s", Format.bytesPerSec(512.0))
        assertEquals("1.0 KB/s", Format.bytesPerSec(1024.0))
        assertEquals("1.5 KB/s", Format.bytesPerSec(1536.0))
        assertEquals("1.00 MB/s", Format.bytesPerSec(1024.0 * 1024))
    }

    @Test
    fun `bytes matches the desktop table`() {
        assertEquals("0 B", Format.bytes(0))
        assertEquals("1023 B", Format.bytes(1023))
        assertEquals("1.0 KB", Format.bytes(1024))
        assertEquals("1.5 KB", Format.bytes(1536))
        assertEquals("1.0 MB", Format.bytes(1024L * 1024))
        assertEquals("1.50 GB", Format.bytes(3L * 1024 * 1024 * 1024 / 2))
    }

    @Test
    fun `durations match the desktop table`() {
        assertEquals("45 s", Format.durationShort(45))
        assertEquals("3 min", Format.durationShort(180))
        assertEquals("2 h", Format.durationShort(7_200))
        assertEquals("1 d", Format.durationShort(90_000))
        assertEquals("45 s", Format.durationLong(45))
        assertEquals("2 min 30 s", Format.durationLong(150))
        assertEquals("1 h 30 min", Format.durationLong(5_400))
    }

    @Test
    fun `numeric output never uses a comma decimal separator`() {
        val locale = java.util.Locale.getDefault()
        try {
            java.util.Locale.setDefault(java.util.Locale("tr", "TR"))
            assertEquals("1.5 KB", Format.bytes(1536))
            assertEquals("1.50 GB", Format.bytes(3L * 1024 * 1024 * 1024 / 2))
        } finally {
            java.util.Locale.setDefault(locale)
        }
    }
}

class IpTest {

    @Test
    fun `private ranges are recognised`() {
        for (address in listOf(
            "10.0.0.1", "10.255.255.255", "192.168.1.1", "172.16.0.1", "172.31.255.255",
            "127.0.0.1", "169.254.1.1", "100.64.0.1", "100.127.0.1", "0.0.0.0",
            "224.0.0.1", "::1", "fe80::1", "fd00::1"
        )) {
            assertFalse("expected $address to be private", Ip.isPublic(address))
        }
    }

    @Test
    fun `public ranges are recognised`() {
        for (address in listOf(
            "8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1", "100.63.0.1", "100.128.0.1",
            "203.0.113.9", "2606:2800:220:1:248:1893:25c8:1946"
        )) {
            assertTrue("expected $address to be public", Ip.isPublic(address))
        }
    }

    @Test
    fun `dnsbl reverse form is ipv4 only`() {
        assertEquals("34.216.184.93", Ip.reverseForDnsbl("93.184.216.34"))
        assertNull(Ip.reverseForDnsbl("2606:2800::1"))
        assertNull(Ip.reverseForDnsbl("not-an-address"))
    }

    @Test
    fun `strict ipv4 parsing rejects malformed octets`() {
        assertTrue(Ip.isIPv4("192.168.0.1"))
        assertFalse(Ip.isIPv4("192.168.0"))
        assertFalse(Ip.isIPv4("192.168.0.256"))
        assertFalse(Ip.isIPv4("192.168.00.1"))
        assertFalse(Ip.isIPv4("192.168.0.-1"))
    }

    @Test
    fun `zone suffix is stripped from interface addresses`() {
        assertEquals("fe80::1", Ip.stripZone("fe80::1%wlan0"))
    }

    @Test
    fun `address ranges are checked numerically for provider evidence`() {
        assertTrue(Ip.isInRange("8.8.8.8", "8.8.8.0", "8.8.8.255"))
        assertFalse(Ip.isInRange("8.8.4.4", "8.8.8.0", "8.8.8.255"))
        assertTrue(Ip.isInRange("2001:db8::2", "2001:db8::", "2001:db8::ffff"))
        assertFalse(Ip.isInRange("8.8.8.8", "2001:db8::", "2001:db8::ffff"))
    }
}

/** The anomaly detector is the desktop algorithm verbatim; the thresholds are pinned. */
class BaselineTest {

    @Test
    fun `first observation seeds the baseline and never alerts`() {
        val tracker = BaselineTracker()
        assertFalse(tracker.observe("app", 100.0))
        assertEquals(100.0, tracker.stat("app")!!.ema, 1e-9)
        assertEquals(1, tracker.stat("app")!!.samples)
    }

    @Test
    fun `a flat series never alerts however long it runs`() {
        val tracker = BaselineTracker(floor = 1.0)
        repeat(200) { assertFalse(tracker.observe("app", 500.0)) }
    }

    @Test
    fun `warmup must complete before an outlier can be reported`() {
        val tracker = BaselineTracker(warmupSamples = 24, floor = 1.0)
        repeat(23) { tracker.observe("app", 100.0) }
        // Sample 24 is the first warmed one; the spike arrives on 25.
        tracker.observe("app", 100.0)
        assertTrue(tracker.observe("app", 100_000.0))
    }

    @Test
    fun `the floor suppresses spikes on an idle subject`() {
        val tracker = BaselineTracker(warmupSamples = 3, floor = 1_000.0)
        repeat(10) { tracker.observe("app", 1.0) }
        assertFalse(tracker.observe("app", 900.0))
    }

    @Test
    fun `three sigma or three times the mean is enough`() {
        val tracker = BaselineTracker(warmupSamples = 5, floor = 1.0)
        repeat(30) { tracker.observe("app", 100.0) }
        // The mean is updated before the test, so the spike must clear three times the
        // updated mean: for a 100 baseline that needs more than 463, not merely 4x.
        assertFalse(tracker.observe("app", 400.0))
        assertTrue(tracker.observe("app", 1_000.0))
    }

    @Test
    fun `serialisation round-trips`() {
        val tracker = BaselineTracker()
        repeat(5) { tracker.observe("com.example.app", 123.456) }
        val lines = tracker.serialize()
        assertEquals(1, lines.size)
        val restored = BaselineTracker()
        restored.restore(lines)
        val stat = restored.stat("com.example.app")
        assertTrue(stat != null)
        assertEquals(5, stat!!.samples)
        assertEquals(tracker.stat("com.example.app")!!.ema, stat.ema, 1e-3)
    }
}

class JsonWriterTest {

    @Test
    fun `nested objects keep their separators`() {
        val json = JsonWriter("").apply {
            beginObject()
            name("a"); value(1)
            name("nested"); beginObject()
            name("b"); value("x")
            name("c"); value(true)
            endObject()
            name("d"); beginArray()
            value("one"); value("two")
            endArray()
            name("e"); value(null as String?)
            endObject()
        }.build()
        assertEquals("""{"a":1,"nested":{"b":"x","c":true},"d":["one","two"],"e":null}""", json)
    }

    @Test
    fun `escapes control characters and quotes`() {
        assertEquals("\"a\\\"b\"", JsonWriter.escapeToString("a\"b"))
        assertEquals("\"a\\nb\"", JsonWriter.escapeToString("a\nb"))
        assertEquals("\"a\\\\b\"", JsonWriter.escapeToString("a\\b"))
    }

    @Test(expected = IllegalStateException::class)
    fun `unbalanced containers are refused`() {
        JsonWriter("").beginObject().build()
    }

    @Test
    fun `non finite doubles become null rather than breaking the document`() {
        val json = JsonWriter("").apply {
            beginObject(); name("x"); value(Double.NaN); endObject()
        }.build()
        assertEquals("""{"x":null}""", json)
    }
}

class ExportTest {

    private fun snapshot() = ExportSnapshot(
        generatedAtMs = 1_700_000_000_000L,
        appVersion = "1.0.0-test",
        language = "en",
        device = DeviceSnapshot(
            model = "Test", manufacturer = "Vendor", androidRelease = "14",
            sdkInt = 34, securityPatch = "2024-01-01", uptimeMs = 60_000
        ),
        link = LinkInfo(
            networkName = "Wi-Fi", transport = "Wi-Fi", validated = true, metered = false,
            roaming = false, vpn = false, captivePortal = false,
            localAddresses = listOf("192.168.1.5/24"), dnsServers = listOf("192.168.1.1"),
            domains = emptyList(), routes = listOf("default via 192.168.1.1"), mtu = 1500
        ),
        wifi = null,
        cellular = null,
        apps = listOf(
            AppTraffic(
                uid = 10_123, packageName = "com.example.app", label = "Example",
                rxBytes = 2_048, txBytes = 1_024, rateIn = 100.0, rateOut = 50.0,
                signerSubject = "CN=Example", requestedPermissions = listOf("android.permission.INTERNET")
            )
        ),
        targets = listOf(
            Target(
                input = "93.184.216.34", ip = "93.184.216.34", port = 443,
                geo = IntelResult.ok(dev.netlurker.android.core.GeoInfo(country = "United States", org = "Example Inc")),
                threat = IntelResult.ok(ThreatInfo(abuseScore = 0, dnsblHits = listOf("SBL/XBL"))),
                banner = IntelResult.ok(BannerInfo(server = "nginx/1.25.0"))
            )
        ),
        alerts = listOf(
            AnomalyAlert(subject = "Example", baseline = 1_000.0, current = 9_000.0, percent = 800, atMs = 1_700_000_000_000L)
        ),
        kpis = listOf("download" to "1.0 KB/s", "upload" to "512 B/s"),
        trafficSupported = true,
        elapsedMs = 120_000
    )

    @Test
    fun `json export contains the evidence and the honesty fields`() {
        // The writer indents for readability; strip whitespace so these assertions test
        // the structure and the values rather than the layout.
        val json = Export.json(snapshot()).replace(Regex("\\s+"), "")
        assertTrue(json.contains("\"platform\":\"android\""))
        assertTrue(json.contains("\"trafficCountersSupported\":true"))
        assertTrue(json.contains("\"dnsblHits\":[\"SBL/XBL\"]"))
        assertTrue(json.contains("\"geoStatus\":\"OK\""))
        // A source that was not queried must say so rather than disappearing.
        assertTrue(json.contains("\"certStatus\":\"IDLE\""))
        assertTrue(json.contains("\"percentAboveBaseline\":800"))
        assertEquals(json.count { it == '{' }, json.count { it == '}' })
        assertEquals(json.count { it == '[' }, json.count { it == ']' })
    }

    @Test
    fun `csv export escapes separators and carries the headers`() {
        val csv = Export.csv(snapshot())
        val lines = csv.trim().split("\r\n")
        assertTrue(lines.first().startsWith("type;name;package;uid;"))
        assertTrue(csv.contains("app;Example;com.example.app;10123;2048;1024;"))
        assertTrue(csv.contains("destination;93.184.216.34;93.184.216.34;443;"))
        assertTrue(csv.contains("anomaly;Example;1000;9000;800;"))
    }

    @Test
    fun `text export labels every section through the resolver`() {
        val labels = mapOf(
            "export.title" to "REPORT",
            "export.generated" to "Generated",
            "export.session" to "Session",
            "export.device" to "Device",
            "export.kpis" to "KPIs",
            "export.anomalies" to "Anomalies",
            "export.no_anomalies" to "none",
            "export.applications" to "Applications",
            "export.destinations" to "Destinations",
            "export.privacy" to "PRIVACY",
            "traffic.unsupported" to "unsupported"
        )
        val text = Export.text(snapshot()) { key -> labels[key] ?: key }
        assertTrue(text.startsWith("REPORT"))
        assertTrue(text.contains("Anomalies (1)"))
        assertTrue(text.contains("Destinations (1)"))
        assertTrue(text.contains("PRIVACY"))
        assertFalse(text.contains("null"))
    }

    @Test
    fun `html export escapes values`() {
        val poisoned = snapshot().copy(
            apps = listOf(
                AppTraffic(
                    uid = 1, packageName = "a<b>", label = "Evil & \"Co\"",
                    rxBytes = 1, txBytes = 1
                )
            )
        )
        val html = Export.html(poisoned) { it }
        assertTrue(html.contains("Evil &amp; &quot;Co&quot;"))
        assertFalse(html.contains("a<b>"))
        assertTrue(html.startsWith("<!DOCTYPE html>"))
    }
}

class PortsTest {

    @Test
    fun `every suspicious port has a service or a note and no duplicate ports exist`() {
        val ports = Ports.suspicious.keys.toList()
        assertEquals("duplicate port in the suspicious table", ports.size, ports.toSet().size)
        for ((port, value) in Ports.suspicious) {
            assertTrue("port $port has no reason", value.second.isNotBlank())
            assertTrue("port $port has a non-positive score", value.first > 0)
        }
    }

    @Test
    fun `internet facing only set matches the desktop rule`() {
        for (port in listOf(445, 3389, 135, 139, 5900)) {
            assertTrue("port $port should be internet-facing only", Ports.isInternetFacingOnly(port))
        }
        assertFalse(Ports.isInternetFacingOnly(4444))
    }

    @Test
    fun `known services resolve and unknown ones do not`() {
        assertEquals("HTTPS", Ports.serviceName(443))
        assertEquals("TELNET", Ports.serviceName(23))
        assertNull(Ports.serviceName(47111))
        assertEquals("4444 - Metasploit/Meterpreter default port", Ports.threatNote(4444))
        assertNull(Ports.threatNote(443))
    }
}

class ProbeParsingTest {

    @Test
    fun `end of life signatures are matched on the desktop list`() {
        assertTrue(BannerProbe.matchesEndOfLife("Apache/2.2.15 (CentOS)"))
        assertTrue(BannerProbe.matchesEndOfLife("nginx/1.4.6"))
        assertTrue(BannerProbe.matchesEndOfLife("Microsoft-IIS/7.5"))
        // A signature ending in a dot is already unambiguous, so 1.3.x must still match.
        assertTrue(BannerProbe.matchesEndOfLife("Apache/1.3.41 (Unix)"))
        // A letter suffix is a patch level, not a new minor version.
        assertTrue(BannerProbe.matchesEndOfLife("OpenSSL/1.0.1e-fips"))
        // Substring matching alone would accuse current software of being end of life.
        assertFalse(BannerProbe.matchesEndOfLife("nginx/1.25.3"))
        assertFalse(BannerProbe.matchesEndOfLife("nginx/1.24.0"))
        assertFalse(BannerProbe.matchesEndOfLife("PHP/8.3.1"))
        // The trade-off for that rule: the desktop's "lighttpd/1.4.2" signature no longer
        // reaches 1.4.25. Missing an old server is preferable to accusing a current one.
        assertFalse(BannerProbe.matchesEndOfLife("lighttpd/1.4.25"))
        assertFalse(BannerProbe.matchesEndOfLife(""))
    }

    @Test
    fun `iso8601 timestamps survive timezones and fractional seconds`() {
        assertEquals(1_700_000_000L, parseIso8601("2023-11-14T22:13:20+00:00"))
        assertEquals(1_700_000_000L, parseIso8601("2023-11-14T22:13:20Z"))
        assertEquals(1_700_000_000L, parseIso8601("2023-11-14T22:13:20.123Z"))
        assertEquals(0L, parseIso8601(null))
        assertEquals(0L, parseIso8601("not a date"))
    }
}

class InputParsingTest {

    @Test
    fun `host and port are split only when the suffix is a valid port`() {
        assertEquals("93.184.216.34" to 8443, dev.netlurker.android.ui.parseInput("93.184.216.34:8443"))
        assertEquals("example.com" to 443, dev.netlurker.android.ui.parseInput(" example.com:443 "))
        assertEquals("example.com" to null, dev.netlurker.android.ui.parseInput("example.com"))
        // 99999 is not a port, so nothing is split off: rewriting it to "example.com"
        // would quietly investigate a target the user never typed.
        assertEquals("example.com:99999" to null, dev.netlurker.android.ui.parseInput("example.com:99999"))
        assertEquals("example.com:x" to null, dev.netlurker.android.ui.parseInput("example.com:x"))
        // ":0" is not a usable port, so the whole string stays the host and no port is set.
        assertEquals("93.184.216.34:0" to null, dev.netlurker.android.ui.parseInput("93.184.216.34:0"))
    }
}
