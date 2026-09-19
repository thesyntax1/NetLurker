package dev.netlurker.android

import dev.netlurker.android.core.Export
import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.core.Ip
import dev.netlurker.android.core.Target
import dev.netlurker.android.data.CacheSchema
import dev.netlurker.android.core.RiskEngine
import dev.netlurker.android.core.IntelResult
import dev.netlurker.android.core.ThreatInfo
import dev.netlurker.android.data.DiskCache
import dev.netlurker.android.data.TrafficSource
import dev.netlurker.android.data.SessionHistory
import dev.netlurker.android.intel.AbuseIpDb
import dev.netlurker.android.intel.PassiveDns
import dev.netlurker.android.intel.VirusTotal
import org.junit.Assert.*
import org.junit.Test

class ProviderEvidenceTest {
    private fun rejected(block: () -> Any?) { assertTrue("Invalid evidence was accepted", runCatching(block).isFailure) }

    @Test fun abuseRequiresMatchingAddressAndTypedWholeNumbers() {
        fun body(score: String = "0", ip: String = "8.8.8.8", reports: String = "0") =
            """{"data":{"ipAddress":"$ip","abuseConfidenceScore":$score,"totalReports":$reports,"isTor":false}}"""
        assertEquals(0, AbuseIpDb.parse(body(), "8.8.8.8").abuseScore)
        for (score in listOf("\"0\"", "null", "1.5", "-1", "101", "true")) rejected { AbuseIpDb.parse(body(score), "8.8.8.8") }
        rejected { AbuseIpDb.parse(body(ip = "8.8.4.4"), "8.8.8.8") }
        rejected { AbuseIpDb.parse(body(reports = "-1"), "8.8.8.8") }
        rejected { AbuseIpDb.parse(body() + "garbage", "8.8.8.8") }
        rejected { AbuseIpDb.parse("""{"data":{"reportedAddress":[]}}""", "8.8.8.8") }
    }

    @Test fun vtCountsOnlyEngineVerdictsAndRejectsMissingOrOverflowedCounts() {
        fun body(stats: String, id: String = "8.8.8.8") = """{"data":{"id":"$id","type":"ip_address","attributes":{"reputation":-2,"last_analysis_stats":$stats}}}"""
        val stats = """{"malicious":2,"suspicious":1,"harmless":3,"undetected":4,"timeout":100}"""
        val result = VirusTotal.parse(body(stats), "8.8.8.8")
        assertEquals(10, result.total)
        assertEquals(-2, result.reputation)
        rejected { VirusTotal.parse(body(stats, "8.8.4.4"), "8.8.8.8") }
        for (value in listOf("{}", """{"malicious":0,"suspicious":0,"harmless":0,"undetected":0}""", stats.replace("2", "-1"), stats.replace("2", "2147483647"), stats.replace("2", "2.5")))
            rejected { VirusTotal.parse(body(value), "8.8.8.8") }
    }

    @Test fun pdnsDistinguishesValidZeroFromErrorObjectsAndSupportsNdjson() {
        assertEquals(0, PassiveDns.parse("[]", "8.8.8.8").records)
        for (body in listOf("", "{}", """{"error":"unauthorized"}""", "[{},null]", "[]garbage"))
            rejected { PassiveDns.parse(body, "8.8.8.8") }
        val record = """{"rrname":"dns.google","rrtype":"A","rdata":"8.8.8.8","time_last":1700000000}"""
        val result = PassiveDns.parse(record + "\n" + record, "8.8.8.8")
        assertEquals(2, result.records)
        assertEquals("dns.google", result.names)
        assertEquals(1700000000L, result.newest)
        rejected { PassiveDns.parse(record, "8.8.4.4") }
    }

    @Test fun spreadsheetCellsCannotEvaluateProviderOrApplicationText() {
        assertEquals("'=1+1", Export.escapeCsv("=1+1"))
        assertEquals("' \t@SUM(1)", Export.escapeCsv(" \t@SUM(1)"))
        assertEquals("\"ACME;\"\"Co\"\"\"", Export.escapeCsv("ACME;\"Co\""))
        assertEquals("normal text", Export.escapeCsv("normal text"))
    }

    @Test fun resolvingAHostnameNeverChangesItsTargetKey() {
        val original = Target(input = "Example.com", port = 443)
        val resolved = original.copy(ip = "8.8.8.8")
        assertEquals(original.key, resolved.key)
        assertTrue(original.acceptsResultOf(resolved))
        assertNotEquals(original.key, Target(input = "other.example", port = 443).key)
        assertFalse(Target(input = "Example.com", port = 443).acceptsResultOf(resolved))
        assertEquals(original.key, Target(input = "example.COM", port = 443).key)
    }

    @Test fun expandedAndMappedIpv6CannotBypassNonPublicClassification() {
        for (ip in listOf("0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:0", "febf::1", "::ffff:c0a8:101", "::ffff:127.0.0.1", "fc00::1"))
            assertFalse(ip, Ip.isPublic(ip))
        assertTrue(Ip.isPublic("2606:4700:4700::1111"))
        assertTrue(Ip.sameAddress("::ffff:808:808", "8.8.8.8"))
        assertFalse(Ip.sameAddress("example.com", "8.8.8.8"))
    }

    @Test fun cacheSchemasRejectEmptyObjectsAndCoercedFields() {
        for (kind in listOf("geo", "rdap", "cert", "banner")) rejected { CacheSchema.decode("{}", kind) }
        val row = """{"name":"Network","org":"Example","abuse":"","cidr":"8.8.8.0/24","registered":1700000000}"""
        assertEquals("Network", CacheSchema.decode(row, "rdap").getString("name"))
        rejected { CacheSchema.decode(row.replace("1700000000", "\"1700000000\""), "rdap") }
        rejected { CacheSchema.decode(row + "garbage", "rdap") }
    }

    @Test fun futureRegistrationIsNeitherYoungNorEstablishedEvidence() {
        val target = Target("8.8.8.8", ip = "8.8.8.8", threat = IntelResult.ok(
            ThreatInfo(rdapOrg = "Example", rdapRegisteredEpochSec = 2000000000L)))
        val verdict = RiskEngine.evaluate(target, 1700000000L)
        assertFalse(verdict.reasons.any { it.key == "risk.registration_young" })
        assertFalse(verdict.mitigations.any { it.key == "risk.mit_rdap_known_org" })
    }

    @Test fun futureDatedAndExpiredCacheEntriesAreNotFresh() {
        assertFalse(DiskCache.Entry(1001, "x").isFresh(1000, 100))
        assertFalse(DiskCache.Entry(0, "x").isFresh(1000, 2000))
        assertFalse(DiskCache.Entry(900, "x").isFresh(1000, 100))
        assertTrue(DiskCache.Entry(901, "x").isFresh(1000, 100))
    }

    @Test fun sharedUidBytesCannotBeAttributedToIndividualPackages() {
        var counter = 1000L
        val source = TrafficSource({ 0L }, { counter }, { counter }, { counter }, { counter })
        val a = AppTraffic(1001, "one.app", "Same label", 0, 0)
        val b = AppTraffic(1001, "two.app", "Same label", 0, 0)
        source.applyRates(listOf(a, b), 1000)
        counter += 5000
        val rows = source.applyRates(listOf(a, b), 2000)
        assertTrue(rows.all { !it.supported && !it.active && it.rateIn == 0.0 })
        assertEquals(0.0, source.applyRates(listOf(a), 3000).single().rateIn, 0.0)
    }

    @Test fun historyReseedsAfterAnUnavailableAppSample() {
        val history = SessionHistory()
        history.record(0, 0, mapOf("one.app" to 1000L), 1000)
        history.record(0, 0, emptyMap(), 1000)
        history.record(0, 0, mapOf("one.app" to 100000L), 1000)
        assertTrue(history.appRateWindow("one.app").isEmpty())
        history.record(0, 0, mapOf("one.app" to 101000L), 1000)
        assertEquals(1000.0, history.appRateWindow("one.app").last().outBytesPerSec, 0.0)
    }
}
