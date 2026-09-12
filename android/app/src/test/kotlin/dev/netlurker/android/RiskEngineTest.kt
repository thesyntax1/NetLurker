package dev.netlurker.android

import dev.netlurker.android.core.BannerInfo
import dev.netlurker.android.core.CertInfo
import dev.netlurker.android.core.GeoInfo
import dev.netlurker.android.core.IntelResult
import dev.netlurker.android.core.IntelStatus
import dev.netlurker.android.core.ReasonKeys
import dev.netlurker.android.core.RiskEngine
import dev.netlurker.android.core.RiskLevel
import dev.netlurker.android.core.Target
import dev.netlurker.android.core.ThreatInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The scoring model is the part of NetLurker that makes a judgement, so it is the part
 * that must be pinned by tests: every rule ported from the desktop build's EvaluateRisk()
 * is asserted here, including the ones that must NOT fire.
 */
class RiskEngineTest {

    private val now = 1_700_000_000L

    private fun target(
        ip: String = "93.184.216.34",
        port: Int? = 443,
        geo: IntelResult<GeoInfo> = IntelResult.idle(),
        threat: IntelResult<ThreatInfo> = IntelResult.idle(),
        cert: IntelResult<CertInfo> = IntelResult.idle(),
        banner: IntelResult<BannerInfo> = IntelResult.idle(),
        reverse: IntelResult<String> = IntelResult.idle()
    ) = Target(
        input = ip,
        ip = ip,
        port = port,
        geo = geo,
        threat = threat,
        cert = cert,
        banner = banner,
        reverseDns = reverse
    )

    private fun keys(target: Target) = RiskEngine.evaluate(target, now).reasons.map { it.key }

    @Test
    fun `clean public destination with answering sources scores zero`() {
        val verdict = RiskEngine.evaluate(
            target(
                geo = IntelResult.ok(GeoInfo(country = "United States", org = "Example Inc")),
                threat = IntelResult.ok(ThreatInfo(abuseScore = 0, sourcesAnswered = listOf("dnsbl(5)")))
            ),
            now
        )
        assertEquals(0, verdict.score)
        assertEquals(RiskLevel.SAFE, verdict.level)
        assertTrue(verdict.reasons.isEmpty())
        assertTrue(
            verdict.mitigations.any { it.key == ReasonKeys.MIT_CLEAN_ALL_SOURCES }
        )
    }

    @Test
    fun `proxy flag adds thirty points`() {
        val verdict = RiskEngine.evaluate(
            target(geo = IntelResult.ok(GeoInfo(proxy = true))),
            now
        )
        assertTrue(verdict.reasons.any { it.key == ReasonKeys.PROXY_OR_VPN && it.points == 30 })
    }

    @Test
    fun `blacklisted address adds thirty points and carries the zone list`() {
        val verdict = RiskEngine.evaluate(
            target(
                threat = IntelResult.ok(
                    ThreatInfo(dnsblHits = listOf("SBL/XBL", "Barracuda"), sourcesAnswered = listOf("dnsbl(5)"))
                )
            ),
            now
        )
        val reason = verdict.reasons.first { it.key == ReasonKeys.DNSBL_LISTED }
        assertEquals(30, reason.points)
        assertEquals(listOf("SBL/XBL", "Barracuda"), reason.args)
    }

    @Test
    fun `abuse score bands match the desktop thresholds`() {
        fun scoreFor(value: Int) = RiskEngine.evaluate(
            target(threat = IntelResult.ok(ThreatInfo(abuseScore = value))), now
        ).reasons.filter { it.key.startsWith("risk.abuse") }.sumOf { it.points }

        assertEquals(0, scoreFor(24))
        assertEquals(8, scoreFor(25))
        assertEquals(8, scoreFor(49))
        assertEquals(20, scoreFor(50))
        assertEquals(20, scoreFor(79))
        assertEquals(35, scoreFor(80))
    }

    @Test
    fun `expired certificate adds eighteen and self-signed on a datacenter adds twenty-two`() {
        val expired = RiskEngine.evaluate(
            target(cert = IntelResult.ok(CertInfo(expired = true))), now
        )
        assertTrue(expired.reasons.any { it.key == ReasonKeys.CERT_EXPIRED && it.points == 18 })

        val selfSigned = RiskEngine.evaluate(
            target(
                geo = IntelResult.ok(GeoInfo(hosting = true)),
                cert = IntelResult.ok(CertInfo(selfSigned = true)),
                reverse = IntelResult.failed("no PTR record")
            ),
            now
        )
        assertTrue(
            selfSigned.reasons.any {
                it.key == ReasonKeys.CERT_SELF_SIGNED_DATACENTER && it.points == 22
            }
        )
    }

    @Test
    fun `datacenter without reverse dns is only flagged once reverse dns has answered`() {
        // Reverse DNS still in flight must not be read as "there is none".
        val pending = RiskEngine.evaluate(
            target(
                geo = IntelResult.ok(GeoInfo(hosting = true)),
                reverse = IntelResult.pending()
            ),
            now
        )
        assertFalse(pending.reasons.any { it.key == ReasonKeys.DATACENTER_NO_RDNS })

        val answered = RiskEngine.evaluate(
            target(
                geo = IntelResult.ok(GeoInfo(hosting = true)),
                reverse = IntelResult.failed("no PTR record")
            ),
            now
        )
        assertTrue(answered.reasons.any { it.key == ReasonKeys.DATACENTER_NO_RDNS })
    }

    @Test
    fun `suspicious port scores the table value and unknown ports score by range`() {
        val backdoor = RiskEngine.evaluate(target(port = 4444), now)
        assertTrue(backdoor.reasons.any { it.key == ReasonKeys.PORT_SUSPICIOUS && it.points == 75 })

        val unknownHigh = RiskEngine.evaluate(target(port = 47111), now)
        assertTrue(
            unknownHigh.reasons.any {
                it.key == ReasonKeys.PORT_UNKNOWN_SERVICE && it.points == 10
            }
        )

        val unknownLow = RiskEngine.evaluate(target(port = 999), now)
        assertTrue(
            unknownLow.reasons.any {
                it.key == ReasonKeys.PORT_RARE_PRIVILEGED && it.points == 15
            }
        )

        val known = RiskEngine.evaluate(target(port = 22), now)
        assertFalse(known.reasons.any { it.key == ReasonKeys.PORT_UNKNOWN_SERVICE })
    }

    @Test
    fun `private addresses are mitigated and never scored as internet destinations`() {
        val verdict = RiskEngine.evaluate(target(ip = "192.168.1.10", port = 445), now)
        assertTrue(verdict.mitigations.any { it.key == ReasonKeys.MIT_PRIVATE_NETWORK })
        // 445 is only alarming when internet facing; a LAN SMB share must not score 45.
        assertFalse(verdict.reasons.any { it.key == ReasonKeys.PORT_SUSPICIOUS })
    }

    @Test
    fun `common web ports are mitigated by five`() {
        val verdict = RiskEngine.evaluate(target(port = 443), now)
        assertTrue(verdict.mitigations.any { it.key == ReasonKeys.MIT_COMMON_WEB_PORT })
    }

    @Test
    fun `pending sources are reported as incomplete evidence rather than clean`() {
        val verdict = RiskEngine.evaluate(
            target(
                geo = IntelResult.pending(),
                threat = IntelResult.pending(),
                cert = IntelResult.pending(),
                banner = IntelResult.pending()
            ),
            now
        )
        assertFalse(verdict.mitigations.any { it.key == ReasonKeys.MIT_CLEAN_ALL_SOURCES })
        val incomplete = verdict.mitigations.first { it.key == ReasonKeys.MIT_EVIDENCE_INCOMPLETE }
        assertEquals("geo, threat, cert, banner", incomplete.args.single())
    }

    @Test
    fun `score is clamped and levels follow the desktop thresholds`() {
        val everything = RiskEngine.evaluate(
            target(
                port = 31337,
                geo = IntelResult.ok(GeoInfo(proxy = true, hosting = true)),
                threat = IntelResult.ok(
                    ThreatInfo(
                        abuseScore = 100,
                        totalReports = 40,
                        dnsblHits = listOf("Sorbs"),
                        isTor = true,
                        vtMalicious = 30,
                        vtTotal = 70
                    )
                ),
                cert = IntelResult.ok(
                    CertInfo(selfSigned = true, expired = true, notYetValid = true, nameMismatch = true)
                ),
                banner = IntelResult.ok(BannerInfo(server = "Apache/2.2.3", endOfLife = true)),
                reverse = IntelResult.failed("no PTR record")
            ),
            now
        )
        assertEquals(100, everything.score)
        assertEquals(RiskLevel.DANGER, everything.level)
        assertTrue(everything.score >= 70)
    }

    @Test
    fun `level boundaries are exactly the desktop ones`() {
        assertEquals(RiskLevel.SAFE, levelOf(0))
        assertEquals(RiskLevel.SAFE, levelOf(19))
        assertEquals(RiskLevel.INFO, levelOf(20))
        assertEquals(RiskLevel.INFO, levelOf(44))
        assertEquals(RiskLevel.WARN, levelOf(45))
        assertEquals(RiskLevel.WARN, levelOf(69))
        assertEquals(RiskLevel.DANGER, levelOf(70))
        assertEquals(RiskLevel.DANGER, levelOf(100))
    }

    @Test
    fun `young registration is flagged and an established owner is a mitigation`() {
        val nowSeconds = now
        val young = RiskEngine.evaluate(
            target(
                threat = IntelResult.ok(
                    ThreatInfo(rdapRegisteredEpochSec = nowSeconds - 10 * 86_400, rdapOrg = "Shell Co")
                )
            ),
            nowSeconds
        )
        assertTrue(young.reasons.any { it.key == ReasonKeys.REGISTRATION_YOUNG })

        val established = RiskEngine.evaluate(
            target(
                threat = IntelResult.ok(
                    ThreatInfo(rdapRegisteredEpochSec = nowSeconds - 4_000 * 86_400, rdapOrg = "Old Corp")
                )
            ),
            nowSeconds
        )
        assertTrue(established.mitigations.any { it.key == ReasonKeys.MIT_RDAP_KNOWN_ORG })
    }

    @Test
    fun `disabled sources never produce a clean verdict`() {
        val verdict = RiskEngine.evaluate(
            target(
                geo = IntelResult.disabled("geolocation is turned off"),
                threat = IntelResult.disabled("threat lookups are turned off")
            ),
            now
        )
        // A source the user switched off is not evidence of safety, so the score stays 0
        // but the "all sources clean" mitigation must not be granted.
        assertEquals(0, verdict.score)
        assertFalse(verdict.mitigations.any { it.key == ReasonKeys.MIT_CLEAN_ALL_SOURCES })
        assertTrue(verdict.reasons.isEmpty())
    }

    @Test
    fun `smb on a public address is scored while the same port on a lan address is not`() {
        val lan = RiskEngine.evaluate(target(ip = "10.0.0.5", port = 445), now)
        assertFalse(lan.reasons.any { it.key == ReasonKeys.PORT_SUSPICIOUS })

        val internet = RiskEngine.evaluate(target(ip = "203.0.113.9", port = 445), now)
        assertTrue(
            internet.reasons.any { it.key == ReasonKeys.PORT_SUSPICIOUS && it.points == 45 }
        )
    }
}

/** Small helper so the threshold assertions read as assertions. */
private fun levelOf(score: Int): RiskLevel =
    dev.netlurker.android.core.Verdict.fromScore(score, emptyList()).level
