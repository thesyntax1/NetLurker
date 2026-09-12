package dev.netlurker.android.ai

import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.core.Format
import dev.netlurker.android.core.IntelStatus
import dev.netlurker.android.core.RiskLevel
import dev.netlurker.android.core.Target
import dev.netlurker.android.data.Settings
import dev.netlurker.android.intel.Http
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * AI-assisted investigation.
 *
 * Two honest modes, never blended:
 *
 *  - With an API key the evidence is sent to the configured OpenAI-compatible endpoint and
 *    the model's answer is returned verbatim, in the interface language.
 *  - Without a key the local rule engine writes the same six-section report from the same
 *    evidence and says in its first line that it is a local rule engine, not a model.
 *
 * The report structure matches the desktop build: VERDICT / CONFIDENCE / WHY / CONCERNS /
 * RECOMMENDATION / STEPS.
 */
class AiClient(private val settings: Settings) {

    data class Report(val text: String, val local: Boolean, val error: String? = null)

    /** Human-readable evidence block; also what the local engine reasons over. */
    fun buildEvidence(target: Target, appCount: Int, label: (String) -> String): String {
        val sb = StringBuilder()
        sb.append(label("ai.context_line")).append("\n\n")
        sb.append(label("ai.field.destination")).append(": ").append(target.display)
        if (target.port != null) sb.append(':').append(target.port)
        sb.append('\n')
        sb.append(label("ai.field.input")).append(": ").append(target.input).append('\n')
        target.reverseDns.let {
            sb.append(label("ai.field.reverse_dns")).append(": ").append(statusText(it.status, it.value, label)).append('\n')
        }
        target.geo.let { result ->
            sb.append(label("ai.field.geolocation")).append(": ")
            val geo = result.value
            if (geo == null) sb.append(statusText(result.status, null, label))
            else {
                sb.append(geo.location().ifBlank { "?" })
                if (geo.org.isNotBlank()) sb.append(" / ").append(geo.org)
                if (geo.asn.isNotBlank()) sb.append(" / ").append(geo.asn)
                if (geo.hosting) sb.append(" [datacenter]")
                if (geo.proxy) sb.append(" [proxy/VPN]")
                if (geo.mobile) sb.append(" [mobile]")
            }
            sb.append('\n')
        }
        target.threat.let { result ->
            val threat = result.value
            if (threat == null) {
                sb.append(label("ai.field.threat")).append(": ")
                    .append(statusText(result.status, null, label)).append('\n')
            } else {
                if (threat.abuseScore >= 0) {
                    sb.append(label("ai.field.abuseipdb")).append(": ")
                        .append(threat.abuseScore).append("/100, ")
                        .append(threat.totalReports).append(' ')
                        .append(label("ai.reports")).append('\n')
                }
                if (threat.dnsblHits.isNotEmpty()) {
                    sb.append(label("ai.field.dnsbl")).append(": ")
                        .append(threat.dnsblHits.joinToString(", ")).append('\n')
                }
                if (threat.passiveDnsRecords > 0) {
                    sb.append(label("ai.field.passive_dns")).append(": ")
                        .append(threat.passiveDnsRecords).append(' ')
                        .append(label("ai.records"))
                    if (threat.passiveDnsNames.isNotBlank()) {
                        sb.append(" (").append(threat.passiveDnsNames).append(')')
                    }
                    sb.append('\n')
                }
                if (threat.rdapOrg.isNotBlank()) {
                    sb.append(label("ai.field.ownership")).append(": ").append(threat.rdapOrg)
                    if (threat.rdapCidr.isNotBlank()) sb.append(" [").append(threat.rdapCidr).append(']')
                    if (threat.rdapAbuse.isNotBlank()) sb.append(" abuse: ").append(threat.rdapAbuse)
                    sb.append('\n')
                }
                if (threat.vtTotal > 0) {
                    sb.append(label("ai.field.virustotal")).append(": ")
                        .append(threat.vtMalicious).append('/').append(threat.vtTotal)
                        .append(", reputation ").append(threat.vtReputation).append('\n')
                }
                sb.append(label("ai.field.sources")).append(": ")
                    .append(threat.sourcesAnswered.joinToString(", ")).append('\n')
            }
        }
        target.cert.let { result ->
            val cert = result.value
            if (cert == null) {
                sb.append(label("ai.field.certificate")).append(": ")
                    .append(statusText(result.status, null, label)).append('\n')
            } else {
                sb.append(label("ai.field.certificate")).append(": ").append(cert.subject)
                sb.append(" | ").append(cert.issuer)
                if (cert.selfSigned) sb.append(" [self-signed]")
                if (cert.expired) sb.append(" [expired]")
                if (cert.notYetValid) sb.append(" [not yet valid]")
                if (cert.nameMismatch) sb.append(" [name mismatch]")
                sb.append(" | expires ").append(Format.epochIso(cert.notAfterEpochSec * 1000L))
                sb.append('\n')
            }
        }
        target.banner.let { result ->
            val banner = result.value
            if (banner != null) {
                sb.append(label("ai.field.banner")).append(": ")
                    .append(banner.server.ifBlank { banner.statusLine })
                if (banner.endOfLife) sb.append(" [end-of-life]")
                sb.append('\n')
            }
        }
        sb.append(label("ai.field.local_score")).append(": ")
            .append(target.verdict.score).append("/100 (")
            .append(target.verdict.level.name).append(")\n")
        if (target.verdict.reasons.isNotEmpty()) {
            sb.append(label("ai.field.local_reasons")).append(":\n")
            for (reason in target.verdict.reasons) {
                sb.append("  +").append(reason.points).append(" ").append(reason.key)
                if (reason.args.isNotEmpty()) sb.append(" [").append(reason.args.joinToString(", ")).append(']')
                sb.append('\n')
            }
        }
        sb.append(label("ai.field.installed_apps")).append(": ").append(appCount).append('\n')
        return sb.toString()
    }

    /** The prompt sent to the model, in the same shape as the desktop build's. */
    fun buildPrompt(
        target: Target,
        appCount: Int,
        languageName: String,
        label: (String) -> String
    ): String {
        val sb = StringBuilder()
        sb.append(label("ai.prompt.intro")).append("\n\n")
        sb.append(label("ai.prompt.structure")).append("\n\n")
        sb.append(buildEvidence(target, appCount, label))
        sb.append('\n').append(label("ai.prompt.questions")).append("\n")
        sb.append(label("ai.prompt.rules")).append('\n')
        sb.append(label("ai.prompt.language")).append(": ").append(languageName).append('.')
        return sb.toString()
    }

    suspend fun analyse(
        target: Target,
        appCount: Int,
        languageName: String,
        label: (String) -> String
    ): Report {
        val prompt = buildPrompt(target, appCount, languageName, label)
        if (!settings.aiConfigured()) {
            return Report(localHeuristic(target, label), local = true)
        }
        val body = JSONObject().apply {
            put("model", settings.aiModel)
            put("temperature", 0.2)
            put("messages", JSONArray().apply {
                put(JSONObject().apply {
                    put("role", "system")
                    put("content", label("ai.system_role"))
                })
                put(JSONObject().apply {
                    put("role", "user")
                    put("content", prompt)
                })
            })
        }.toString()

        val response = withContext(Dispatchers.IO) {
            Http.post(
                url = settings.aiEndpoint,
                body = body,
                contentType = "application/json",
                headers = mapOf("Authorization" to "Bearer ${settings.aiApiKey}"),
                timeoutMs = 45_000
            )
        }
        if (!response.ok) {
            // Fall back to the local engine but say so, rather than showing an empty panel.
            val fallback = localHeuristic(target, label)
            return Report(
                text = label("ai.remote_failed", "error" to (response.error ?: "unknown error")) +
                    "\n\n" + fallback,
                local = true,
                error = response.error
            )
        }
        val text = runCatching {
            JSONObject(response.body).getJSONArray("choices")
                .getJSONObject(0).getJSONObject("message").getString("content")
        }.getOrNull()
        return if (text.isNullOrBlank()) {
            Report(localHeuristic(target, label), local = true, error = "empty model response")
        } else {
            Report(text, local = false)
        }
    }

    /**
     * Same structure, produced by rules on the device. The first line always states that
     * this is the local engine so no one mistakes it for a model's judgement.
     */
    fun localHeuristic(target: Target, label: (String) -> String): String {
        val verdict = target.verdict
        val sb = StringBuilder()
        sb.append(label("ai.local_disclaimer")).append("\n\n")

        sb.append(label("ai.section.verdict")).append(": ")
        sb.append(
            when (verdict.level) {
                RiskLevel.DANGER -> label("ai.verdict.danger")
                RiskLevel.WARN -> label("ai.verdict.warn")
                RiskLevel.INFO -> label("ai.verdict.info")
                RiskLevel.SAFE -> label("ai.verdict.safe")
            }
        ).append('\n')

        // Confidence follows evidence coverage, not the score: a high score from a single
        // source is worth less than a low score confirmed by five.
        val answered = countAnswered(target)
        val confidence = when {
            verdict.reasons.isEmpty() && answered == 0 -> 10
            verdict.reasons.isEmpty() -> (30 + answered * 12).coerceAtMost(80)
            else -> (45 + answered * 10 + verdict.reasons.size * 4).coerceAtMost(95)
        }
        sb.append(label("ai.section.confidence")).append(": ").append(confidence).append("%\n")

        sb.append(label("ai.section.why")).append(":\n")
        if (verdict.reasons.isEmpty()) {
            sb.append("- ").append(label("ai.why.no_findings")).append('\n')
            if (answered > 0) {
                sb.append("- ").append(label("ai.why.sources_clean")).append(": ").append(answered).append('\n')
            } else {
                sb.append("- ").append(label("ai.why.no_sources")).append('\n')
            }
        } else {
            for (reason in verdict.reasons) {
                sb.append("- ").append(reason.key)
                if (reason.args.isNotEmpty()) sb.append(" [").append(reason.args.joinToString(", ")).append(']')
                sb.append(" (+").append(reason.points).append(")\n")
            }
        }

        sb.append(label("ai.section.concerns")).append(":\n")
        val concerns = concernsFor(target, label)
        if (concerns.isEmpty()) sb.append("- ").append(label("ai.concerns.none")).append('\n')
        else concerns.forEach { sb.append("- ").append(it).append('\n') }

        sb.append(label("ai.section.recommendation")).append(": ")
        sb.append(
            when (verdict.level) {
                RiskLevel.DANGER -> label("ai.recommend.block")
                RiskLevel.WARN -> label("ai.recommend.investigate")
                RiskLevel.INFO -> label("ai.recommend.monitor")
                RiskLevel.SAFE -> label("ai.recommend.none")
            }
        ).append('\n')

        sb.append(label("ai.section.steps")).append(":\n")
        stepsFor(target, label).forEachIndexed { index, step ->
            sb.append(index + 1).append(". ").append(step).append('\n')
        }
        return sb.toString()
    }

    private fun countAnswered(target: Target): Int = listOf(
        target.geo.status == IntelStatus.OK,
        target.threat.status == IntelStatus.OK,
        target.cert.status == IntelStatus.OK,
        target.banner.status == IntelStatus.OK,
        target.reverseDns.status == IntelStatus.OK
    ).count { it }

    private fun concernsFor(target: Target, label: (String) -> String): List<String> {
        val out = mutableListOf<String>()
        val pending = listOf(
            target.geo.status to "geolocation",
            target.threat.status to "threat",
            target.cert.status to "certificate",
            target.banner.status to "banner"
        ).filter { it.first == IntelStatus.PENDING }.map { it.second }
        if (pending.isNotEmpty()) {
            out += label("ai.concern.pending", "sources" to pending.joinToString(", "))
        }
        val disabled = listOf(
            target.geo.status to "geolocation",
            target.threat.status to "threat",
            target.cert.status to "certificate",
            target.banner.status to "banner"
        ).filter { it.first == IntelStatus.DISABLED }.map { it.second }
        if (disabled.isNotEmpty()) {
            out += label("ai.concern.disabled", "sources" to disabled.joinToString(", "))
        }
        if (target.threat.value?.abuseScore == -1 && target.threat.status == IntelStatus.OK) {
            out += label("ai.concern.no_abuse_key")
        }
        target.threat.value?.let { threat ->
            if (threat.vtTotal == 0 && threat.sourcesAnswered.isNotEmpty()) {
                out += label("ai.concern.no_virustotal")
            }
        }
        return out
    }

    private fun stepsFor(target: Target, label: (String) -> String): List<String> {
        val steps = mutableListOf<String>()
        val verdict = target.verdict
        if (verdict.score >= 45) steps += label("ai.step.block")
        steps += label("ai.step.virustotal")
        steps += label("ai.step.abuseipdb")
        if (target.threat.value?.rdapAbuse?.isNotBlank() == true) steps += label("ai.step.abuse_contact")
        if (target.cert.value?.expired == true) steps += label("ai.step.cert_expired")
        if (verdict.score < 20 && verdict.reasons.isEmpty()) steps += label("ai.step.keep_monitoring")
        steps += label("ai.step.recheck")
        return steps
    }

    private fun statusText(status: IntelStatus, value: String?, label: (String) -> String): String =
        when (status) {
            IntelStatus.OK -> value ?: "?"
            IntelStatus.PENDING -> label("status.querying")
            IntelStatus.FAILED -> label("status.failed")
            IntelStatus.OFFLINE -> label("status.offline")
            IntelStatus.DISABLED -> label("status.disabled")
            IntelStatus.UNAVAILABLE -> label("status.unavailable")
            IntelStatus.IDLE -> label("status.idle")
        }
}
