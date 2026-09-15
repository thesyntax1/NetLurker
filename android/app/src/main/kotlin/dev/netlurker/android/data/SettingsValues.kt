package dev.netlurker.android.data

import java.net.URI

/** Editable snapshot. Kept in memory, never put API keys into an activity saved-state Bundle. */
data class SettingsValues(
    val geo: Boolean = true,
    val threat: Boolean = true,
    val rdap: Boolean = true,
    val vt: Boolean = false,
    val tls: Boolean = true,
    val banner: Boolean = true,
    val publicIp: Boolean = false,
    val notify: Boolean = true,
    val refreshMs: Long = 2000L,
    val language: String = "en",
    val abuseKey: String = "",
    val vtKey: String = "",
    val aiEndpoint: String = "https://api.openai.com/v1/chat/completions",
    val aiModel: String = "gpt-4o-mini",
    val aiKey: String = ""
) {
    fun normalized() = copy(
        refreshMs = refreshMs.coerceIn(1000L, 30000L),
        language = language.takeIf { it in listOf("", "en", "tr", "es", "de", "fr", "ja", "zh", "pt") } ?: "en",
        abuseKey = abuseKey.trim(), vtKey = vtKey.trim(), aiKey = aiKey.trim(),
        aiEndpoint = aiEndpoint.trim(), aiModel = aiModel.trim()
    )

    fun aiConfigured(): Boolean = aiKey.isNotBlank() && aiEndpoint.isNotBlank() && aiModel.isNotBlank()

    fun validationError(): String? {
        if (aiKey.isBlank()) return null // local analysis does not require an endpoint/model
        val endpoint = runCatching { URI(aiEndpoint.trim()) }.getOrNull()
        if (endpoint == null || !endpoint.scheme.equals("https", ignoreCase = true) || endpoint.host.isNullOrBlank() ||
            endpoint.userInfo != null || endpoint.fragment != null || endpoint.port !in -1..65535 || endpoint.port == 0)
            return "settings.error.endpoint"
        if (aiModel.isBlank()) return "settings.error.model"
        return null
    }
}
