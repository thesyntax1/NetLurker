package dev.netlurker.android.data

import android.content.Context
import android.content.SharedPreferences

/**
 * Every user-facing switch. Defaults follow the desktop build: geolocation and threat
 * lookups on, anything that needs a personal API key off, and the public-IP check off
 * because it is the one lookup that reveals the device's own address to a third party.
 */
class Settings internal constructor(private val prefs: SharedPreferences) {
    constructor(context: Context) : this(
        context.applicationContext.getSharedPreferences("netlurker", Context.MODE_PRIVATE)
    )

    var geoEnabled: Boolean
        get() = prefs.getBoolean(KEY_GEO, true)
        set(value) = prefs.edit().putBoolean(KEY_GEO, value).apply()

    var threatEnabled: Boolean
        get() = prefs.getBoolean(KEY_THREAT, true)
        set(value) = prefs.edit().putBoolean(KEY_THREAT, value).apply()

    var rdapEnabled: Boolean
        get() = prefs.getBoolean(KEY_RDAP, true)
        set(value) = prefs.edit().putBoolean(KEY_RDAP, value).apply()

    var vtEnabled: Boolean
        get() = prefs.getBoolean(KEY_VT, false)
        set(value) = prefs.edit().putBoolean(KEY_VT, value).apply()

    var tlsEnabled: Boolean
        get() = prefs.getBoolean(KEY_TLS, true)
        set(value) = prefs.edit().putBoolean(KEY_TLS, value).apply()

    var bannerEnabled: Boolean
        get() = prefs.getBoolean(KEY_BANNER, true)
        set(value) = prefs.edit().putBoolean(KEY_BANNER, value).apply()

    var publicIpEnabled: Boolean
        get() = prefs.getBoolean(KEY_PUBLIC_IP, false)
        set(value) = prefs.edit().putBoolean(KEY_PUBLIC_IP, value).apply()

    var anomalyNotifications: Boolean
        get() = prefs.getBoolean(KEY_NOTIFY, true)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFY, value).apply()

    /** Milliseconds between traffic polls. */
    var refreshMs: Long
        get() = prefs.getLong(KEY_REFRESH, 2_000L).coerceIn(1_000L, 30_000L)
        set(value) = prefs.edit().putLong(KEY_REFRESH, value.coerceIn(1_000L, 30_000L)).apply()

    /** Fresh installs start in English; an explicit legacy "" still follows the system. */
    var languageOverride: String
        get() = prefs.getString(KEY_LANGUAGE, "en") ?: "en"
        set(value) = prefs.edit().putString(KEY_LANGUAGE, value).apply()

    /** Keep the UI in sync without restarting the activity or losing the current tab. */
    fun observeLanguage(onChange: () -> Unit): () -> Unit {
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == KEY_LANGUAGE || key == null) onChange()
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        return { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    var abuseIpDbKey: String
        get() = safeHeaderValue(prefs.getString(KEY_ABUSE_KEY, "").orEmpty())
        set(value) = prefs.edit().putString(KEY_ABUSE_KEY, value.trim()).apply()

    var virusTotalKey: String
        get() = safeHeaderValue(prefs.getString(KEY_VT_KEY, "").orEmpty())
        set(value) = prefs.edit().putString(KEY_VT_KEY, value.trim()).apply()

    var aiEndpoint: String
        get() = prefs.getString(KEY_AI_ENDPOINT, DEFAULT_AI_ENDPOINT).orEmpty()
        set(value) = prefs.edit().putString(KEY_AI_ENDPOINT, value.trim()).apply()

    var aiModel: String
        get() = prefs.getString(KEY_AI_MODEL, DEFAULT_AI_MODEL).orEmpty()
        set(value) = prefs.edit().putString(KEY_AI_MODEL, value.trim()).apply()

    var aiApiKey: String
        get() = safeHeaderValue(prefs.getString(KEY_AI_KEY, "").orEmpty())
        set(value) = prefs.edit().putString(KEY_AI_KEY, value.trim()).apply()

    /**
     * Older installs may contain values written before header validation existed. Treat those
     * values as absent at the read boundary too, so they can never reach an HTTP header before
     * the user opens and saves Settings.
     */
    private fun safeHeaderValue(value: String): String =
        value.takeUnless { it.any { character -> character < ' ' || character == '\u007f' } }.orEmpty()

    fun snapshot() = SettingsValues(
        geoEnabled, threatEnabled, rdapEnabled, vtEnabled, tlsEnabled, bannerEnabled,
        publicIpEnabled, anomalyNotifications, refreshMs, languageOverride,
        abuseIpDbKey, virusTotalKey, aiEndpoint, aiModel, aiApiKey
    )

    /** Single editor transaction; call on IO, and do not dismiss the editor on failure. */
    fun save(values: SettingsValues): Boolean {
        val next = values.normalized()
        if (next.validationError() != null) return false
        val previous = snapshot()
        val saved = runCatching { writeValues(next).commit() }.getOrDefault(false)
        // SharedPreferences updates its in-memory map even if its disk commit fails.
        if (!saved) writeValues(previous).apply()
        return saved
    }

    private fun writeValues(v: SettingsValues): SharedPreferences.Editor = prefs.edit()
        .putBoolean(KEY_GEO, v.geo).putBoolean(KEY_THREAT, v.threat)
        .putBoolean(KEY_RDAP, v.rdap).putBoolean(KEY_VT, v.vt)
        .putBoolean(KEY_TLS, v.tls).putBoolean(KEY_BANNER, v.banner)
        .putBoolean(KEY_PUBLIC_IP, v.publicIp).putBoolean(KEY_NOTIFY, v.notify)
        .putLong(KEY_REFRESH, v.refreshMs).putString(KEY_LANGUAGE, v.language)
        .putString(KEY_ABUSE_KEY, v.abuseKey).putString(KEY_VT_KEY, v.vtKey)
        .putString(KEY_AI_ENDPOINT, v.aiEndpoint).putString(KEY_AI_MODEL, v.aiModel)
        .putString(KEY_AI_KEY, v.aiKey)

    fun aiConfigured(): Boolean =
        aiApiKey.isNotBlank() && aiEndpoint.isNotBlank() && aiModel.isNotBlank()

    fun clearAll() = prefs.edit().clear().apply()

    companion object {
        const val DEFAULT_AI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
        const val DEFAULT_AI_MODEL = "gpt-4o-mini"

        private const val KEY_GEO = "geo_enabled"
        private const val KEY_THREAT = "threat_enabled"
        private const val KEY_RDAP = "rdap_enabled"
        private const val KEY_VT = "vt_enabled"
        private const val KEY_TLS = "tls_enabled"
        private const val KEY_BANNER = "banner_enabled"
        private const val KEY_PUBLIC_IP = "public_ip_enabled"
        private const val KEY_NOTIFY = "notify_anomaly"
        private const val KEY_REFRESH = "refresh_ms"
        private const val KEY_LANGUAGE = "language_override"
        private const val KEY_ABUSE_KEY = "abuseipdb_key"
        private const val KEY_VT_KEY = "virustotal_key"
        private const val KEY_AI_ENDPOINT = "ai_endpoint"
        private const val KEY_AI_MODEL = "ai_model"
        private const val KEY_AI_KEY = "ai_key"
    }
}
