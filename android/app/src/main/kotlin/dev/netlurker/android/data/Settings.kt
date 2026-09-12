package dev.netlurker.android.data

import android.content.Context
import android.content.SharedPreferences

/**
 * Every user-facing switch. Defaults follow the desktop build: geolocation and threat
 * lookups on, anything that needs a personal API key off, and the public-IP check off
 * because it is the one lookup that reveals the device's own address to a third party.
 */
class Settings(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences("netlurker", Context.MODE_PRIVATE)

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

    /** "" means "follow the system language". */
    var languageOverride: String
        get() = prefs.getString(KEY_LANGUAGE, "").orEmpty()
        set(value) = prefs.edit().putString(KEY_LANGUAGE, value).apply()

    var abuseIpDbKey: String
        get() = prefs.getString(KEY_ABUSE_KEY, "").orEmpty()
        set(value) = prefs.edit().putString(KEY_ABUSE_KEY, value.trim()).apply()

    var virusTotalKey: String
        get() = prefs.getString(KEY_VT_KEY, "").orEmpty()
        set(value) = prefs.edit().putString(KEY_VT_KEY, value.trim()).apply()

    var aiEndpoint: String
        get() = prefs.getString(KEY_AI_ENDPOINT, DEFAULT_AI_ENDPOINT).orEmpty()
        set(value) = prefs.edit().putString(KEY_AI_ENDPOINT, value.trim()).apply()

    var aiModel: String
        get() = prefs.getString(KEY_AI_MODEL, DEFAULT_AI_MODEL).orEmpty()
        set(value) = prefs.edit().putString(KEY_AI_MODEL, value.trim()).apply()

    var aiApiKey: String
        get() = prefs.getString(KEY_AI_KEY, "").orEmpty()
        set(value) = prefs.edit().putString(KEY_AI_KEY, value.trim()).apply()

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
