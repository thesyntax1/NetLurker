package dev.netlurker.android

import android.content.SharedPreferences
import dev.netlurker.android.data.Settings
import dev.netlurker.android.data.SettingsValues
import org.junit.Assert.*
import org.junit.Test

class SettingsTest {
    @Test fun draftEditsDoNotChangeTheOriginal() {
        val original = SettingsValues()
        val draft = original.copy(language = "tr", aiKey = "test-only-key", publicIp = true)
        assertEquals("en", original.language)
        assertEquals("", original.aiKey)
        assertFalse(original.publicIp)
        assertTrue(draft.publicIp)
    }

    @Test fun normalizationUsesTheEntireSupportedRefreshRange() {
        assertEquals(1000L, SettingsValues(refreshMs = -1).normalized().refreshMs)
        assertEquals(30000L, SettingsValues(refreshMs = Long.MAX_VALUE).normalized().refreshMs)
        assertEquals(25000L, SettingsValues(refreshMs = 25000).normalized().refreshMs)
        assertEquals("key", SettingsValues(aiKey = " key \n").normalized().aiKey)
        assertEquals("en", SettingsValues(language = "invalid").normalized().language)
    }

    @Test fun onlyLocalAnalysisMayOmitEndpointAndModel() {
        assertNull(SettingsValues(aiEndpoint = "", aiModel = "").validationError())
        assertEquals("settings.error.model", SettingsValues(aiKey = "test", aiModel = " ").validationError())
        assertFalse(SettingsValues().aiConfigured())
        assertTrue(SettingsValues(aiKey = "test").aiConfigured())
    }

    @Test fun remoteKeysRequireAnUnambiguousHttpsEndpoint() {
        for (url in listOf("http://example.com", "file:///tmp/key", "https://", "https://u:p@example.com", "https://example.com/#x", "https://example.com:0", "https://example.com:65536", "not a URL"))
            assertEquals(url, "settings.error.endpoint", SettingsValues(aiKey = "test", aiEndpoint = url).validationError())
        for (url in listOf("https://example.com/v1?version=2", "HTTPS://example.com", "https://[::1]:8443/v1"))
            assertNull(url, SettingsValues(aiKey = "test", aiEndpoint = url).validationError())
    }

    @Test fun successfulSaveIsOneTransactionAndSurvivesANewSettingsInstance() {
        val prefs = MemoryPreferences()
        val settings = Settings(prefs)
        val next = settings.snapshot().copy(language = "tr", refreshMs = 30000, vt = true, vtKey = " test ")
        assertTrue(settings.save(next))
        assertEquals(1, prefs.commits)
        assertEquals(next.normalized(), Settings(prefs).snapshot())
    }

    @Test fun failedCommitRestoresMemoryInsteadOfApplyingUnsavedLanguageAndKeys() {
        val prefs = MemoryPreferences()
        val settings = Settings(prefs)
        val before = settings.snapshot()
        prefs.commitSucceeds = false
        assertFalse(settings.save(before.copy(language = "tr", aiKey = "test-only-key")))
        assertEquals(before, settings.snapshot())
        assertEquals(1, prefs.commits)
    }

    @Test fun invalidSaveDoesNotTouchPreferences() {
        val prefs = MemoryPreferences()
        assertFalse(Settings(prefs).save(SettingsValues(aiKey = "test", aiEndpoint = "http://remote.example")))
        assertEquals(0, prefs.commits)
        assertTrue(prefs.getAll().isEmpty())
    }

    /** Models Android's important behavior: commit mutates memory even on disk failure. */
    private class MemoryPreferences : SharedPreferences {
        private val values = mutableMapOf<String, Any?>()
        var commitSucceeds = true
        var commits = 0
        override fun getAll(): Map<String, *> = values.toMap()
        override fun contains(key: String?) = values.containsKey(key)
        override fun getString(key: String?, defValue: String?) = values[key] as? String ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean) = values[key] as? Boolean ?: defValue
        override fun getLong(key: String?, defValue: Long) = values[key] as? Long ?: defValue
        override fun getInt(key: String?, defValue: Int) = values[key] as? Int ?: defValue
        override fun getFloat(key: String?, defValue: Float) = values[key] as? Float ?: defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = values[key] as? MutableSet<String> ?: defValues
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            val pending = mutableMapOf<String, Any?>()
            var clear = false
            fun put(key: String?, value: Any?): SharedPreferences.Editor { pending[requireNotNull(key)] = value; return this }
            override fun putString(key: String?, value: String?) = put(key, value)
            override fun putStringSet(key: String?, values: MutableSet<String>?) = put(key, values)
            override fun putInt(key: String?, value: Int) = put(key, value)
            override fun putLong(key: String?, value: Long) = put(key, value)
            override fun putFloat(key: String?, value: Float) = put(key, value)
            override fun putBoolean(key: String?, value: Boolean) = put(key, value)
            override fun remove(key: String?) = put(key, null)
            override fun clear(): SharedPreferences.Editor { clear = true; return this }
            override fun apply() {
                if (clear) values.clear()
                pending.forEach { (k, v) -> if (v == null) values.remove(k) else values[k] = v }
            }
            override fun commit(): Boolean { commits++; apply(); return commitSucceeds }
        }
    }
}
