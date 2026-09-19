package dev.netlurker.android

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.netlurker.android.data.Settings
import dev.netlurker.android.ui.InfoRow
import dev.netlurker.android.ui.NetLurkerTheme
import dev.netlurker.android.ui.SettingsDialog
import dev.netlurker.android.ui.Strings
import dev.netlurker.android.ui.strings
import java.util.Locale
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LanguageAndLayoutTest {
    @get:Rule
    val compose = createComposeRule()
    private val application = ApplicationProvider.getApplicationContext<Application>()
    private val prefs = application.getSharedPreferences("netlurker", Context.MODE_PRIVATE)
    private val store = ViewModelStore()
    private var previousLanguage: String? = null

    @Before
    fun resetLanguage() {
        previousLanguage = prefs.getString("language_override", null)
        prefs.edit().remove("language_override").commit()
    }

    @After
    fun restoreLanguage() {
        store.clear()
        prefs.edit().putString("language_override", previousLanguage).commit()
    }

    private fun turkishDevice(): Context = application.createConfigurationContext(
        Configuration(application.resources.configuration).apply { setLocale(Locale.forLanguageTag("tr")) }
    )

    @Test
    fun freshInstallStartsInEnglishEvenOnTurkishDevice() {
        val context = turkishDevice()
        assertEquals("en", Settings(context).languageOverride)
        assertEquals("en", Strings(context).language)
        assertEquals("Language", Strings(context)("settings.language"))
        compose.setContent {
            CompositionLocalProvider(LocalContext provides context) {
                NetLurkerTheme { Text(strings()("settings.language")) }
            }
        }
        compose.onNodeWithText("Language").assertIsDisplayed()
    }

    @Test
    fun savedLanguagesSurviveNewSettingsAndStringInstances() {
        val context = turkishDevice()
        for ((code, _) in Strings.supportedLanguages) {
            Settings(context).languageOverride = code
            assertEquals(code, Settings(context).languageOverride)
            assertEquals(code, Strings(context).language)
            assertTrue(Strings(context).has("settings.language"))
        }
        Settings(context).languageOverride = "invalid-code"
        assertEquals("en", Strings(context).language)
        // Only an explicitly saved legacy system preference follows the device.
        Settings(context).languageOverride = ""
        assertEquals("tr", Strings(context).language)
    }

    @Test
    fun settingsPickerPreviewsButOnlySavePersists() {
        val model = MainViewModel(application)
        store.put("settings-test", model)
        var open by mutableStateOf(true)
        compose.setContent {
            NetLurkerTheme {
                if (open) SettingsDialog(model, onRequestLocation = {}, onDismiss = { open = false })
            }
        }
        compose.onNodeWithTag("settings-language").assertIsDisplayed().performClick()
        compose.onNodeWithText("Türkçe").performClick()
        compose.onNodeWithText("DİL").assertIsDisplayed()
        assertEquals("en", Settings(application).languageOverride)
        compose.onNodeWithTag("settings-save").assertIsDisplayed().performClick()
        compose.waitUntil(5000) { !open }
        assertEquals("tr", Settings(application).languageOverride)
        assertEquals("Dil", Strings(application)("settings.language"))
        compose.onNodeWithTag("settings-save").assertDoesNotExist()
    }

    @Test
    fun cancelDiscardsTheLanguageDraft() {
        val model = MainViewModel(application)
        store.put("cancel-test", model)
        var open by mutableStateOf(true)
        compose.setContent {
            NetLurkerTheme {
                if (open) SettingsDialog(model, onRequestLocation = {}, onDismiss = { open = false })
            }
        }
        compose.onNodeWithTag("settings-language").assertIsDisplayed().performClick()
        compose.onNodeWithText("Türkçe").performClick()
        compose.onNodeWithTag("settings-cancel").performClick()
        compose.onNodeWithTag("settings-save").assertDoesNotExist()
        assertEquals("en", Settings(application).languageOverride)
        assertEquals("Language", Strings(application)("settings.language"))
    }

    @Test
    fun languageSelectorIsVisibleOnOpeningCompactSettingsWithoutScrolling() {
        val model = MainViewModel(application)
        store.put("language-visible-test", model)
        compose.setContent {
            NetLurkerTheme {
                SettingsDialog(model, onRequestLocation = {}, onDismiss = {},
                    modifier = Modifier.width(320.dp).heightIn(max = 360.dp))
            }
        }
        compose.onNodeWithTag("settings-language").assertIsDisplayed().performClick()
        compose.onNodeWithText("Türkçe").assertIsDisplayed().performClick()
        compose.onNodeWithText("DİL").assertIsDisplayed()
        // Choosing previews the language; explicit Save/Cancel semantics stay intact.
        assertEquals("en", Settings(application).languageOverride)
        compose.onNodeWithTag("settings-save").assertIsDisplayed()
    }

    @Test
    fun compactSettingsKeepsBothActionsVisibleAtDoubleFontSizeEvenAfterScrolling() {
        val model = MainViewModel(application)
        store.put("compact-settings-test", model)
        compose.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, fontScale = 2f)) {
                NetLurkerTheme {
                    SettingsDialog(model, onRequestLocation = {}, onDismiss = {},
                        modifier = Modifier.width(320.dp).heightIn(max = 360.dp))
                }
            }
        }
        val before = compose.onNodeWithTag("settings-save").assertIsDisplayed().fetchSemanticsNode().boundsInRoot
        compose.onNodeWithTag("settings-cancel").assertIsDisplayed()
        compose.onNodeWithText(Strings(application)("privacy.body")).performScrollTo()
        val after = compose.onNodeWithTag("settings-save").assertIsDisplayed().fetchSemanticsNode().boundsInRoot
        compose.onNodeWithTag("settings-cancel").assertIsDisplayed()
        assertEquals("Scrolling the form must not move Save", before, after)
    }

    @Test
    fun narrowDetailsStackAtLargeFontSizeWithoutOverlapping() {
        val label = "Remote address"
        val value = "2001:db8::1234"
        compose.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, fontScale = 2f)) {
                NetLurkerTheme {
                    Box(Modifier.width(260.dp)) { InfoRow(label, value, mono = true) }
                }
            }
        }
        compose.onNodeWithText(label).assertIsDisplayed()
        compose.onNodeWithText(value).assertIsDisplayed()
        val labelBounds = compose.onNodeWithText(label).fetchSemanticsNode().boundsInRoot
        val valueBounds = compose.onNodeWithText(value).fetchSemanticsNode().boundsInRoot
        assertTrue("Value overlaps its label", valueBounds.top >= labelBounds.bottom)
    }
}
