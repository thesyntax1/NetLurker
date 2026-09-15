package dev.netlurker.android

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
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
    fun settingsPickerAppliesImmediatelyAndPersists() {
        val model = MainViewModel(application)
        store.put("settings-test", model)
        compose.setContent {
            NetLurkerTheme {
                SettingsDialog(model, onRequestLocation = {}, onDismiss = {})
            }
        }
        compose.onNodeWithText("English").performClick()
        compose.onNodeWithText("Türkçe").performClick()
        compose.onNodeWithText("DİL").assertIsDisplayed()
        assertEquals("tr", Settings(application).languageOverride)
        assertEquals("Dil", Strings(application)("settings.language"))
        compose.onNodeWithText("Türkçe").performClick()
        compose.onNodeWithText("English").performClick()
        compose.onNodeWithText("LANGUAGE").assertIsDisplayed()
        assertEquals("en", Settings(application).languageOverride)
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
