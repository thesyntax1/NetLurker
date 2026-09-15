package dev.netlurker.android

import android.Manifest
import android.os.Build
import androidx.test.rule.GrantPermissionRule
import androidx.lifecycle.ViewModelStore
import dev.netlurker.android.ui.Strings
import org.junit.After
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.netlurker.android.ui.MainScreen
import dev.netlurker.android.ui.NetLurkerTheme
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Every tab is composed for real on a device.
 *
 * The unit tests pin the scoring arithmetic; they cannot tell you that a screen composes.
 * These assertions are deliberately about *rendering*, not about data: on an emulator with
 * no Wi-Fi, no radio and no granted permissions the honest thing for each panel to show is
 * "unavailable here", and the test's job is to prove that path reaches the screen instead of
 * throwing. A composable that crashes on missing data fails here even though every unit
 * test is green.
 *
 * Two conventions this file has to respect: resource names are the catalog keys, dots
 * included, so they are not valid Kotlin identifiers and go through Resources.getIdentifier
 * the way the app does; and several catalog strings legitimately appear more than once on a
 * screen (a section header and the row inside it can share a label), so presence is asserted
 * by count rather than by assuming a single node.
 */
@RunWith(AndroidJUnit4::class)
class ScreenRenderTest {

    @get:Rule
    val compose = createComposeRule()

    @get:Rule
    val permissions: GrantPermissionRule = GrantPermissionRule.grant(
        *buildList {
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.POST_NOTIFICATIONS)
        }.toTypedArray()
    )

    private val store = ViewModelStore()
    private lateinit var viewModel: MainViewModel

    private fun text(key: String): String {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        return Strings(context)(key)
    }

    /** True when the label is on screen at least once. */
    private fun isShown(key: String): Boolean =
        compose.onAllNodesWithText(text(key), substring = true)
            .fetchSemanticsNodes()
            .isNotEmpty()

    private fun clickTab(key: String) {
        compose.onAllNodesWithText(text(key), substring = true).onFirst().performClick()
        compose.waitForIdle()
    }

    @Before
    fun setUp() {
        viewModel = MainViewModel(ApplicationProvider.getApplicationContext())
        store.put("screen-test", viewModel)
        compose.setContent {
            NetLurkerTheme { MainScreen(viewModel) }
        }
    }

    @After
    fun tearDown() {
        viewModel.stop()
        store.clear()
    }

    @Test
    fun everyTabComposesWithoutThrowing() {
        val tabs = listOf("tab.investigate", "tab.apps", "tab.network", "tab.history", "tab.summary")

        for (tab in tabs) {
            clickTab(tab)

            // Surviving composition: the title bar is still on screen, so nothing in the
            // panel we just switched to threw while it was being composed.
            compose.onNodeWithText("NetLurker").assertIsDisplayed()
            assertTrue("tab bar lost its own label after opening $tab", isShown(tab))
        }
    }

    @Test
    fun networkTabShowsItsUnconditionalSections() {
        clickTab("tab.network")

        // These headers render whether or not the device answers, which is exactly the
        // honesty contract the rest of the app is built on.
        assertTrue("link section missing", isShown("section.link"))
        assertTrue("hosts section missing", isShown("hosts.title"))
    }

    @Test
    fun topBarControlsAreReachableFromTheFirstTab() {
        assertTrue("export action missing", isShown("action.export"))
        assertTrue("pause action missing", isShown("action.pause"))
    }
}
