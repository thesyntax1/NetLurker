package dev.netlurker.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import dev.netlurker.android.ui.MainScreen
import dev.netlurker.android.ui.NetLurkerTheme

/**
 * NetLurker for Android.
 *
 * A monitoring tool that cannot see the kernel socket table without root would be a toy, so
 * this build does not guess: it measures what the framework genuinely reports (per-UID
 * traffic, interfaces, link properties, Wi-Fi and radio state), investigates the
 * destinations you point it at with real lookups, and states plainly which question it
 * cannot answer on this device. See README-android.md.
 */
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NetLurkerTheme {
                MainScreen(viewModel)
            }
        }
    }

    override fun onPause() {
        // Keep observing while the screen is off is not the point: the counters are read on
        // a poll loop that only makes sense in the foreground, and Android throttles it
        // anyway. Persist so the baselines survive the process being reclaimed.
        viewModel.persist()
        super.onPause()
    }
}
