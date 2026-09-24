package com.cybershieldai

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.cybershieldai.ui.CyberShieldApp
import com.cybershieldai.ui.theme.CyberShieldTheme
import com.cybershieldai.utils.DeviceIdProvider
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private var sharedText by mutableStateOf<String?>(null)
    private var deepLinkScreen by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Edge-to-edge dark chrome: content draws behind transparent status/nav bars.
        androidx.core.view.WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = android.graphics.Color.TRANSPARENT
        window.navigationBarColor = android.graphics.Color.TRANSPARENT
        androidx.core.view.WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }
        DeviceIdProvider.init(this)
        handleIntent(intent)
        // UI design concept (visual only): restore the persisted skin BEFORE
        // first composition so the app never flashes the wrong design.
        val savedConcept = kotlinx.coroutines.runBlocking {
            try {
                com.cybershieldai.data.local.SettingsStore(this@MainActivity)
                    .uiConcept.firstOrNull()
            } catch (_: Exception) { null }
        }
        com.cybershieldai.ui.theme.SkinState.apply(
            com.cybershieldai.ui.theme.UiConcept.fromId(savedConcept))
        setContent {
            CyberShieldTheme {
                CyberShieldApp(initialSharedText = sharedText, startScreen = deepLinkScreen)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }    /** Share Intent → scanner; notification taps ("screen" extra) → deep link. */
    private fun handleIntent(intent: Intent?) {
        if (intent?.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
        }

        intent?.getStringExtra("screen")?.let { deepLinkScreen = it }
    }
}

/** Application class — initializes alert channels and background monitors. */
class CyberShieldApplication : android.app.Application() {
    override fun onCreate() {
        super.onCreate()
        com.cybershieldai.utils.ContextHolder.appContext = this
        com.cybershieldai.utils.NotificationHelper.ensureChannels(this)
        com.cybershieldai.monitor.MonitorController.start(this)
        // Automatic ~12h security check (spec §4) — user-configurable in Settings.
        try {
            val prefs = kotlinx.coroutines.runBlocking {
                com.cybershieldai.data.local.SettingsStore(this@CyberShieldApplication)
                    .autoCheckPrefsOnce()
            }
            if (prefs.enabled) {
                com.cybershieldai.work.AutoCheckWorker.schedule(this, prefs.intervalHours)
            }
        } catch (_: Exception) { }
    }
}
