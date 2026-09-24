package com.cybershieldai.ui.diagnostics

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.navigation.NavHostController
import com.cybershieldai.data.local.SettingsStore
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Notification Diagnostics (spec §7) — the REAL state of the notification
 * pipeline, read live from Android and CyberShield's own tracking. No fake
 * statuses. [Send Test Notification] posts a REAL notification through the
 * REAL pipeline (explicitly labelled as a test, not a fake detection).
 */
@Composable
fun DiagnosticsScreen(navController: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tick by remember { mutableStateOf(0) }   // refresh trigger
    var testResult by remember { mutableStateOf<String?>(null) }

    // Android 13+ runtime permission request straight from diagnostics.
    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { tick++ }

    // Background-processing state from WorkManager's real job store.
    LaunchedEffect(Unit) { tick++ }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        // ---------------- Header ----------------
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { navController.popBackStack() }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back", tint = TextSecondary)
            }
            Text("Notification Diagnostics", style = CS.Heading, color = TextPrimary)
        }
        Text("Live status of the notification pipeline. All values are read from Android and CyberShield's own delivery tracking.",
            style = CS.BodyMedium, color = TextSecondary)

        key(tick) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            val notifPerm = Build.VERSION.SDK_INT < 33 ||
                ContextCompat.checkSelfPermission(
                    context, Manifest.permission.POST_NOTIFICATIONS) ==
                    PackageManager.PERMISSION_GRANTED

            // WorkManager state for the periodic security check.
            val workInfo = try {
                androidx.work.WorkManager.getInstance(context)
                    .getWorkInfosForUniqueWork("cybershield_auto_check").get()
                    .firstOrNull()
            } catch (_: Exception) { null }
            val bgState = when (workInfo?.state) {
                androidx.work.WorkInfo.State.RUNNING, androidx.work.WorkInfo.State.ENQUEUED -> "RUNNING"
                androidx.work.WorkInfo.State.FAILED -> "ERROR"
                androidx.work.WorkInfo.State.CANCELLED -> "STOPPED"
                null -> "STOPPED"
                else -> "RESTRICTED"
            }
            val bgDetail = when (bgState) {
                "RUNNING" -> "12-hour security check scheduled"
                "STOPPED" -> "Background check not scheduled (enable in Settings)"
                "ERROR" -> "Last background check failed"
                else -> "Constrained by Android (battery/background rules)"
            }
            val mediaEngineReady = com.cybershieldai.ai.AiModelManager.isInstalled(context)

            @Composable
            fun statusLine(label: String, state: String, detail: String = "") {
                val color = when {
                    state.startsWith("ON") || state == "READY" || state == "ENABLED" ||
                        state == "RUNNING" || state == "NONE" -> Safe
                    state.startsWith("OFF") || state == "DISABLED" || state == "STOPPED" ||
                        state == "NOT READY" || state.startsWith("ERROR") -> Warning
                    else -> Warning
                }
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(label, style = CS.CardTitle, color = TextPrimary)
                        if (detail.isNotEmpty())
                            Text(detail, style = CS.Secondary, color = TextTertiary)
                    }
                    Surface(shape = MaterialTheme.shapes.small, color = color.copy(alpha = 0.15f)) {
                        Text(state, style = CS.Label, color = color,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
                    }
                }
            }

            val fmt = remember { SimpleDateFormat("MMM d, HH:mm:ss", Locale.US) }
            val mgr = com.cybershieldai.utils.CyberShieldNotificationManager

            // ---------------- Permission + manager ----------------
            SectionCard {
                Text("Pipeline Status", style = CS.CardTitle, color = TextPrimary)
                Spacer(Modifier.height(Dsn.S))
                statusLine(
                    "Notification Permission",
                    if (notifPerm) "ON" else "OFF",
                    if (notifPerm) "Android 13+ runtime consent granted"
                    else "Required to show any notification")
                statusLine(
                    "Notification Manager",
                    if (nm != null) "READY" else "ERROR",
                    if (nm != null) "Android NotificationManager available"
                    else "System notification service unavailable")
                statusLine(
                    "Critical Channel",
                    mgr.channelState(context, mgr.CH_CRITICAL),
                    "Scam-risk and critical alerts")
                statusLine(
                    "Security Channel",
                    mgr.channelState(context, mgr.CH_SECURITY),
                    "Warnings needing review")
                statusLine(
                    "Scan Channel",
                    mgr.channelState(context, mgr.CH_SCAN),
                    "Scan and auto-check results")
                statusLine(
                    "AI Media Engine",
                    if (mediaEngineReady) "READY" else "OPTIONAL",
                    if (mediaEngineReady)
                        "Local model installed — explanations available for media analysis"
                    else
                        "Optional: install the local model for AI explanations of results")
                statusLine(
                    "Background Processing",
                    bgState, bgDetail)
            }

            // ---------------- Recent activity ----------------
            SectionCard {
                Text("Recent Pipeline Activity", style = CS.CardTitle, color = TextPrimary)
                Spacer(Modifier.height(Dsn.S))
                statusLine(
                    "Last Notification",
                    if (mgr.lastNotificationAt > 0) fmt.format(Date(mgr.lastNotificationAt)) else "NONE",
                    "Most recent notification actually posted")
                statusLine(
                    "Last Detection",
                    if (mgr.lastDetectionAt > 0) fmt.format(Date(mgr.lastDetectionAt)) else "NONE",
                    "Most recent analyzed security event")
                statusLine(
                    "Last Error",
                    if (mgr.lastError != null) "ERROR" else "NONE",
                    mgr.lastError ?: "No delivery failures recorded")
            }

            // ---------------- Delivery trail ----------------
            val trail = mgr.recentTrail()
            if (trail.isNotEmpty()) {
                SectionCard {
                    Text("Delivery Trail (newest first)", style = CS.CardTitle, color = TextPrimary)
                    Spacer(Modifier.height(Dsn.S))
                    trail.take(8).forEach { e ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                            Text(
                                fmt.format(Date(e.time)),
                                style = CS.Secondary, color = TextTertiary)
                            Spacer(Modifier.width(Dsn.S))
                            Text(
                                if (e.ok) "✓" else "✗",
                                style = CS.Secondary,
                                color = if (e.ok) Safe else High)
                            Spacer(Modifier.width(Dsn.S))
                            Text(
                                "${e.stage} ${e.detail}".take(60),
                                style = CS.Secondary, color = TextSecondary)
                        }
                    }
                }
            }

            // ---------------- Actions ----------------
            Row(horizontalArrangement = Arrangement.spacedBy(Dsn.M)) {
                Button(
                    onClick = {
                        if (!notifPerm && Build.VERSION.SDK_INT >= 33) {
                            permLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        } else {
                            scope.launch {
                                val ok = com.cybershieldai.utils.CyberShieldNotificationManager
                                    .sendTestNotification(context)
                                testResult = if (ok)
                                    "Test notification posted — check the notification bar."
                                else
                                    "Blocked: ${com.cybershieldai.utils.CyberShieldNotificationManager.diagnoseBlock(context)}"
                                tick++
                            }
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) { Text(if (notifPerm) "Send Test Notification" else "Grant Notification Permission") }

                OutlinedButton(
                    onClick = {
                        try {
                            context.startActivity(
                                android.content.Intent(
                                    android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                    .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE,
                                        context.packageName))
                        } catch (_: Exception) { }
                    },
                    modifier = Modifier.weight(1f)
                ) { Text("Android Settings") }
            }

            testResult?.let {
                Text(it, style = CS.BodyMedium,
                    color = if (it.startsWith("Test notification posted")) Safe else Warning)
            }

            Text(
                "The test notification is generated by the notification system itself — " +
                    "it is not a security detection and does not create a fake alert.",
                style = CS.Secondary, color = TextTertiary)
        }
    }
}
