package com.cybershieldai.ui.settings

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.cybershieldai.data.local.NotificationPrefs
import com.cybershieldai.data.local.SettingsStore
import com.cybershieldai.ui.components.*
import com.cybershieldai.ui.theme.TextSecondary
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settings = remember { SettingsStore(context) }
    var checkingAi by remember { mutableStateOf(false) }
    var aiStatusText by remember { mutableStateOf("Not checked yet") }
    var deleteMessage by remember { mutableStateOf<String?>(null) }

    val notifications by settings.notificationsEnabled.collectAsState(initial = true)
    val autoScan by settings.autoScanShares.collectAsState(initial = true)
    val storeHistory by settings.storeHistory.collectAsState(initial = true)
    val monitoring by settings.monitoringEnabled.collectAsState(initial = true)
    val notifPrefs by settings.notificationPrefs.collectAsState(initial = NotificationPrefs())

    // Android 13+ requires runtime POST_NOTIFICATIONS consent
    val notifPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }
    fun onNotificationsToggle(enabled: Boolean) {
        scope.launch { settings.setNotificationsEnabled(enabled) }
        if (enabled && Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)

        // ---------------- UI design concept (visual only) ----------------
        SectionCard {
            Text("App Design", style = MaterialTheme.typography.titleMedium)
            Text(
                "Choose one of five design concepts. This changes the look and feel " +
                    "only — every feature, scan and setting stays exactly the same.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            com.cybershieldai.ui.theme.UiConcept.entries.forEach { concept ->
                val selected = com.cybershieldai.ui.theme.SkinState.concept == concept
                Surface(
                    onClick = {
                        com.cybershieldai.ui.theme.SkinState.apply(concept)
                        scope.launch { settings.setUiConcept(concept.id) }
                    },
                    shape = MaterialTheme.shapes.medium,
                    color = if (selected)
                        com.cybershieldai.ui.theme.Primary.copy(alpha = 0.14f)
                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                    border = if (selected)
                        androidx.compose.foundation.BorderStroke(
                            1.dp, com.cybershieldai.ui.theme.Primary)
                    else null,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
                ) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(concept.label, style = MaterialTheme.typography.titleSmall)
                            Text(concept.description,
                                style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        }
                        androidx.compose.material3.RadioButton(
                            selected = selected, onClick = null)
                    }
                }
            }
        }

        // ---------------- Privacy ----------------
        SectionCard {
            Text("Privacy", style = MaterialTheme.typography.titleMedium)
            Text(
                "What is analyzed: message text you submit, URLs you submit, decoded QR content, and file metadata.\n\n" +
                "What is stored: scan results with indicators only, in this app's private local storage. Raw message content is NOT stored.\n\n" +
                "What leaves your device: nothing. All analysis runs on this device.\n\n" +
                "What never leaves your device: passwords, OTPs, authentication tokens, cookies, and anything you don't submit.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            SettingsToggle("Store scan history", storeHistory,
                { scope.launch { settings.setStoreHistory(it) } },
                "Keep scan results in this app's private storage for history and correlation. Turning this off also disables attack-chain correlation.")
        }

        // ---------------- Monitoring (spec §18: user must know what is monitored) ----------------
        SectionCard {
            Text("CyberShield Monitoring", style = MaterialTheme.typography.titleMedium)
            SettingsToggle("Monitoring", monitoring,
                { enabled ->
                    scope.launch {
                        settings.setMonitoringEnabled(enabled)
                        com.cybershieldai.monitor.MonitorController.start(context)
                    }
                },
                "ON: new-app permission checks, app-update permission diffing, hourly " +
                "security score refresh, 6-hourly data-retention hygiene.")
            Spacer(Modifier.height(6.dp))
            Text("What CyberShield monitors — always visible to you:",
                style = MaterialTheme.typography.bodyMedium)
            Text(
                "• Apps you install or update (permission changes only)\n" +
                "• Scans you run and their results\n" +
                "• Notification text — ONLY if you grant Notification access (separate opt-in in Protection Setup, revocable anytime)",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Spacer(Modifier.height(4.dp))
            Text(
                "Never monitored: other apps' private data, passwords, OTPs, cookies, " +
                "browsing history, camera or microphone. No hidden surveillance — ever.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }

        // ---------------- Automatic security check (spec §4) ----------------
        SectionCard {
            Text("Automatic Security Check", style = MaterialTheme.typography.titleMedium)
            val autoPrefs by settings.autoCheckPrefs.collectAsState(
                initial = com.cybershieldai.data.local.SettingsStore.AutoCheckPrefs())
            SettingsToggle("Background security check", autoPrefs.enabled,
                { on ->
                    scope.launch {
                        settings.setAutoCheckEnabled(on)
                        if (on) com.cybershieldai.work.AutoCheckWorker.reschedule(
                            context, autoPrefs.intervalHours)
                        else com.cybershieldai.work.AutoCheckWorker.cancel(context)
                    }
                },
                "Approximately every 12 hours, CyberShield re-checks installed apps, " +
                "permissions, recent events and your security score — when Android " +
                "allows background execution.")
            if (autoPrefs.enabled) {
                Spacer(Modifier.height(6.dp))
                Text("Check interval", style = MaterialTheme.typography.bodyLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(6, 12, 24).forEach { h ->
                        FilterChip(
                            selected = autoPrefs.intervalHours == h,
                            onClick = {
                                scope.launch {
                                    settings.setAutoCheckHours(h)
                                    com.cybershieldai.work.AutoCheckWorker.reschedule(context, h)
                                }
                            },
                            label = { Text(if (h == 24) "24 h" else "$h h") })
                    }
                }
                SettingsToggle("Check-complete notifications", autoPrefs.notify,
                    { on -> scope.launch { settings.setAutoCheckNotify(on) } },
                    "Get a summary after each automatic check. Risk alerts are always delivered regardless.")
            }
        }

        // ---------------- Notifications ----------------
        SectionCard {
            Text("Notifications", style = MaterialTheme.typography.titleMedium)
            SettingsToggle("Security alerts", notifications,
                { onNotificationsToggle(it) },
                "Master switch. Rules below also apply.")
            SettingsToggle("Auto-scan shared text", autoScan,
                { scope.launch { settings.setAutoScanShares(it) } },
                "Pre-fill the message scanner when you share text from another app.")

            Spacer(Modifier.height(8.dp))
            Text("Alert severity threshold", style = MaterialTheme.typography.bodyLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("MEDIUM", "HIGH", "CRITICAL").forEach { sev ->
                    FilterChip(
                        selected = notifPrefs.minSeverity == sev,
                        onClick = {
                            scope.launch { settings.updateNotificationPrefs { it.copy(minSeverity = sev) } }
                        },
                        label = { Text(sev) })
                }
            }
            Text("MEDIUM alerts are optional; CRITICAL always attempts delivery.",
                style = MaterialTheme.typography.bodySmall, color = TextSecondary)

            Spacer(Modifier.height(8.dp))
            SettingsToggle("Quiet hours", notifPrefs.quietHoursEnabled,
                { on -> scope.launch { settings.updateNotificationPrefs { it.copy(quietHoursEnabled = on) } } },
                "Only critical alerts break through, and never when the phone is face-down in a pocket.")
            if (notifPrefs.quietHoursEnabled) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Text("From", style = MaterialTheme.typography.bodyMedium)
                    HourStepper(notifPrefs.quietStartHour) { h ->
                        scope.launch { settings.updateNotificationPrefs { it.copy(quietStartHour = h) } }
                    }
                    Text("to", style = MaterialTheme.typography.bodyMedium)
                    HourStepper(notifPrefs.quietEndHour) { h ->
                        scope.launch { settings.updateNotificationPrefs { it.copy(quietEndHour = h) } }
                    }
                }
            }

            Spacer(Modifier.height(8.dp))
            Text("Frequency limit", style = MaterialTheme.typography.bodyLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(10, 30, 60).forEach { mins ->
                    FilterChip(
                        selected = notifPrefs.minIntervalMinutes == mins,
                        onClick = {
                            scope.launch { settings.updateNotificationPrefs { it.copy(minIntervalMinutes = mins) } }
                        },
                        label = { Text("$mins min") })
                }
            }
            Text("Hard cap: at most 6 security alerts per hour, regardless of settings.",
                style = MaterialTheme.typography.bodySmall, color = TextSecondary)

            Spacer(Modifier.height(8.dp))
            Text("Categories", style = MaterialTheme.typography.bodyLarge)
            SettingsToggle("Critical security", notifPrefs.catCritical,
                { on -> scope.launch { settings.updateNotificationPrefs { it.copy(catCritical = on) } } },
                "")
            SettingsToggle("High risk", notifPrefs.catHighRisk,
                { on -> scope.launch { settings.updateNotificationPrefs { it.copy(catHighRisk = on) } } },
                "")
            SettingsToggle("Privacy", notifPrefs.catPrivacy,
                { on -> scope.launch { settings.updateNotificationPrefs { it.copy(catPrivacy = on) } } },
                "")
            SettingsToggle("Scam & phishing", notifPrefs.catScam,
                { on -> scope.launch { settings.updateNotificationPrefs { it.copy(catScam = on) } } },
                "")
            SettingsToggle("Security updates (score changes)", notifPrefs.catUpdates,
                { on -> scope.launch { settings.updateNotificationPrefs { it.copy(catUpdates = on) } } },
                "")
        }        // ---------------- On-Device AI (no backend exists) ----------------
        SectionCard {
            Text("On-Device AI", style = MaterialTheme.typography.titleMedium)
            Text(
                "All analysis runs on this device — nothing is sent to any server, " +
                "and no backend is needed. The security scanner uses the on-device " +
                "rule engine plus the local AI model when installed.",
                style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            Spacer(Modifier.height(4.dp))
            val modelInstalled = com.cybershieldai.ai.AiModelManager.isInstalled(context)
            Text(
                if (modelInstalled) "Local AI model: installed — hybrid rules + AI analysis active."
                else "Local AI model: not installed — rule engine active (fully functional).",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            Button(onClick = {
                checkingAi = true
                scope.launch {
                    aiStatusText = if (com.cybershieldai.ai.AiModelManager.isInstalled(context))
                        "On-device AI ready. Scanner: rules + local AI. Chat: local model."
                    else
                        "Rule engine active. Scanner and assistant work fully offline; " +
                            "install the model in AI Model Settings to enable AI explanations."
                    checkingAi = false
                }
            }, enabled = !checkingAi) {
                Text(if (checkingAi) "Checking…" else "Check AI Status")
            }
            Text(aiStatusText, style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary)
        }

        // ---------------- Scan preferences ----------------
        SectionCard {
            Text("Scan Preferences", style = MaterialTheme.typography.titleMedium)
            Text("Risk thresholds are calibrated application values (not universal standards): " +
                 "0–24 SAFE, 25–49 LOW, 50–74 MEDIUM, 75–89 HIGH, 90–100 CRITICAL.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }

        // ---------------- Data deletion ----------------
        SectionCard {
            Text("Data & Deletion", style = MaterialTheme.typography.titleMedium)
            Button(onClick = {
                scope.launch {
                    try {
                        com.cybershieldai.data.repository.EventRepository(context).clearAll()
                        deleteMessage = "Scan history deleted from this device."
                    } catch (_: Exception) {
                        deleteMessage = "Could not delete scan history."
                    }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Delete Scan History") }

            Spacer(Modifier.height(6.dp))
            Button(onClick = {
                scope.launch {
                    settings.clearAll()
                    deleteMessage = "All local settings and data cleared."
                }
            }, modifier = Modifier.fillMaxWidth(),
               colors = ButtonDefaults.buttonColors(
                   containerColor = MaterialTheme.colorScheme.error)) {
                Text("Delete All Local Data")
            }
            deleteMessage?.let {
                Spacer(Modifier.height(6.dp))
                Text(it, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
        }

        // ---------------- About ----------------
        SectionCard {
            Text("About", style = MaterialTheme.typography.titleMedium)
            val vName = try {
                context.packageManager.getPackageInfo(context.packageName, 0).versionName
            } catch (_: Exception) { "?" }
            Text("CyberShield AI v$vName — AI-Powered Personal Cyber Threat Detection & Protection.\n\n" +
                 "Defensive tool: detects, explains, and helps you avoid cyber threats. " +
                 "Detection engines decide risk; the AI assistant only explains results in plain language.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }
    }
}

@Composable
fun SettingsToggle(title: String, checked: Boolean, onChange: (Boolean) -> Unit,
                   subtitle: String = "") {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (subtitle.isNotEmpty())
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

/** Compact 0-23 hour picker with +/- steppers (used for quiet hours). */
@Composable
fun HourStepper(hour: Int, onChange: (Int) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        OutlinedButton(onClick = { onChange((hour + 23) % 24) },
            contentPadding = PaddingValues(horizontal = 10.dp)) { Text("−") }
        Text("%02d:00".format(hour), style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = { onChange((hour + 1) % 24) },
            contentPadding = PaddingValues(horizontal = 10.dp)) { Text("+") }
    }
}
