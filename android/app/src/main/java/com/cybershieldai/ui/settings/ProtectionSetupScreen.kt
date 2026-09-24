package com.cybershieldai.ui.settings

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.cybershieldai.monitor.MonitorController
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.TextSecondary

private data class PermItem(
    val title: String,
    val why: String,
    val dataProcessed: String,
    val leavesDevice: Boolean,
    val granted: () -> Boolean,
    val request: androidx.activity.compose.ManagedActivityResultLauncher<String, Boolean>? = null,
    val permission: String? = null,
    val isSpecialAccess: Boolean = false
)

/**
 * Protection Setup — explain-before-request permission UX. Each capability
 * states: why it's needed, what data it processes, whether that data leaves
 * the phone, and how to revoke. Nothing is requested without consent.
 */
@Composable
fun ProtectionSetupScreen() {
    val context = LocalContext.current
    var refresh by remember { mutableIntStateOf(0) }

    val notifLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { refresh++ }

    val items = listOf(
        PermItem(
            title = "Notifications",
            why = "Alerts you the moment a high-risk threat is detected",
            dataProcessed = "Detection metadata only (risk scores, categories)",
            leavesDevice = false,
            granted = {
                Build.VERSION.SDK_INT < 33 || androidx.core.content.ContextCompat
                    .checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
                    PackageManager.PERMISSION_GRANTED
            },
            request = if (Build.VERSION.SDK_INT >= 33) notifLauncher else null,
            permission = if (Build.VERSION.SDK_INT >= 33) Manifest.permission.POST_NOTIFICATIONS else null
        ),
        PermItem(
            title = "Notification access (background message monitoring)",
            why = "Watches incoming notification text for scam/phishing patterns in the background",
            dataProcessed = "Notification text analyzed in memory; only risk scores stored locally",
            leavesDevice = false,
            granted = { isNotificationListenerEnabled(context) },
            isSpecialAccess = true
        ),
        PermItem(
            title = "App information",
            why = "Lists installed apps' requested permissions to flag risky combinations",
            dataProcessed = "Package names and declared permissions (no app data)",
            leavesDevice = false,
            granted = { true }, // PackageManager needs no runtime grant
            isSpecialAccess = false
        ),
        PermItem(
            title = "Files you select",
            why = "Static analysis of files and APKs you explicitly pick — nothing automatic",
            dataProcessed = "Chosen file bytes in memory (hashed; never uploaded by default)",
            leavesDevice = false,
            granted = { true }, // SAF requires no runtime permission
            isSpecialAccess = false
        )
    )

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("Protection Setup", style = MaterialTheme.typography.headlineMedium)

        SectionCard {
            Text("ENABLE PROTECTION", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text(
                "CyberShield provides stronger monitoring when you enable supported " +
                "Android capabilities. Everything is opt-in, explained below, and " +
                "revocable. You remain in control.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }

        items.forEach { item ->
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(item.title, style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text("Why: ${item.why}", style = MaterialTheme.typography.bodyMedium)
                        Text("Data: ${item.dataProcessed}", style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                        Text("Leaves phone: ${if (item.leavesDevice) "Yes — explicit opt-in required" else "Never"}",
                            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                        Text("Revoke: Android Settings → Apps → CyberShield AI",
                            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                    }
                    if (item.granted()) {
                        Text("✓ On", color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.titleMedium)
                    } else {
                        Button(onClick = {
                            when {
                                item.permission != null && item.request != null ->
                                    item.request.launch(item.permission)
                                item.isSpecialAccess ->
                                    openNotificationListenerSettings(context)
                            }
                        }) { Text("Enable") }
                    }
                }
            }
        }

        SectionCard {
            Text("Background services status", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Master switch: Settings → CyberShield Monitoring (ON/OFF)\n" +
                "When ON:\n" +
                "  • Package monitoring — new installs & app-update permission diffs\n" +
                "  • Security score refresh — hourly via WorkManager\n" +
                "  • Hygiene scan — every 6h (local retention enforcement)\n" +
                "  • Notification monitoring — only when you grant Notification access above",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            Button(onClick = { MonitorController.start(context) }, modifier = Modifier.fillMaxWidth()) {
                Text("Apply monitoring settings")
            }
        }

        SectionCard {
            Text("What CyberShield will NEVER request", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            listOf(
                "READ_SMS / SEND_SMS (Play-policy restricted; share messages into the app instead)",
                "Accessibility service (screen scraping)",
                "Usage stats access",
                "Device admin",
                "Location background tracking"
            ).forEach { Text("✗ $it", style = MaterialTheme.typography.bodyMedium, color = TextSecondary) }
        }
    }
}

private fun isNotificationListenerEnabled(context: Context): Boolean {
    val cn = ComponentName(context, com.cybershieldai.monitor.ShieldNotificationListener::class.java)
    val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners") ?: return false
    return flat.split(":").any { it.equals(cn.flattenToString(), ignoreCase = true) }
}

private fun openNotificationListenerSettings(context: Context) {
    try {
        context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: Exception) { }
}
