package com.cybershieldai.ui.privacy

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.severityColor

/**
 * Privacy Center (spec §4): per-resource view of which apps hold sensitive
 * access, with honest counts and one-tap deep links into the exact Android
 * Settings page so the USER changes permissions. CyberShield never silently
 * modifies permissions and never reads other apps' private data.
 */
@Composable
fun PrivacyScreen() {
    val context = LocalContext.current
    var resources by remember { mutableStateOf<List<ResourceAccess>>(emptyList()) }
    var accessibilityCount by remember { mutableStateOf<Int?>(null) }
    var permChanges by remember { mutableStateOf<Int?>(null) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
            resources = collectResourceAccess(context)
            accessibilityCount = countAccessibilityServices(context)
            permChanges = countRecentPrivacyEvents(context)
        }
        loading = false
    }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("Privacy Center", style = MaterialTheme.typography.headlineMedium)
        Text("Who can access what. Tap an app to open its Android permission page — you decide, CyberShield never changes permissions silently.",
            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)

        // Privacy Score (spec §17/§10): derived from the deterministic engine's
        // privacy factor — real evidence only, "Not enough data" when unavailable.
        var privacyScore by remember { mutableStateOf<Int?>(null) }
        var privacyFactors by remember { mutableStateOf<String?>(null) }
        LaunchedEffect(Unit) {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                try {
                    val r = com.cybershieldai.engine.SecurityScoreEngine.computeCurrent(context)
                    val f = r.factors.firstOrNull { it.key == "privacy" }
                    privacyScore = f?.let { 100 - it.deduction }
                    privacyFactors = f?.detail
                } catch (_: Exception) { }
            }
        }
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Privacy Score", style = MaterialTheme.typography.titleMedium)
                    Text(
                        privacyFactors ?: "Not enough data — run a scan from Home first.",
                        style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                }
                Text(
                    privacyScore?.toString() ?: "—",
                    style = MaterialTheme.typography.headlineMedium,
                    color = when {
                        privacyScore == null -> TextSecondary
                        privacyScore!! >= 80 -> severityColor("SAFE")
                        privacyScore!! >= 55 -> severityColor("MEDIUM")
                        else -> severityColor("HIGH")
                    })
            }
        }

        // Recent permission changes recorded by background monitoring (spec §4)
        SectionCard {
            Text("Permission changes", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                when {
                    permChanges == null -> "Background monitoring has not recorded changes yet."
                    permChanges == 0 -> "No sensitive permission changes recorded in the recent window."
                    else -> "$permChanges sensitive permission change(s) recorded. See Alerts → Privacy for the evidence."
                },
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }

        if (loading) {
            com.cybershieldai.ui.components.LoadingView("Auditing permission grants…")
        } else {
            resources.forEach { res ->
                ResourceCard(res)
            }

            // Accessibility-related privileges (special access, not a runtime permission)
            SectionCard {
                Text("Accessibility-related privileges", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    when {
                        accessibilityCount == null -> "Status unavailable on this device."
                        accessibilityCount == 0 -> "No accessibility services enabled — this is the safest state."
                        else -> "$accessibilityCount accessibility service(s) enabled. These can read screen content — review them carefully."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if ((accessibilityCount ?: 0) > 0) severityColor("MEDIUM") else TextSecondary)
                Spacer(Modifier.height(6.dp))
                OutlinedButton(onClick = { openAccessibilitySettings(context) },
                    modifier = Modifier.fillMaxWidth()) {
                    Text("Review accessibility services")
                }
            }
        }

        SectionCard {
            Text("How this works", style = MaterialTheme.typography.titleMedium)
            Text(
                "Counts come from Android's PackageManager: requested and granted permissions of visible apps. " +
                "Some apps may be hidden by Android package visibility. CyberShield never reads other apps' private data — only permission state.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }
    }
}

data class ResourceAccess(
    val label: String,
    val description: String,
    val permissions: List<String>,
    val apps: List<AppPermRow>
)

data class AppPermRow(val appName: String, val packageName: String)

@Composable
fun ResourceCard(res: ResourceAccess) {
    var expanded by remember { mutableStateOf(false) }
    val context = LocalContext.current
    SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(res.label, style = MaterialTheme.typography.titleMedium)
                Text(res.description, style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary)
            }
            Text("${res.apps.size}",
                style = MaterialTheme.typography.headlineMedium,
                color = if (res.apps.isEmpty()) severityColor("SAFE") else severityColor("MEDIUM"))
        }
        if (res.apps.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            Text(
                if (res.apps.size == 1) "1 application has access."
                else "${res.apps.size} applications have permission.",
                style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "Hide apps" else "Show apps")
            }
            if (expanded) {
                res.apps.forEach { app ->
                    Row(Modifier.fillMaxWidth()
                        .clickable { openAppSettings(context, app.packageName) }
                        .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(app.appName, style = MaterialTheme.typography.bodyLarge)
                            Text(app.packageName, style = MaterialTheme.typography.labelMedium,
                                color = TextSecondary)
                        }
                        Text("Review →", style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary)
                    }
                }
            }
        } else {
            Spacer(Modifier.height(4.dp))
            Text("No visible apps hold this permission.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }
    }
}

/** Aggregate granted sensitive permissions per resource across visible packages. */
private fun collectResourceAccess(context: Context): List<ResourceAccess> {
    val pm = context.packageManager
    val groups = listOf(
        ResourceAccess(
            "Camera access", "Apps that can take pictures or record video.",
            listOf(Manifest.permission.CAMERA), emptyList()),
        ResourceAccess(
            "Microphone access", "Apps that can record audio.",
            listOf(Manifest.permission.RECORD_AUDIO), emptyList()),
        ResourceAccess(
            "Location access", "Apps that can read your device location.",
            listOf(Manifest.permission.ACCESS_FINE_LOCATION,
                   Manifest.permission.ACCESS_COARSE_LOCATION,
                   Manifest.permission.ACCESS_BACKGROUND_LOCATION), emptyList()),
        ResourceAccess(
            "Contacts access", "Apps that can read or modify your contacts.",
            listOf(Manifest.permission.READ_CONTACTS,
                   Manifest.permission.WRITE_CONTACTS), emptyList()),
        ResourceAccess(
            "Photos & media access", "Apps that can read images, video or audio files.",
            listOf(Manifest.permission.READ_EXTERNAL_STORAGE,
                   Manifest.permission.READ_MEDIA_IMAGES,
                   Manifest.permission.READ_MEDIA_VIDEO,
                   Manifest.permission.READ_MEDIA_AUDIO), emptyList()),
        ResourceAccess(
            "SMS access", "Apps that can read or send SMS. Share suspicious texts into CyberShield instead of granting SMS access.",
            listOf(Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS,
                   Manifest.permission.SEND_SMS), emptyList())
    )
    val mutable = groups.map { it.copy(apps = mutableListOf<AppPermRow>()) as ResourceAccess }
        .toMutableList()

    try {
        val pkgs: List<PackageInfo> = pm.getInstalledPackages(
            PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        val labelCache = mutableMapOf<String, String>()
        for (p in pkgs) {
            val requested = p.requestedPermissions ?: continue
            val grantedFlags = p.requestedPermissionsFlags ?: IntArray(requested.size)
            val app = p.applicationInfo ?: continue
            val appName = labelCache.getOrPut(p.packageName) {
                try { app.loadLabel(pm)?.toString() ?: p.packageName } catch (_: Exception) { p.packageName }
            }
            val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            requested.forEachIndexed { idx, perm ->
                val granted = (grantedFlags.getOrElse(idx) { 0 } and
                    PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                if (!granted) return@forEachIndexed
                val target = mutable.indexOfFirst { perm in it.permissions }
                if (target >= 0) {
                    val existing = mutable[target].apps
                    // System apps hold many platform permissions by design; still listed
                    // (flagged) for transparency but they cannot be revoked like normal apps.
                    if (existing.none { it.packageName == p.packageName }) {
                        val suffix = if (isSystem) " (system)" else ""
                        mutable[target] = mutable[target].copy(
                            apps = existing + AppPermRow(appName + suffix, p.packageName))
                    }
                }
            }
        }
    } catch (_: SecurityException) {
        // Package visibility restricted — show what we could collect
    } catch (_: Exception) {
    }
    return mutable.map { it.copy(apps = it.apps.sortedBy { r -> r.appName.lowercase() }) }
}

private fun countAccessibilityServices(context: Context): Int? = try {
    val flat = Settings.Secure.getString(
        context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
    flat?.split(":")?.count { it.isNotBlank() }
} catch (_: Exception) { null }

private suspend fun countRecentPrivacyEvents(context: Context): Int? = try {
    com.cybershieldai.data.repository.EventRepository(context)
        .events(category = "PRIVACY", limit = 50).size
} catch (_: Exception) { null }

/** Deep link to one app's Android Settings page (the user changes permissions there). */
internal fun openAppSettings(context: Context, packageName: String) {
    try {
        context.startActivity(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.parse("package:$packageName"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    } catch (_: ActivityNotFoundException) {
        // Some OEMs remove this page; nothing safe to fall back to
    }
}

private fun openAccessibilitySettings(context: Context) {
    try {
        context.startActivity(
            Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: Exception) { }
}
