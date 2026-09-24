package com.cybershieldai.ui.protection

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Contacts
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.PostAdd
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.local.SettingsStore
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.relativeTime
import com.cybershieldai.ui.theme.*

/**
 * APP PROTECTION — exact layout from the provided reference image:
 * back header → "App Protection" summary card with Active pill → segmented
 * Permissions / Installed Apps / Data Access tabs → Sensitive Permissions
 * rows (icon, name, real "N apps" count, WORKING toggle backed by
 * per-category monitoring prefs) → Recently Suspicious Apps (real events).
 * Counts come from PackageManager; toggles genuinely enable/disable that
 * category's permission-change monitoring.
 */
@Composable
fun ProtectionScreen(navController: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by remember { mutableStateOf(0) }

    var permCounts by remember { mutableStateOf<Map<String, Int>>(emptyMap()) }
    // label -> list of (app label, permission actually GRANTED, package name)
    var permApps by remember { mutableStateOf<Map<String, List<Triple<String, Boolean, String>>>>(emptyMap()) }
    var totalUserApps by remember { mutableStateOf(0) }
    var suspiciousApps by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var recentChanges by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var watch by remember { mutableStateOf(SettingsStore.PermWatchPrefs()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val pm = context.packageManager
                val groups = mapOf(
                    "Camera" to android.Manifest.permission.CAMERA,
                    "Microphone" to android.Manifest.permission.RECORD_AUDIO,
                    "Location" to android.Manifest.permission.ACCESS_FINE_LOCATION,
                    "Contacts" to android.Manifest.permission.READ_CONTACTS,
                    "SMS" to android.Manifest.permission.RECEIVE_SMS,
                    "Files & Storage" to android.Manifest.permission.READ_EXTERNAL_STORAGE
                )
                val counts = mutableMapOf<String, Int>()
                val appsByPerm = mutableMapOf<String, MutableList<Triple<String, Boolean, String>>>()
                var userApps = 0
                val pkgs = try {
                    pm.getInstalledPackages(android.content.pm.PackageManager.PackageInfoFlags.of(
                        android.content.pm.PackageManager.GET_PERMISSIONS.toLong()))
                } catch (_: Exception) { emptyList() }
                for (p in pkgs) {
                    val isSystem = (p.applicationInfo.flags and
                        android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    if (isSystem) continue
                    userApps++
                    val requested = p.requestedPermissions ?: continue
                    val appLabel = try { p.applicationInfo?.loadLabel(pm)?.toString() ?: p.packageName }
                        catch (_: Exception) { p.packageName }
                    groups.forEach { (label, perm) ->
                        if (requested.contains(perm)) {
                            counts[label] = (counts[label] ?: 0) + 1
                            // TRUE grant state (not just "declared in manifest"):
                            // runtime-revoked permissions show as not granted.
                            val granted = pm.checkPermission(perm, p.packageName) ==
                                android.content.pm.PackageManager.PERMISSION_GRANTED
                            appsByPerm.getOrPut(label) { mutableListOf() }
                                .add(Triple(appLabel, granted, p.packageName))
                        }
                    }
                }
                // Ensure every row exists even with 0 apps.
                groups.keys.forEach { counts.putIfAbsent(it, 0) }
                // Granted apps first, then alphabetical — stable, honest order.
                permApps = appsByPerm.mapValues { (_, list) ->
                    list.sortedWith(
                        compareByDescending<Triple<String, Boolean, String>> { it.second }
                            .thenBy { it.first.lowercase() })
                }
                permCounts = counts
                totalUserApps = userApps
            } catch (_: Exception) { }
            try {
                val repo = EventRepository(context)
                suspiciousApps = repo.events(limit = 200)
                    .filter { it.category == "APP" && it.riskScore >= 40 }
                    .take(5)
                recentChanges = repo.events(category = "PRIVACY", limit = 5)
            } catch (_: Exception) { }
            watch = try { SettingsStore(context).permWatchPrefsOnce() }
            catch (_: Exception) { SettingsStore.PermWatchPrefs() }
            loading = false
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Dsn.L)) {
        // ---------------- Header ----------------
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = {
                // Reached both as a bottom-nav tab (nothing to pop → Home)
                // and as a pushed screen (pop back).
                if (!navController.popBackStack()) navController.navigate("home")
            }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back", tint = TextSecondary)
            }
            Text("App Protection", style = CS.Heading, color = TextPrimary,
                modifier = Modifier.weight(1f))
        }

        // ---------------- Summary card (image: shield icon + Active pill) ----------
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(shape = CircleShape, color = Primary.copy(alpha = 0.2f)) {
                    Icon(Icons.Filled.Shield, contentDescription = null, tint = Primary,
                        modifier = Modifier.padding(10.dp).size(26.dp))
                }
                Spacer(Modifier.width(Dsn.M))
                Column(Modifier.weight(1f)) {
                    Text("App Protection", style = CS.CardTitle, color = TextPrimary)
                    Text("Monitor app behavior, permissions and data access " +
                        "to keep your device safe.",
                        style = CS.Secondary, color = TextSecondary)
                }
                Surface(
                    shape = RoundedCornerShape(50),
                    color = Safe.copy(alpha = 0.15f)
                ) {
                    Text("Active", style = CS.Caption, color = Safe,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
                }
            }
        }

        // ---------------- Segmented tabs (image: filled active segment) ------------
        SegmentedTabs(
            tabs = listOf("Permissions", "Installed Apps", "Data Access"),
            selected = tab,
            onSelect = { tab = it }
        )
        Spacer(Modifier.height(Dsn.M))

        when {
            loading -> com.cybershieldai.ui.components.LoadingView("Reading app metadata…")
            tab == 0 -> PermissionsTab(
                permCounts, permApps, watch,
                onToggle = { key, on ->
                    scope.launch {
                        SettingsStore(context).setPermWatch { it.copyFor(key, on) }
                        watch = SettingsStore(context).permWatchPrefsOnce()
                    }
                },
                recentChanges = recentChanges
            )
            tab == 1 -> InstalledAppsTab(totalUserApps, navController)
            else -> DataAccessTab()
        }

        // ---------------- Recently Suspicious Apps (image section) -----------------
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Recently Suspicious Apps", style = CS.Heading, color = TextPrimary,
                modifier = Modifier.weight(1f))
            TextButton(onClick = { navController.navigate("alerts") }) {
                Text("View all", style = CS.Label, color = Primary)
            }
        }
        if (suspiciousApps.isEmpty()) {
            SectionCard {
                Text("No suspicious apps recorded", style = CS.CardTitle)
                Text("Apps flagged by the risk engine appear here. Nothing is fabricated.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
        } else {
            suspiciousApps.forEach { ev ->
                SectionCard(modifier = Modifier.padding(vertical = Dsn.XS)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(shape = CircleShape, color = Warning.copy(alpha = 0.15f)) {
                            Icon(Icons.Filled.Description, contentDescription = null,
                                tint = Warning, modifier = Modifier.padding(8.dp).size(18.dp))
                        }
                        Spacer(Modifier.width(Dsn.M))
                        Column(Modifier.weight(1f)) {
                            Text(ev.summary, style = CS.BodyMedium, color = TextPrimary)
                            Text(relativeTime(ev.timestamp), style = CS.Caption,
                                color = TextTertiary)
                        }
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = High.copy(alpha = 0.15f)
                        ) {
                            Text("High", style = CS.Caption, color = High,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(Dsn.M))
    }
}

private fun SettingsStore.PermWatchPrefs.copyFor(key: String, on: Boolean) = when (key) {
    "Camera" -> copy(camera = on)
    "Microphone" -> copy(microphone = on)
    "Location" -> copy(location = on)
    "Contacts" -> copy(contacts = on)
    "SMS" -> copy(sms = on)
    "Files & Storage" -> copy(files = on)
    else -> this
}

/** Image-style segmented control: filled purple active segment. */
@Composable
private fun SegmentedTabs(tabs: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(Dsn.XS)
    ) {
        tabs.forEachIndexed { i, t ->
            val active = i == selected
            Surface(
                onClick = { onSelect(i) },
                shape = RoundedCornerShape(12.dp),
                color = if (active) Primary else SurfaceVariant,
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    t, style = CS.Label,
                    color = if (active) androidx.compose.ui.graphics.Color.White else TextSecondary,
                    modifier = Modifier.padding(vertical = 10.dp),
                    maxLines = 1
                )
            }
        }
    }
}

private data class PermRowData(
    val label: String,
    val icon: ImageVector,
    val count: Int,
    val apps: List<Triple<String, Boolean, String>>
)

@Composable
private fun PermissionsTab(
    counts: Map<String, Int>,
    appsByPerm: Map<String, List<Triple<String, Boolean, String>>>,
    watch: SettingsStore.PermWatchPrefs,
    onToggle: (String, Boolean) -> Unit,
    recentChanges: List<SecurityEventEntity>
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    Text("Sensitive Permissions", style = CS.Heading, color = TextPrimary)
    Text("Monitor apps that access sensitive data.",
        style = CS.Secondary, color = TextTertiary)
    Spacer(Modifier.height(Dsn.S))

    val rows = listOf(
        PermRowData("Camera", Icons.Filled.CameraAlt, counts["Camera"] ?: 0, appsByPerm["Camera"].orEmpty()),
        PermRowData("Microphone", Icons.Filled.Mic, counts["Microphone"] ?: 0, appsByPerm["Microphone"].orEmpty()),
        PermRowData("Location", Icons.Filled.LocationOn, counts["Location"] ?: 0, appsByPerm["Location"].orEmpty()),
        PermRowData("Contacts", Icons.Filled.Contacts, counts["Contacts"] ?: 0, appsByPerm["Contacts"].orEmpty()),
        PermRowData("SMS", Icons.Filled.Sms, counts["SMS"] ?: 0, appsByPerm["SMS"].orEmpty()),
        PermRowData("Files & Storage", Icons.Filled.Folder, counts["Files & Storage"] ?: 0, appsByPerm["Files & Storage"].orEmpty())
    )
    rows.forEach { row ->
        val on = watchFor(watch, row.label)
        var expanded by remember { mutableStateOf(false) }
        val grantedCount = row.apps.count { it.second }
        SectionCard(modifier = Modifier.padding(vertical = Dsn.XS)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().then(
                    if (row.apps.isEmpty()) Modifier
                    else Modifier.clickable { expanded = !expanded }
                )
            ) {
                Surface(shape = CircleShape, color = Primary.copy(alpha = 0.16f)) {
                    Icon(row.icon, contentDescription = null, tint = Primary,
                        modifier = Modifier.padding(8.dp).size(18.dp))
                }
                Spacer(Modifier.width(Dsn.M))
                Column(Modifier.weight(1f)) {
                    Text(row.label, style = CS.BodyMedium, color = TextPrimary)
                    Text(
                        when {
                            row.count == 0 -> "No user apps request this"
                            else -> "$grantedCount of ${row.count} app(s) granted"
                        },
                        style = CS.Secondary, color = TextSecondary)
                }
                if (row.apps.isNotEmpty()) {
                    Icon(
                        if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = if (expanded) "Hide apps" else "Show apps",
                        tint = TextTertiary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(Dsn.S))
                }
                Switch(
                    checked = on,
                    onCheckedChange = { onToggle(row.label, it) },
                    colors = SwitchDefaults.colors(
                        checkedTrackColor = Safe,
                        checkedThumbColor = androidx.compose.ui.graphics.Color.White
                    )
                )
            }
            if (expanded && row.apps.isNotEmpty()) {
                Spacer(Modifier.height(Dsn.S))
                row.apps.forEach { (app, granted, pkg) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                            .clickable {
                                // Open the system App Info page for this app —
                                // where the permission can be allowed/denied.
                                try {
                                    context.startActivity(android.content.Intent(
                                        android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                        android.net.Uri.fromParts("package", pkg, null))
                                        .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                                } catch (_: Exception) { }
                            }
                            .padding(vertical = 5.dp)
                    ) {
                        Surface(
                            shape = CircleShape,
                            color = if (granted) Safe else TextTertiary.copy(alpha = 0.4f),
                            modifier = Modifier.size(8.dp)
                        ) {}
                        Spacer(Modifier.width(Dsn.M))
                        Text(app, style = CS.BodyMedium, color = TextPrimary,
                            modifier = Modifier.weight(1f))
                        Text(
                            if (granted) "Granted" else "Not granted",
                            style = CS.Caption,
                            color = if (granted) Safe else TextTertiary
                        )
                        Spacer(Modifier.width(Dsn.S))
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowForward,
                            contentDescription = "Open $app in system settings",
                            tint = TextTertiary,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
                Text(
                    "Tap an app to open its system settings and allow or revoke this " +
                        "permission. Toggle the switch to watch this category for changes.",
                    style = CS.Caption, color = TextTertiary,
                    modifier = Modifier.padding(top = 6.dp)
                )
            }
        }
    }
    // Toggles only affect future monitoring — state that plainly.
    Text(
        "Toggles control which permission categories CyberShield watches for " +
            "changes. They do not block apps or revoke Android permissions.",
        style = CS.Caption, color = TextTertiary,
        modifier = Modifier.padding(vertical = Dsn.S))

    if (recentChanges.isNotEmpty()) {
        Spacer(Modifier.height(Dsn.S))
        Text("Recently Changed Permissions", style = CS.Heading, color = TextPrimary)
        recentChanges.forEach { ev ->
            SectionCard(modifier = Modifier.padding(vertical = Dsn.XS)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.PostAdd, contentDescription = null, tint = Warning,
                        modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(Dsn.M))
                    Text(ev.summary, style = CS.BodyMedium, color = TextPrimary,
                        modifier = Modifier.weight(1f))
                    Text(relativeTime(ev.timestamp), style = CS.Caption, color = TextTertiary)
                }
            }
        }
    }
}

private fun watchFor(w: SettingsStore.PermWatchPrefs, key: String) = when (key) {
    "Camera" -> w.camera
    "Microphone" -> w.microphone
    "Location" -> w.location
    "Contacts" -> w.contacts
    "SMS" -> w.sms
    "Files & Storage" -> w.files
    else -> true
}

@Composable
private fun InstalledAppsTab(totalUserApps: Int, navController: NavHostController) {
    SectionCard {
        Text(
            if (totalUserApps == 0) "App inventory unavailable"
            else if (totalUserApps == 1) "1 user-installed app"
            else "$totalUserApps user-installed apps",
            style = CS.CardTitle, color = TextPrimary)
        Text("Full list with per-app risk analysis lives in the Apps screen.",
            style = CS.Secondary, color = TextSecondary)
        Spacer(Modifier.height(Dsn.S))
        Button(
            onClick = { navController.navigate("apps") },
            shape = RoundedCornerShape(Dsn.ButtonCorner),
            colors = ButtonDefaults.buttonColors(
                containerColor = Primary, contentColor = androidx.compose.ui.graphics.Color.White)
        ) { Text("Open Apps Inventory", style = CS.Label) }
    }
}

@Composable
private fun DataAccessTab() {
    Text("Data Access", style = CS.Heading, color = TextPrimary)
    Spacer(Modifier.height(Dsn.S))
    DataAccessRow("AVAILABLE", Safe,
        "Installed app inventory (PackageManager): app names, versions, requested permissions")
    DataAccessRow("PERMISSION REQUIRED", Warning,
        "Notification text analysis — only with Android Notification access (opt-in)")
    DataAccessRow("NOT AVAILABLE", TextTertiary,
        "Call audio, other apps' private files and databases, full browsing history — " +
            "Android does not provide these to CyberShield")
    Spacer(Modifier.height(Dsn.S))
    Text("CyberShield does not record or analyze phone-call audio.",
        style = CS.BodyMedium, color = Safe)
}

@Composable
private fun DataAccessRow(state: String, color: androidx.compose.ui.graphics.Color, text: String) {
    SectionCard(modifier = Modifier.padding(vertical = Dsn.XS)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Surface(
                shape = RoundedCornerShape(50),
                color = color.copy(alpha = 0.15f)
            ) {
                Text(state, style = CS.Caption, color = color,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
            }
            Spacer(Modifier.width(Dsn.M))
            Text(text, style = CS.BodyMedium, color = TextSecondary, modifier = Modifier.weight(1f))
        }
    }
}
