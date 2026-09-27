package com.cybershieldai.ui.protection

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.PostAdd
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import kotlinx.coroutines.withContext
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.relativeTime
import com.cybershieldai.ui.theme.*

/**
 * APP PROTECTION — back header → "App Protection" summary card with Active
 * pill → segmented Permissions / Installed Apps / Data Access tabs →
 * Recently Suspicious Apps (real events).
 *
 * Sensitive-permission enumeration was REMOVED by product decision: the
 * Permissions tab now directs the user to Android's own Permission manager
 * instead of listing which installed apps hold camera/mic/location/… grants.
 */
@Composable
fun ProtectionScreen(navController: NavHostController) {
    val context = LocalContext.current
    var tab by remember { mutableStateOf(0) }

    var totalUserApps by remember { mutableStateOf(0) }
    var suspiciousApps by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var recentChanges by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val pm = context.packageManager
                var userApps = 0
                val pkgs = try {
                    pm.getInstalledPackages(android.content.pm.PackageManager.PackageInfoFlags.of(0))
                } catch (_: Exception) { emptyList() }
                for (p in pkgs) {
                    val isSystem = (p.applicationInfo.flags and
                        android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    if (isSystem) continue
                    userApps++
                }
                totalUserApps = userApps
            } catch (_: Exception) { }
            try {
                val repo = EventRepository(context)
                suspiciousApps = repo.events(limit = 200)
                    .filter { it.category == "APP" && it.riskScore >= 40 }
                    .take(5)
                recentChanges = repo.events(category = "PRIVACY", limit = 5)
            } catch (_: Exception) { }
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

        // ---------------- Summary card ----------------
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

        // ---------------- Segmented tabs ----------------
        SegmentedTabs(
            tabs = listOf("Permissions", "Installed Apps", "Data Access"),
            selected = tab,
            onSelect = { tab = it }
        )
        Spacer(Modifier.height(Dsn.M))

        when {
            loading -> com.cybershieldai.ui.components.LoadingView("Reading app metadata…")
            tab == 0 -> PermissionsTab()
            tab == 1 -> InstalledAppsTab(totalUserApps, navController)
            else -> DataAccessTab()
        }

        // ---------------- Recently Suspicious Apps -----------------
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

@Composable
private fun PermissionsTab() {
    val context = LocalContext.current
    Text("Permissions", style = CS.Heading, color = TextPrimary)
    Text("Permission categories are not enumerated by CyberShield.",
        style = CS.Secondary, color = TextTertiary)
    Spacer(Modifier.height(Dsn.S))
    SectionCard {
        Text("Permission manager", style = CS.CardTitle, color = TextPrimary)
        Text(
            "CyberShield no longer lists which apps hold sensitive permissions. " +
                "Use Android Settings → Privacy → Permission manager to review and " +
                "revoke each app's access to camera, microphone, location, contacts, " +
                "SMS and files.",
            style = CS.BodyMedium, color = TextSecondary)
        Spacer(Modifier.height(Dsn.S))
        Button(
            onClick = {
                try {
                    context.startActivity(android.content.Intent(
                        android.provider.Settings.ACTION_SETTINGS)
                        .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                } catch (_: Exception) { }
            },
            shape = RoundedCornerShape(Dsn.ButtonCorner),
            colors = ButtonDefaults.buttonColors(
                containerColor = Primary, contentColor = androidx.compose.ui.graphics.Color.White)
        ) { Text("Open Android Settings", style = CS.Label) }
    }
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
        "Installed app inventory (PackageManager): app names and versions")
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
