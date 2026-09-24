package com.cybershieldai.ui.apps

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.cybershieldai.ui.components.AppIconTile
import com.cybershieldai.ui.components.LoadingView
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.StatusPill
import com.cybershieldai.ui.theme.CS
import com.cybershieldai.ui.theme.Dsn
import androidx.navigation.NavHostController
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.TextTertiary
import com.cybershieldai.ui.theme.severityColor
import kotlinx.coroutines.launch
import com.cybershieldai.utils.AppRiskAnalyzer
import com.cybershieldai.utils.AppScanCache

/**
 * App Security (spec §6/§23): the user's REAL installed applications, split
 * from system/OEM packages. Default tab = user apps; system & vendor packages
 * live under a separate tab. No Storage card (spec §1) — storage lives on Home.
 * Rows open a full detail screen with permission review.
 */
@Composable
fun AppsScreen(navController: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var loading by remember { mutableStateOf(!AppScanCache.hasData) }
    var tab by rememberSaveable { mutableStateOf(0) } // 0 = User apps, 1 = System/OEM
    var query by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(Unit) {
        val ok = AppScanCache.ensureLoaded(context, force = false)
        loading = false
        if (!ok && AppScanCache.visibilityRestricted) {
            // stays on the honest "unavailable" state below
        }
    }

    Column(
        Modifier.fillMaxSize().padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        Text("App Security", style = CS.ScreenTitle, color = com.cybershieldai.ui.theme.TextPrimary)

        TabRow(
            selectedTabIndex = tab,
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            val device = AppScanCache.deviceApps
            Tab(selected = tab == 0, onClick = { tab = 0 },
                text = { Text("User apps${device?.let { " (${it.userApps.size})" } ?: ""}", style = CS.Label) })
            Tab(selected = tab == 1, onClick = { tab = 1 },
                text = { Text("System / OEM${device?.let { " (${it.systemAndOem.size})" } ?: ""}", style = CS.Label) })
        }

        if (loading) {
            LoadingView("Reviewing installed apps…")
            return@Column
        }

        if (!AppScanCache.hasData) {
            SectionCard {
                Text("App list unavailable", style = CS.CardTitle)
                Text(
                    if (AppScanCache.visibilityRestricted)
                        "Android package visibility is restricted on this device."
                    else "No app data is available yet. Run a scan from Home.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
            return@Column
        }

        // ---- Search filter (name + package) ----
        val source = if (tab == 0) AppScanCache.userRisks else AppScanCache.systemRisks
        val results = if (query.isBlank()) source else source.filter {
            it.appName.contains(query, ignoreCase = true) ||
                it.app.packageName.contains(query, ignoreCase = true)
        }
        val filtered = query.isNotBlank()

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            placeholder = { Text("Search apps or packages", style = CS.BodyMedium, color = TextSecondary) },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null, tint = TextSecondary) },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    IconButton(onClick = { query = "" }) {
                        Icon(Icons.Filled.Close, contentDescription = "Clear search", tint = TextSecondary)
                    }
                }
            },
            shape = RoundedCornerShape(Dsn.CardCornerSm),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = com.cybershieldai.ui.theme.Primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.outline
            )
        )

        if (results.isEmpty()) {
            SectionCard {
                Text(
                    if (filtered) "No matches for \"$query\"" else "Nothing to review here",
                    style = CS.CardTitle)
                Text(
                    if (filtered) "Try a different name or package name."
                    else if (tab == 0) "No user-installed apps are visible to the scanner."
                    else "No system/OEM packages request permissions on this device.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
            return@Column
        }

        // ---- Runtime-computed summary for the selected tab ----
        val riskyCount = results.count {
            it.status == AppRiskAnalyzer.SUSPICIOUS ||
                it.status == AppRiskAnalyzer.HIGH_RISK ||
                it.status == AppRiskAnalyzer.CONFIRMED_THREAT
        }
        val reviewCount = results.count { it.status == AppRiskAnalyzer.REVIEW }
        val avgPrivacy = if (results.isEmpty()) 0 else results.sumOf { it.privacyScore } / results.size

        SectionCard {
            Text(
                if (filtered) "${results.size} match(es) for \"$query\""
                else "${results.size} ${if (tab == 0) "user apps" else "system/OEM packages"} analyzed",
                style = CS.Heading, color = com.cybershieldai.ui.theme.TextPrimary)
            Spacer(Modifier.height(Dsn.XS))
            Text(
                when {
                    filtered -> "$riskyCount flagged · $reviewCount to review in this list"
                    riskyCount == 0 && reviewCount == 0 -> "No apps require attention"
                    riskyCount == 0 -> "$reviewCount app(s) deserve a quick review"
                    else -> "$riskyCount app(s) flagged · $reviewCount to review"
                },
                style = CS.CardSecondary, color = TextSecondary)
            if (!filtered) {
                Text("avg privacy exposure $avgPrivacy/100",
                    style = CS.BodyMedium, color = TextTertiary)
                Text("A permission is not proof of spying — it is a reason to review.",
                    style = CS.Secondary, color = TextTertiary)
            }
        }

        val sorted = results.sortedWith(
            compareByDescending<AppRiskAnalyzer.AppRiskResult> { it.overallScore }
                .thenBy { it.appName.lowercase() })
        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(Dsn.S),
            modifier = Modifier.weight(1f)
        ) {
            items(sorted, key = { it.app.packageName }) {
                AppResultRow(it, onOpen = {
                    val encoded = java.net.URLEncoder.encode(it.app.packageName, "UTF-8")
                    navController.navigate("appdetail/$encoded")
                })
            }
        }
    }
}

@Composable
private fun AppResultRow(r: AppRiskAnalyzer.AppRiskResult, onOpen: () -> Unit) {
    val context = LocalContext.current
    var expanded by remember { mutableStateOf(false) }
    val colorKey = AppRiskAnalyzer.statusColorKey(r.status)

    SectionCard(modifier = Modifier.clickable(onClick = onOpen)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AppIconTile(packageName = r.app.packageName)
            Spacer(Modifier.width(Dsn.M))
            Column(Modifier.weight(1f)) {
                Text(r.appName, style = CS.CardTitle,
                    color = com.cybershieldai.ui.theme.TextPrimary)
                Text(r.app.packageName, style = CS.Secondary, color = TextSecondary,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.width(Dsn.S))
            Column(horizontalAlignment = Alignment.End) {
                // Risk score — right-aligned, prominent (spec §9)
                Text("${r.overallScore}", style = CS.ScoreSmall,
                    color = severityColor(colorKey))
                StatusPill(r.status, colorKey)
            }
        }
        Spacer(Modifier.height(Dsn.XS))
        Text(
            "Privacy ${r.privacyScore} · Sec ${r.securityScore} · Mal ${
                if (r.malwareEvidence == 0) "NONE" else "${r.malwareEvidence}"
            }" + (r.versionName?.let { " · v$it" } ?: ""),
            style = CS.Secondary, color = TextTertiary,
            maxLines = 1, overflow = TextOverflow.Ellipsis)

        if (expanded) {
            Spacer(Modifier.height(Dsn.S))
            Text("Findings", style = CS.CardTitle)
            r.findings.forEach { f ->
                Text("• $f", style = CS.BodyMedium)
            }
            if (r.grantedSensitive.isNotEmpty()) {
                Spacer(Modifier.height(Dsn.S))
                Text("Granted sensitive permissions", style = CS.CardTitle)
                Text(r.grantedSensitive.joinToString { it.substringAfterLast('.') },
                    style = CS.BodyMedium, color = TextSecondary)
            }
            Spacer(Modifier.height(Dsn.S))
            Text("Requested permissions (${r.permissions.size})", style = CS.CardTitle)
            Text(r.permissions.take(60).joinToString { it.substringAfterLast('.') } +
                    if (r.permissions.size > 60) " … (${r.permissions.size - 60} more)" else "",
                style = CS.BodyMedium, color = TextSecondary)
            Spacer(Modifier.height(Dsn.S))
            r.installSource?.let {
                Text("Install source: $it", style = CS.Secondary, color = TextTertiary)
            }
            TextButton(onClick = {
                com.cybershieldai.ui.privacy.openAppSettings(context, r.app.packageName)
            }) { Text("Open in Android Settings →", style = CS.Label) }
        }
    }
}
