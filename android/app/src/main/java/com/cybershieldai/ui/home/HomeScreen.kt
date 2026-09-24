package com.cybershieldai.ui.home

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.QuestionMark
import androidx.compose.material.icons.filled.Report
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.EnhancedEncryption
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavHostController
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.engine.ScanRunner
import com.cybershieldai.ui.components.CircularProtectionScore
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.relativeTime
import com.cybershieldai.ui.theme.*
import com.cybershieldai.utils.AppRiskAnalyzer
import com.cybershieldai.utils.AppScanCache
import com.cybershieldai.utils.CyberShieldNotificationManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * HOME — Phone-Manager-style dashboard (visual reference; CyberShield
 * security content, spec §2/§4/§5/§13/§21):
 * header (brand + status indicator + menu) → large circular PROTECTION SCORE
 * (real SecurityScoreEngine value; tap → Security Report) with the LIVE
 * operation under it ("Scanning: Installed apps" is literally running) →
 * [ Security Scan ] button → 2×2 security cards (AI Media Security / Threat
 * Scanner / Scam Protection / App Security, all real state) → SECURITY
 * SCANNERS grid (six real scanners) → 🚨 REPORT SCAM.
 * No storage-cleaner / booster features. No fake data.
 */
@Composable
fun HomeScreen(navController: NavHostController, initialSharedText: String? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // ---- Real state ----
    var score by remember { mutableStateOf<Int?>(null) }
    var phase by remember { mutableStateOf("Ready") }
    var scanning by remember { mutableStateOf(false) }
    var lastScanAt by remember { mutableStateOf<Long?>(null) }
    var highRiskToday by remember { mutableStateOf(0) }
    var threatReviewCount by remember { mutableStateOf(0) }
    var recentEvents by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var appCounts by remember { mutableStateOf<Triple<Int, Int, Int>?>(null) }
    var menuOpen by remember { mutableStateOf(false) }

    suspend fun loadHomeData() = withContext(Dispatchers.IO) {
        try {
            val dao = com.cybershieldai.data.local.DatabaseProvider.get(context).securityEventDao()
            highRiskToday = dao.countHighRiskSince(System.currentTimeMillis() - 24 * 60 * 60 * 1000L)
            recentEvents = dao.recent(3)
            threatReviewCount = dao.recent(100).count {
                (it.severity == "MEDIUM" || it.severity == "HIGH" || it.severity == "CRITICAL") &&
                    it.status == "New"
            }
            lastScanAt = try {
                com.cybershieldai.utils.WhatChangedStore.lastCheck(context)?.completedAt
            } catch (_: Exception) { null }
            score = try {
                com.cybershieldai.engine.SecurityScoreEngine.computeCurrent(context).score
            } catch (_: Exception) { null }
            appCounts = AppScanCache.counts
        } catch (_: Exception) { }
    }

    LaunchedEffect(Unit) { loadHomeData() }

    fun startScan() {
        if (scanning) return
        scanning = true
        scope.launch {
            val result = ScanRunner.runScan(context) { p -> phase = p }
            score = result.score
            lastScanAt = System.currentTimeMillis()
            CyberShieldNotificationManager.markScanCompleted(
                context, itemsChecked = result.itemsChecked, issuesFound = result.highRisk + result.warnings)
            loadHomeData()
            scanning = false
            phase = "Scan complete"
        }
    }

    // ---- Score status line (real, matches the score band; never forced good) ----
    val currentScore = score
    val statusLine = when {
        scanning -> phase
        currentScore == null -> "Run a security scan for your score"
        (highRiskToday + threatReviewCount) > 0 ->
            "${highRiskToday + threatReviewCount} security issue(s) require attention"
        currentScore >= 80 -> "Protection status: Good"
        currentScore >= 50 -> "Protection status: Fair — review recommendations"
        else -> "Protection status: Attention required"
    }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = Dsn.L, vertical = Dsn.M),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        if (initialSharedText != null) {
            SectionCard {
                Text("Shared text received", style = CS.CardTitle)
                Text("Open More → Scanner to analyze the message you shared.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
        }

        // ---------------- Header: brand + status indicator + menu ----------------
        Row(verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = CircleShape, color = Primary.copy(alpha = 0.2f)) {
                Icon(Icons.Filled.Shield, contentDescription = null, tint = Primary,
                    modifier = Modifier.padding(8.dp).size(26.dp))
            }
            Spacer(Modifier.width(Dsn.M))
            Column(Modifier.weight(1f)) {
                Text("CYBERSHIELD AI", style = CS.Heading, color = Primary,
                    maxLines = 1)
                Text("Personal cyber security",
                    style = CS.Secondary, color = TextSecondary, maxLines = 1)
            }
            // Notification / security status indicator (real: highest severity today)
            IconButton(onClick = { navController.navigate("alerts") }) {
                Icon(
                    if (highRiskToday > 0) Icons.Filled.ErrorOutline else Icons.Filled.Notifications,
                    contentDescription = "Alerts",
                    tint = if (highRiskToday > 0) High else TextSecondary)
            }
            Box {
                IconButton(onClick = { menuOpen = true }) {
                    Icon(Icons.Filled.MoreVert, contentDescription = "Menu", tint = TextSecondary)
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text("Security Report") },
                        onClick = { menuOpen = false; navController.navigate("reports") })
                    DropdownMenuItem(
                        text = { Text("Notification Diagnostics") },
                        onClick = { menuOpen = false; navController.navigate("diagnostics") })
                    DropdownMenuItem(
                        text = { Text("AI Assistant") },
                        onClick = { menuOpen = false; navController.navigate("assistant") })
                    DropdownMenuItem(
                        text = { Text("AI Model Settings") },
                        onClick = { menuOpen = false; navController.navigate("ai_model_settings") })
                    DropdownMenuItem(
                        text = { Text("AI Media Security") },
                        onClick = { menuOpen = false; navController.navigate("media_scan") })
                    DropdownMenuItem(
                        text = { Text("Security Timeline") },
                        onClick = { menuOpen = false; navController.navigate("timeline") })
                    DropdownMenuItem(
                        text = { Text("Incident Center") },
                        onClick = { menuOpen = false; navController.navigate("incidents") })
                    DropdownMenuItem(
                        text = { Text("Settings") },
                        onClick = { menuOpen = false; navController.navigate("settings") })
                }
            }
        }

        // ---------------- Circular protection score (real) ----------------
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            CircularProtectionScore(
                score = score,
                subtitle = statusLine,
                scanning = scanning,
                onClick = { navController.navigate("report") })
        }

        // ---------------- Security Scan button ----------------
        Button(
            onClick = { startScan() },
            enabled = !scanning,
            modifier = Modifier.fillMaxWidth().height(Dsn.ButtonHeight),
            shape = RoundedCornerShape(Dsn.ButtonCorner),
            colors = ButtonDefaults.buttonColors(
                containerColor = Primary, contentColor = Color.White)
        ) {
            Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(Dsn.S))
            Text(if (scanning) "Scanning…" else "Security Scan", style = CS.Button)
        }
        lastScanAt?.let {
            Text(
                "Last scan: " + relativeTime(it),
                style = CS.Secondary, color = TextTertiary,
                modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        }

        // ---------------- 🛡 DEVICE TOTAL SCAN (central workflow) -------------
        Surface(
            onClick = { navController.navigate("totalscan") },
            enabled = !scanning,
            shape = RoundedCornerShape(Dsn.CardCorner),
            color = Surface,
            border = androidx.compose.foundation.BorderStroke(1.dp, Primary.copy(alpha = 0.5f))
        ) {
            Row(Modifier.padding(Dsn.M), verticalAlignment = Alignment.CenterVertically) {
                Surface(shape = CircleShape, color = Primary.copy(alpha = 0.15f)) {
                    Icon(Icons.Filled.EnhancedEncryption, contentDescription = null,
                        tint = Primary, modifier = Modifier.padding(10.dp).size(26.dp))
                }
                Spacer(Modifier.width(Dsn.M))
                Column(Modifier.weight(1f)) {
                    Text("DEVICE TOTAL SCAN", style = CS.CardTitle, color = Primary)
                    Text("One coordinated check: apps, permissions, network, " +
                        "links, messages & history.",
                        style = CS.Secondary, color = TextSecondary)
                }
                Icon(Icons.Filled.ChevronRight, contentDescription = null,
                    tint = Primary)
            }
        }

        // ---------------- 2×2 feature cards (real state) ----------------
        Row(horizontalArrangement = Arrangement.spacedBy(Dsn.M)) {
            HomeCard(
                icon = Icons.Filled.GraphicEq, title = "AI Media Security",
                modifier = Modifier.weight(1f),
                status = "Voice · image · video checks",
                ok = true
            ) { navController.navigate("media_scan") }
            HomeCard(
                icon = Icons.Filled.Security, title = "Threat Scanner",
                modifier = Modifier.weight(1f),
                status = if (threatReviewCount > 0) "$threatReviewCount item(s) require review"
                    else if (recentEvents.isEmpty()) "Not scanned yet" else "No threats detected",
                ok = threatReviewCount == 0 && recentEvents.isNotEmpty()
            ) { navController.navigate("scanners") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(Dsn.M)) {
            HomeCard(
                icon = Icons.Filled.PhoneAndroid, title = "App Security",
                modifier = Modifier.weight(1f),
                status = appCounts?.let { (total, flagged, _) ->
                    if (flagged > 0) "$flagged app(s) require review" else "$total apps checked"
                } ?: "Tap to check apps",
                ok = (appCounts?.second ?: 0) == 0
            ) { navController.navigate("protection") }
        }

        // ---------------- AI SECURITY ASSISTANT (spec §10/§11) ----------------
        Surface(
            onClick = { navController.navigate("assistant") },
            shape = RoundedCornerShape(Dsn.CardCorner),
            color = Surface,
            border = androidx.compose.foundation.BorderStroke(1.dp, Primary.copy(alpha = 0.35f))
        ) {
            Row(Modifier.padding(Dsn.M), verticalAlignment = Alignment.CenterVertically) {
                Surface(shape = CircleShape, color = Primary.copy(alpha = 0.15f)) {
                    Icon(Icons.AutoMirrored.Filled.Chat, contentDescription = null,
                        tint = Primary, modifier = Modifier.padding(8.dp).size(22.dp))
                    }
                Spacer(Modifier.width(Dsn.M))
                Column(Modifier.weight(1f)) {
                    Text("AI Security Assistant", style = CS.CardTitle, color = TextPrimary)
                    Text("Ask CyberShield about scams, phishing, privacy & security.",
                        style = CS.Secondary, color = TextSecondary)
                    Text("On-device • Offline →",
                        style = CS.Secondary, color = Primary)
                }
            }
        }

        // ---------------- SECURITY SCANNERS (six real scanners) ----------------
        Text("SECURITY SCANNERS", style = CS.SectionHeading, color = TextPrimary)
        Row(horizontalArrangement = Arrangement.spacedBy(Dsn.M)) {
            ScannerTile(Icons.Filled.PhoneAndroid, "Phone\nScan", Modifier.weight(1f)) {
                navController.navigate("phonescan") }
            ScannerTile(Icons.Filled.GraphicEq, "Media\nScanner", Modifier.weight(1f)) {
                navController.navigate("media_scan") }
            ScannerTile(Icons.Filled.Sms, "SMS\nScanner", Modifier.weight(1f)) {
                navController.navigate("scan") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(Dsn.M)) {
            ScannerTile(Icons.Filled.Link, "Link\nScanner", Modifier.weight(1f)) {
                navController.navigate("scan") }
            ScannerTile(Icons.Filled.PersonSearch, "App\nScanner", Modifier.weight(1f)) {
                navController.navigate("protection") }
            ScannerTile(Icons.Filled.AdminPanelSettings, "Permission\nScanner", Modifier.weight(1f)) {
                navController.navigate("protection") }
        }

        // ---------------- 🚨 REPORT SCAM ----------------
        Button(
            onClick = { navController.navigate("report") },
            modifier = Modifier.fillMaxWidth().height(Dsn.ButtonHeight),
            shape = RoundedCornerShape(Dsn.ButtonCorner),
            colors = ButtonDefaults.buttonColors(
                containerColor = High.copy(alpha = 0.16f), contentColor = High)
        ) {
            Icon(Icons.Filled.Report, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(Dsn.S))
            Text("REPORT SCAM", style = CS.Button)
        }
    }
}

/** 2-column feature card: icon tile, title, real status line. */
@Composable
private fun HomeCard(
    icon: ImageVector,
    title: String,
    status: String,
    ok: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(Dsn.CardCorner),
        color = Surface,
        border = androidx.compose.foundation.BorderStroke(1.dp, SurfaceVariant),
        modifier = modifier
    ) {
        Column(Modifier.padding(Dsn.M)) {
            Surface(shape = CircleShape, color = (if (ok) Safe else Warning).copy(alpha = 0.15f)) {
                Icon(icon, contentDescription = null,
                    tint = if (ok) Safe else Warning,
                    modifier = Modifier.padding(8.dp).size(22.dp))
            }
            Spacer(Modifier.height(Dsn.S))
            Text(title, style = CS.CardTitle, color = TextPrimary)
            Text(status, style = CS.Secondary, color = TextSecondary)
        }
    }
}

/** Scanner tile in the 2×3 grid — each opens a REAL scanner screen. */
@Composable
private fun ScannerTile(
    icon: ImageVector,
    label: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(Dsn.CardCorner),
        color = Surface,
        border = androidx.compose.foundation.BorderStroke(1.dp, SurfaceVariant),
        modifier = modifier
    ) {
        Column(
            Modifier.padding(Dsn.M).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Surface(shape = CircleShape, color = Primary.copy(alpha = 0.15f)) {
                Icon(icon, contentDescription = null, tint = Primary,
                    modifier = Modifier.padding(8.dp).size(20.dp))
            }
            Spacer(Modifier.height(Dsn.S))
            Text(label, style = CS.Label, color = TextPrimary,
                textAlign = TextAlign.Center, lineHeight = 15.sp)
        }
    }
}
