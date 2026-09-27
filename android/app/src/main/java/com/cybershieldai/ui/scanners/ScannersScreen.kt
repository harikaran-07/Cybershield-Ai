package com.cybershieldai.ui.scanners

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.engine.ScanRunner
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.relativeTime
import com.cybershieldai.ui.theme.*
import com.cybershieldai.utils.CyberShieldNotificationManager
import kotlinx.coroutines.launch

/**
 * SCANNERS tab (spec §5/§6): every scanner performs a REAL supported
 * operation. Phone Security Scan runs the full phased scan here; the other
 * tiles deep-link into the dedicated real scanners.
 */
@Composable
fun ScannersScreen(navController: NavHostController) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var scanning by remember { mutableStateOf(false) }
    var phase by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<ScanRunner.ScanResult?>(null) }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        Text("Scanners", style = CS.ScreenTitle, color = TextPrimary)
        Text("Every scanner performs a real check using Android-supported APIs.",
            style = CS.BodyMedium, color = TextSecondary)

        // ---------------- Phone Security Scan (runs here) ----------------
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(shape = CircleShape, color = Primary.copy(alpha = 0.15f)) {
                    Icon(Icons.Filled.PhoneAndroid, contentDescription = null,
                        tint = Primary, modifier = Modifier.padding(10.dp).size(24.dp))
                }
                Spacer(Modifier.width(Dsn.M))
                Column(Modifier.weight(1f)) {
                    Text("Phone Security Scan", style = CS.CardTitle, color = TextPrimary)
                    Text(
                        when {
                            scanning -> "Scanning: $phase"
                            result != null -> "Complete: ${result!!.itemsChecked} items · " +
                                "${result!!.warnings} warning(s) · ${result!!.highRisk} high-risk"
                            else -> "Apps · permissions · security status · threat history"
                        },
                        style = CS.Secondary, color = TextSecondary)
                }
            }
            Spacer(Modifier.height(Dsn.M))
            Button(
                onClick = {
                    if (scanning) return@Button
                    scanning = true; result = null; phase = "Starting"
                    scope.launch {
                        val r = ScanRunner.runScan(context) { p -> phase = p }
                        result = r
                        CyberShieldNotificationManager.markScanCompleted(
                            context, itemsChecked = r.itemsChecked,
                            issuesFound = r.highRisk + r.warnings)
                        scanning = false
                    }
                },
                enabled = !scanning,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(Dsn.ButtonCorner)
            ) { Text(if (scanning) "Scanning…" else "Run Phone Security Scan", style = CS.Label) }

            result?.let { r ->
                Spacer(Modifier.height(Dsn.M))
                Text("SCAN COMPLETE", style = CS.Label, color = Safe)
                Spacer(Modifier.height(Dsn.S))
                ResultLine("Items checked", "${r.itemsChecked}")
                ResultLine("Warnings", "${r.warnings}", warn = r.warnings > 0)
                ResultLine("High-risk items", "${r.highRisk}", warn = r.highRisk > 0)
                if (r.recommendations.isEmpty()) {
                    ResultLine("Recommendations", "None — no issues detected")
                } else {
                    Text("Recommendations", style = CS.CardTitle, color = TextPrimary)
                    r.recommendations.forEach {
                        Row(Modifier.padding(vertical = 2.dp)) {
                            Text("• ", color = Primary, style = CS.BodyMedium)
                            Text(it, style = CS.BodyMedium, color = TextSecondary)
                        }
                    }
                }
                if (r.appDetails.isNotEmpty()) {
                    Spacer(Modifier.height(Dsn.S))
                    Text("Flagged apps", style = CS.CardTitle, color = TextPrimary)
                    r.appDetails.take(5).forEach { app ->
                        Row(Modifier.padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.WarningAmber, contentDescription = null,
                                tint = Warning, modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(Dsn.S))
                            Text("${app.appName} — ${app.status}", style = CS.BodyMedium,
                                color = TextSecondary, modifier = Modifier.weight(1f))
                        }
                    }
                }
                // Honest Local-AI line (§2): shown ONLY when the model ran.
                if (r.aiUsed && r.aiSummary != null) {
                    Spacer(Modifier.height(Dsn.S))
                    Text("AI Analysis (on-device)", style = CS.CardTitle, color = TextPrimary)
                    Text(r.aiSummary!!, style = CS.BodyMedium, color = TextSecondary)
                } else if (!r.aiUsed) {
                    Spacer(Modifier.height(Dsn.S))
                    Text("Local AI unavailable — CyberShield completed rule-based analysis.",
                        style = CS.BodyMedium, color = TextSecondary)
                }
            }
        }

        // ---------------- Other real scanners ----------------
        ScannerLink(Icons.Filled.Sms, "SMS Scam Scanner",
            "Analyze any message text for scam patterns") {
            navController.navigate("scan") }
        ScannerLink(Icons.Filled.Link, "Link Scanner",
            "Check URLs and QR content for phishing indicators") {
            navController.navigate("scan") }
        ScannerLink(Icons.Filled.PersonSearch, "App Security Scanner",
            "Installed-app risk analysis from package metadata") {
            navController.navigate("protection") }
        ScannerLink(Icons.Filled.AdminPanelSettings, "Permission Scanner",
            "App inventory and permission guidance") {
            navController.navigate("protection") }
    }
}

@Composable
private fun ResultLine(label: String, value: String, warn: Boolean = false) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, style = CS.BodyMedium, color = TextSecondary, modifier = Modifier.weight(1f))
        Text(value, style = CS.BodyMedium,
            color = if (warn) Warning else TextPrimary, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
    }
}

@Composable
private fun ScannerLink(
    icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(Dsn.CardCorner),
        color = Surface,
        border = androidx.compose.foundation.BorderStroke(1.dp, SurfaceVariant)
    ) {
        Row(Modifier.fillMaxWidth().padding(Dsn.M), verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = CircleShape, color = Primary.copy(alpha = 0.15f)) {
                Icon(icon, contentDescription = null, tint = Primary,
                    modifier = Modifier.padding(8.dp).size(20.dp))
            }
            Spacer(Modifier.width(Dsn.M))
            Column(Modifier.weight(1f)) {
                Text(title, style = CS.CardTitle, color = TextPrimary)
                Text(subtitle, style = CS.Secondary, color = TextTertiary)
            }
            Icon(Icons.Filled.ChevronRight, contentDescription = null,
                tint = TextTertiary, modifier = Modifier.size(16.dp))
        }
    }
}
