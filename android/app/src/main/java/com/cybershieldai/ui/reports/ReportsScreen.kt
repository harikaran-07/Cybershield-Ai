package com.cybershieldai.ui.reports

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.data.local.CommunityReportEntity
import com.cybershieldai.data.local.DatabaseProvider
import com.cybershieldai.engine.ScanRunner
import com.cybershieldai.engine.SecurityScoreEngine
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.relativeTime
import com.cybershieldai.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * REPORTS tab (spec §9/§14): the CYBERSHIELD SECURITY REPORT (all values from
 * real application state, tap-the-score target) and MY SCAM REPORTS — the
 * user's locally-stored scam reports with View / Mark reviewed / Delete.
 */
@Composable
fun ReportsScreen(navController: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var reports by remember { mutableStateOf<List<CommunityReportEntity>>(emptyList()) }
    var detail by remember { mutableStateOf<CommunityReportEntity?>(null) }
    var reload by remember { mutableStateOf(0) }

    // Security report state (all real)
    var score by remember { mutableStateOf<Int?>(null) }
    var appsChecked by remember { mutableStateOf(0) }
    var suspiciousEvents by remember { mutableStateOf(0) }
    var lastScanAt by remember { mutableStateOf<Long?>(null) }

    LaunchedEffect(reload) {
        withContext(Dispatchers.IO) {
            try {
                reports = DatabaseProvider.get(context).communityReportDao().recent(50)
            } catch (_: Exception) { }
            try {
                score = SecurityScoreEngine.computeCurrent(context).score
            } catch (_: Exception) { }
            try {
                val dao = DatabaseProvider.get(context).securityEventDao()
                val day = System.currentTimeMillis() - 24 * 60 * 60 * 1000L
                suspiciousEvents = dao.countSince(day)
                appsChecked = com.cybershieldai.utils.AppScanCache.counts?.first ?: 0
                lastScanAt = com.cybershieldai.utils.WhatChangedStore.lastCheck(context)?.completedAt
            } catch (_: Exception) { }
        }
    }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        Text("Reports", style = CS.ScreenTitle, color = TextPrimary)

        // ---------------- CYBERSHIELD SECURITY REPORT ----------------
        SectionCard {
            Text("CYBERSHIELD SECURITY REPORT", style = CS.CardTitle, color = TextPrimary)
            Spacer(Modifier.height(Dsn.S))
            ReportRow("Protection Score", score?.let { "$it/100" } ?: "Not scanned yet")
            ReportRow("App Security", if (appsChecked > 0) "$appsChecked apps reviewed" else "Not scanned yet")
            ReportRow("Suspicious Events (24h)", "$suspiciousEvents")
            ReportRow(
                "Last Scan",
                lastScanAt?.let { SimpleDateFormat("MMM d, HH:mm", Locale.US).format(Date(it)) }
                    ?: "Never")
        }

        // ---------------- MY SCAM REPORTS ----------------
        Text("MY SCAM REPORTS", style = CS.SectionHeading, color = TextPrimary)
        if (reports.isEmpty()) {
            SectionCard {
                Text("No reports yet", style = CS.CardTitle, color = TextPrimary)
                Text("No locally-stored reports on this device.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
        } else {
            reports.forEach { r ->
                SectionCard(modifier = Modifier.padding(vertical = Dsn.XS)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(shape = CircleShape,
                            color = (if (r.status == "New") High else Safe).copy(alpha = 0.15f)) {
                            Icon(reportIcon(r.kind), contentDescription = null,
                                tint = if (r.status == "New") High else Safe,
                                modifier = Modifier.padding(8.dp).size(18.dp))
                        }
                        Spacer(Modifier.width(Dsn.M))
                        Column(Modifier.weight(1f)) {
                            Text(kindLabel(r.kind), style = CS.CardTitle, color = TextPrimary)
                            Text(
                                "Reported " + SimpleDateFormat("MMM d", Locale.US).format(Date(r.createdAt)) +
                                    " · " + r.reportType.replace('_', ' ').lowercase()
                                    .replaceFirstChar { it.uppercase() } +
                                    (if (r.note.isNotBlank()) " · ${r.note.take(30)}" else ""),
                                style = CS.Secondary, color = TextTertiary, maxLines = 2)
                        }
                        if (r.status == "New") {
                            Surface(shape = RoundedCornerShape(50), color = High.copy(alpha = 0.15f)) {
                                Text("New", style = CS.Label, color = High,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp))
                            }
                        }
                    }
                    Spacer(Modifier.height(Dsn.S))
                    Row(horizontalArrangement = Arrangement.spacedBy(Dsn.S)) {
                        TextButton(onClick = { detail = r }) { Text("View", style = CS.Label) }
                        if (r.status == "New") {
                            TextButton(onClick = {
                                scope.launch {
                                    withContext(Dispatchers.IO) {
                                        try {
                                            DatabaseProvider.get(context).communityReportDao()
                                                .setStatus(r.id, "Reviewed")
                                        } catch (_: Exception) { }
                                    }
                                    reload++
                                }
                            }) { Text("Mark reviewed", style = CS.Label, color = Safe) }
                        }
                        TextButton(onClick = {
                            scope.launch {
                                withContext(Dispatchers.IO) {
                                    try {
                                        DatabaseProvider.get(context).communityReportDao()
                                            .deleteById(r.id)
                                    } catch (_: Exception) { }
                                }
                                reload++
                            }
                        }) {
                            Icon(Icons.Filled.Delete, contentDescription = null,
                                tint = High, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Delete", style = CS.Label, color = High)
                        }
                    }
                }
            }
        }
    }

    // ---------------- Report detail dialog ----------------
    detail?.let { r ->
        AlertDialog(
            onDismissRequest = { detail = null },
            confirmButton = {
                TextButton(onClick = { detail = null }) { Text("Close") }
            },
            title = {
                Column {
                    Text(kindLabel(r.kind), style = CS.CardTitle)
                    Text(
                        SimpleDateFormat("MMM d, HH:mm", Locale.US).format(Date(r.createdAt)),
                        style = CS.Secondary, color = TextTertiary)
                }
            },
            text = {
                Column {
                    ReportRow("Value", r.value)
                    ReportRow("Type", r.reportType.replace('_', ' '))
                    ReportRow("Status", r.status)
                    if (r.note.isNotBlank()) ReportRow("Details", r.note)
                    Spacer(Modifier.height(Dsn.S))
                    Text(
                        "Stored on this device only — never uploaded. URL and app reports " +
                            "are surfaced in Alerts when related signals are detected again.",
                        style = CS.Secondary, color = TextTertiary)
                }
            }
        )
    }
}

@Composable
private fun ReportRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(label, style = CS.BodyMedium, color = TextSecondary, modifier = Modifier.weight(1f))
        Text(value, style = CS.BodyMedium, color = TextPrimary,
            fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
    }
}

private fun reportIcon(kind: String): ImageVector = when (kind) {
    "NUMBER" -> Icons.Filled.PersonSearch
    "SMS" -> Icons.Filled.Sms
    "URL" -> Icons.Filled.Link
    "APP" -> Icons.Filled.PhoneAndroid
    else -> Icons.Filled.HelpOutline
}

private fun kindLabel(kind: String) = when (kind) {
    "NUMBER" -> "Phone Number"
    "SMS" -> "SMS Message"
    "URL" -> "Website"
    "APP" -> "Application"
    else -> "Other"
}
