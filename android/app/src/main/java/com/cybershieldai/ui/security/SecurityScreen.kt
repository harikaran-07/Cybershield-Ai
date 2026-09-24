package com.cybershieldai.ui.security

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.cybershieldai.ui.components.*
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.severityColor
import com.cybershieldai.viewmodel.SecurityViewModel

@Composable
fun SecurityScreen() {
    val context = LocalContext.current
    val vm: SecurityViewModel = viewModel()
    val appState by vm.appState.collectAsState()
    val netState by vm.netState.collectAsState()

    LaunchedEffect(Unit) {
        vm.loadAppSecurity(context)
        vm.loadNetworkSecurity()
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("Security", style = MaterialTheme.typography.headlineMedium)

        // ---------------- App permissions overview ----------------
        Text("App Security", style = MaterialTheme.typography.titleMedium)
        when (val s = appState) {
            is SecurityViewModel.AppState.Idle -> {}
            is SecurityViewModel.AppState.Loading -> LoadingView("Reviewing installed apps…")
            is SecurityViewModel.AppState.Unavailable -> ErrorView(s.reason)
            is SecurityViewModel.AppState.Error -> ErrorView(s.message)
            is SecurityViewModel.AppState.Ready -> {
                SectionCard {
                    Text("Installed apps reviewed: ${s.result.summary.totalApps}",
                        style = MaterialTheme.typography.bodyLarge)
                    Text("Apps with elevated privacy flags: ${s.result.summary.riskyCount}",
                        style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                    Spacer(Modifier.height(8.dp))
                    Text(s.result.disclaimer,
                        style = MaterialTheme.typography.labelMedium, color = TextSecondary)
                }
                // On-device AI explanation of the riskiest app (§7) — evidence-only.
                val aiSummary by vm.appAiSummary.collectAsState()
                LaunchedEffect(s.result.summary.totalApps) {
                    vm.loadAppAiSummary(context)
                }
                aiSummary?.let { ai ->
                    SectionCard {
                        Text(
                            if (ai.fromLlm) "AI Analysis — ${ai.appName} (on-device)"
                            else "Permission review — ${ai.appName}",
                            style = MaterialTheme.typography.titleMedium)
                        Text(ai.text,
                            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                    }
                }
                val risky = s.result.apps.filter { it.label != "SAFE" }
                    .sortedByDescending { it.riskScore }.take(10)
                LazyColumn(modifier = Modifier.height(320.dp),
                           verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(risky, key = { it.packageName }) { app ->
                        AppRiskRow(app)
                    }
                }
            }
        }

        // ---------------- Network overview ----------------
        Text("Network Security", style = MaterialTheme.typography.titleMedium)
        when (val n = netState) {
            is SecurityViewModel.NetState.Idle -> {}
            is SecurityViewModel.NetState.Loading -> LoadingView("Checking traffic metadata…")
            is SecurityViewModel.NetState.Unavailable -> SectionCard {
                Text(n.reason, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
            is SecurityViewModel.NetState.Error -> ErrorView(n.message)
            is SecurityViewModel.NetState.Ready -> SectionCard {
                Text(n.analysis.verdict, style = MaterialTheme.typography.titleLarge,
                    color = severityColor(
                        when (n.analysis.verdict) {
                            "ANOMALOUS" -> "CRITICAL"; "SUSPICIOUS" -> "HIGH"; else -> "SAFE"
                        }))
                Text("Anomaly score: ${"%.2f".format(n.analysis.anomalyScore)}",
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                if (n.analysis.flaggedDestinations.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text("Flagged destinations:", style = MaterialTheme.typography.titleMedium)
                    IndicatorList(n.analysis.flaggedDestinations)
                }
                n.analysis.notes.forEach { note ->
                    Text("• $note", style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary)
                }
                Spacer(Modifier.height(6.dp))
                Text("Metadata-only analysis. Message contents, passwords, and authentication data are never inspected or stored.",
                    style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
        }

        // ---------------- Device security info ----------------
        SectionCard {
            Text("Device Security", style = MaterialTheme.typography.titleMedium)
            Text("• Install apps only from trusted stores",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Text("• Keep your OS updated for the latest security patches",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Text("• Review app permissions regularly in Android Settings",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Text("• Use a screen lock and enable device encryption",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }

        // ---------------- Cookie security (honest availability note) --------
        SectionCard {
            Text("Cookie Security", style = MaterialTheme.typography.titleMedium)
            Text("Cookie inspection is unavailable for this browser. " +
                 "CyberShield never bypasses browser security to read cookies. " +
                 "When a browser integration is available, we check Secure, HttpOnly, SameSite, and expiry attributes only.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }
    }
}

@Composable
fun AppRiskRow(app: com.cybershieldai.data.model.AppAnalysis) {
    SectionCard {
        Row {
            Column(Modifier.weight(1f)) {
                Text(app.appName ?: app.packageName,
                    style = MaterialTheme.typography.titleMedium)
                Text(app.packageName, style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary)
            }
            Column(horizontalAlignment = androidx.compose.ui.Alignment.End) {
                Text("${app.riskScore}", style = MaterialTheme.typography.titleLarge,
                    color = severityColor(
                        when (app.label) { "RISKY" -> "HIGH"; "CAUTION" -> "MEDIUM"; else -> "SAFE" }))
                Text(app.label, style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
        }
        val highPerms = app.permissions.filter { it.category == "HIGH" }.take(3)
        if (highPerms.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            highPerms.forEach { p ->
                Text("• ${p.permission.substringAfterLast(".")} (high risk)",
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
        }
    }
}
