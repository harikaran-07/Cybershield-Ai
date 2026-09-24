package com.cybershieldai.ui.threats

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.cybershieldai.data.model.Threat
import com.cybershieldai.ui.components.*
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.severityColor
import com.cybershieldai.viewmodel.ThreatsViewModel

@Composable
fun ThreatsScreen() {
    val vm: ThreatsViewModel = viewModel()
    val state by vm.state.collectAsState()
    var detailId by remember { mutableStateOf<String?>(null) }
    var showDeleteDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { vm.load() }

    if (detailId != null) {
        ThreatDetailScreen(scanId = detailId!!, onBack = { vm.clearDetail(); detailId = null })
        return
    }

    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Threat History", style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.weight(1f))
            TextButton(onClick = { showDeleteDialog = true }) { Text("Clear") }
        }

        // Filters
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = state.severityFilter == null,
                onClick = { vm.setSeverityFilter(null) },
                label = { Text("All") })
            listOf("HIGH", "CRITICAL").forEach { sev ->
                FilterChip(
                    selected = state.severityFilter == sev,
                    onClick = { vm.setSeverityFilter(sev) },
                    label = { Text(sev) })
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("SMS", "URL", "QR", "FILE").forEach { type ->
                FilterChip(
                    selected = state.typeFilter == type,
                    onClick = { vm.setTypeFilter(if (state.typeFilter == type) null else type) },
                    label = { Text(type) })
            }
        }

        when {
            state.loading -> LoadingView("Loading history…")
            state.error != null -> ErrorView(state.error!!)
            state.threats.isEmpty() -> SectionCard {
                Text("No threats recorded yet.",
                    color = TextSecondary, style = MaterialTheme.typography.bodyLarge)
            }
            else -> LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(state.threats, key = { it.scanId }) { threat ->
                    ThreatRow(threat) { detailId = threat.scanId }
                }
            }
        }
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete scan history?") },
            text = { Text("This removes all scans, events, and chains stored on this device. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    vm.deleteHistory { }
                    showDeleteDialog = false
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { showDeleteDialog = false }) { Text("Cancel") } }
        )
    }
}

@Composable
fun ThreatRow(threat: Threat, onClick: () -> Unit) {
    SectionCard(modifier = Modifier.clickable(onClick = onClick)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(threat.classification, fontWeight = FontWeight.Bold,
                    color = severityColor(threat.severity))
                Text("${threat.type} · ${threat.createdAt ?: ""} · confidence ${"%.0f".format(threat.confidence * 100)}%",
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
            SeverityChip(threat.severity)
            Spacer(Modifier.width(6.dp))
            Text("${threat.riskScore}", fontWeight = FontWeight.Bold)
        }
        if (threat.indicators.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Text(threat.indicators.first(), style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary, maxLines = 1)
        }
    }
}

// ---------------------------------------------------------------------------
// Detail screen
// ---------------------------------------------------------------------------
@Composable
fun ThreatDetailScreen(scanId: String, onBack: () -> Unit) {
    val vm: ThreatsViewModel = viewModel()
    val detail by vm.detail.collectAsState()
    var reviewed by remember { mutableStateOf(false) }

    LaunchedEffect(scanId) { vm.loadDetail(scanId) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        TextButton(onClick = onBack) { Text("← Back") }

        if (detail == null) {
            LoadingView("Loading details…")
            return
        }
        val d = detail!!

        SectionCard {
            Text("${d.classification} DETECTED", style = MaterialTheme.typography.headlineMedium,
                color = severityColor(d.severity))
            Spacer(Modifier.height(12.dp))
            RiskScoreGauge(d.riskScore, d.severity, Modifier.fillMaxWidth())
            Spacer(Modifier.height(12.dp))
            Row {
                Text("Confidence", style = MaterialTheme.typography.labelMedium,
                    color = TextSecondary, modifier = Modifier.weight(1f))
                Text("Detected by", style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
            Row {
                Text("${"%.0f".format(d.confidence * 100)}%",
                    style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                Text(d.detectionMethods.joinToString(" · "),
                    style = MaterialTheme.typography.bodyLarge)
            }
        }

        SectionCard {
            Text("Why?", style = MaterialTheme.typography.titleMedium)
            IndicatorList(d.indicators)
        }

        if (d.correlatedChain != null) {
            SectionCard {
                Text("Correlated Threat Chain", style = MaterialTheme.typography.titleMedium)
                Text(d.correlatedChain!!.chainTypes.joinToString(" → "),
                    style = MaterialTheme.typography.bodyLarge,
                    color = severityColor(d.correlatedChain!!.severity))
                Spacer(Modifier.height(6.dp))
                Text(d.correlatedChain!!.explanation,
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
        }

        if (d.timeline.isNotEmpty()) {
            SectionCard {
                Text("Timeline", style = MaterialTheme.typography.titleMedium)
                d.timeline.forEach { e ->
                    Row(Modifier.padding(vertical = 3.dp)) {
                        Text("${e.time.take(19)}  ", style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary)
                        Text("${e.eventType} (${e.riskScore})",
                            style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        SectionCard {
            Text("AI Explanation", style = MaterialTheme.typography.titleMedium)
            Text(
                d.aiExplanation
                    ?: "AI explanation is temporarily unavailable. The security detection result is still available.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }

        SectionCard {
            Text("Recommended action", style = MaterialTheme.typography.titleMedium)
            Text(d.recommendation, style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(10.dp))
            Button(onClick = { reviewed = true }, enabled = !reviewed,
                   modifier = Modifier.fillMaxWidth()) {
                Text(if (reviewed) "✓ Marked as Reviewed" else "Mark as Reviewed")
            }
        }
    }
}
