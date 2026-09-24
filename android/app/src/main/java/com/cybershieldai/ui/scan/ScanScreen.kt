package com.cybershieldai.ui.scan

import android.Manifest
import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.cybershieldai.data.local.SettingsStore
import com.cybershieldai.data.repository.ScanRepository
import com.cybershieldai.ui.components.*
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.severityColor
import com.cybershieldai.utils.UrlSecurity
import com.cybershieldai.viewmodel.ScanUiState
import com.cybershieldai.viewmodel.ScanViewModel

@Composable
fun ScanScreen(initialSharedText: String? = null) {
    val tabs = listOf("Message", "URL", "QR")
    var selected by remember { mutableStateOf(0) }
    var initialShared by remember { mutableStateOf(initialSharedText) }
    val context = LocalContext.current

    // Honest engine status (§2/§14): LOCAL only when the model file exists.
    var aiEngine by remember {
        mutableStateOf("Local LLM unavailable — Rule Engine active")
    }
    LaunchedEffect(Unit) {
        aiEngine = if (com.cybershieldai.ai.AiModelManager.isInstalled(context))
            "Local" else "Local LLM unavailable — Rule Engine active"
    }

    Column(Modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = selected, containerColor = MaterialTheme.colorScheme.surface) {
            tabs.forEachIndexed { i, title ->
                Tab(selected = selected == i, onClick = { selected = i }, text = { Text(title) })
            }
        }
        AiEngineChip()
        when (selected) {
            0 -> MessageScanTab(sharedText = initialShared, onSharedConsumed = { initialShared = null })
            1 -> UrlScanTab()
            2 -> QrScanTab()
        }
    }
}

/** AI Engine chip shown under the tabs (honest per §2). */
@Composable
fun AiEngineChip() {
    val context = LocalContext.current
    var ready by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(Unit) {
        ready = com.cybershieldai.ai.AiModelManager.isInstalled(context)
    }
    Row(
        Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            when (ready) {
                true -> "AI Engine: Local"
                false -> "AI Engine: Local LLM unavailable — Rule Engine active"
                null -> "AI Engine: checking…"
            },
            style = MaterialTheme.typography.labelSmall,
            color = if (ready == true) MaterialTheme.colorScheme.primary else TextSecondary
        )
    }
}

// ---------------------------------------------------------------------------
// Message scanner
// ---------------------------------------------------------------------------
@Composable
fun MessageScanTab(sharedText: String?, onSharedConsumed: () -> Unit) {
    val vm: ScanViewModel = viewModel()
    val state by vm.state.collectAsState()
    var text by remember { mutableStateOf("") }
    val context = LocalContext.current
    val autoScan by remember { SettingsStore(context) }.autoScanShares
        .collectAsState(initial = true)

    // Receive text shared from other apps (SMS/chat apps → share → CyberShield)
    LaunchedEffect(sharedText) {
        if (sharedText != null && text.isBlank() && autoScan) {
            text = sharedText
            onSharedConsumed()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Paste a message, SMS, or email text to analyze.",
            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        OutlinedTextField(
            value = text, onValueChange = { text = it },
            modifier = Modifier.fillMaxWidth().height(140.dp),
            placeholder = { Text("Paste message text here…") },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary)
        )
        Button(
            onClick = { vm.scanMessage(text) },
            enabled = text.isNotBlank() && state !is ScanUiState.Loading,
            modifier = Modifier.fillMaxWidth()
        ) { Text("Analyze Message") }

        ScanResultView(state)
    }
}

// ---------------------------------------------------------------------------
// URL scanner — dedicated phishing pipeline (URL-scanner spec §12-§17)
// ---------------------------------------------------------------------------
@Composable
fun UrlScanTab() {
    val vm: ScanViewModel = viewModel()
    val urlState by vm.urlState.collectAsState()
    var url by remember { mutableStateOf("") }
    val scanning = urlState.phase != null

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("URLs are analyzed as text and never opened.",
            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        OutlinedTextField(
            value = url, onValueChange = { url = it; vm.clearUrlError() },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Paste a URL to check") },
            singleLine = true,
            isError = urlState.error != null,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary)
        )
        urlState.error?.let {
            Text("⚠ $it", color = com.cybershieldai.ui.theme.High,
                style = MaterialTheme.typography.bodyMedium)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = { vm.scanUrlDetailed(url, full = false) },
                enabled = url.isNotBlank() && !scanning,
                modifier = Modifier.weight(1f)
            ) { Text("Scan URL") }
            OutlinedButton(
                onClick = { vm.scanUrlDetailed(url, full = true) },
                enabled = url.isNotBlank() && !scanning,
                modifier = Modifier.weight(1f)
            ) { Text("Run Full Scan") }
        }

        when {
            scanning -> LoadingView(urlState.phase ?: "Analyzing…")
            urlState.result != null -> UrlResultView(
                outcome = urlState.result!!,
                onRescan = { vm.rescanUrl() },
                onFullScan = { vm.runFullScan() },
                busy = scanning)
        }
    }

    // Clear the shared pipeline state so both flows never fight over one screen.
    LaunchedEffect(Unit) { vm.reset() }
}

/** Result page (§12-§13): score, badge, recommendation, per-signal cards. */
@Composable
fun UrlResultView(
    outcome: ScanRepository.UrlScanOutcome,
    onRescan: () -> Unit,
    onFullScan: () -> Unit,
    busy: Boolean
) {
    val r = outcome.urlResult
    val accent = severityColor(r.severity)

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionCard {
            Text("SECURITY RESULT", style = MaterialTheme.typography.labelMedium,
                color = TextSecondary)
            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Risk Score", style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f))
                Text("${r.riskScore}/100", style = MaterialTheme.typography.titleLarge,
                    color = accent)
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Surface(shape = RoundedCornerShape(50), color = accent.copy(alpha = 0.16f)) {
                    Text(r.classification, color = accent,
                        style = MaterialTheme.typography.labelLarge,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp))
                }
                if (outcome.detectionMethods.isNotEmpty()) {
                    Text("Detected by: ${outcome.detectionMethods.joinToString()}",
                        style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                }
            }
            Spacer(Modifier.height(10.dp))
            // Hard-rule labels (§UI LABELS): the engine decided, the LLM only
            // explains. Both rows always render so the split stays visible.
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("✓", color = com.cybershieldai.ui.theme.Safe)
                Text("SECURITY ENGINE — URL analysis completed",
                    style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(if (outcome.aiNote != null) "✓" else "○",
                    color = if (outcome.aiNote != null) com.cybershieldai.ui.theme.Safe
                    else TextSecondary)
                Text(
                    if (outcome.aiNote != null) "LOCAL AI — explanation generated"
                    else "LOCAL AI — AI explanation unavailable (engine result unchanged)",
                    style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
            outcome.aiNote?.let {
                Spacer(Modifier.height(10.dp))
                Text("Explanation by Local AI", style = MaterialTheme.typography.titleMedium)
                Text(it, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
        }

        SectionCard {
            Text("Security Signals", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            r.signals.forEach { SignalCard(it) }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(onClick = onRescan, enabled = !busy, modifier = Modifier.weight(1f)) {
                Text("Rescan")
            }
            OutlinedButton(onClick = onFullScan, enabled = !busy, modifier = Modifier.weight(1f)) {
                Text("Run Full Scan")
            }
        }
    }
}

/** One signal card (§13): ✓ / ⚠ / ✕ icon, title, honest description. */
@Composable
fun SignalCard(signal: UrlSecurity.Signal) {
    val (icon, color) = when (signal.status) {
        UrlSecurity.Status.SAFE -> "✓" to com.cybershieldai.ui.theme.Safe
        UrlSecurity.Status.WARNING -> "⚠" to com.cybershieldai.ui.theme.Warning
        UrlSecurity.Status.DANGER -> "✕" to com.cybershieldai.ui.theme.High
        UrlSecurity.Status.UNKNOWN -> "•" to TextSecondary
    }
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = androidx.compose.ui.graphics.Color.Transparent,
        border = androidx.compose.foundation.BorderStroke(1.dp, color.copy(alpha = 0.35f)),
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
            Text(icon, color = color, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.width(10.dp))
            Column {
                Text(signal.title, style = MaterialTheme.typography.titleSmall,
                    color = if (signal.status == UrlSecurity.Status.SAFE)
                        TextSecondary else color)
                Spacer(Modifier.height(2.dp))
                Text(signal.description, style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// QR scanner (ML Kit)
// ---------------------------------------------------------------------------
@Composable
fun QrScanTab() {
    QrScannerScreen()
}

// ---------------------------------------------------------------------------
// Shared result rendering
// ---------------------------------------------------------------------------
@Composable
fun ScanResultView(state: ScanUiState) {
    when (state) {
        is ScanUiState.Idle -> {}
        is ScanUiState.Loading -> LoadingView("Analyzing…")
        is ScanUiState.Failure -> {
            ErrorView(state.message)
            state.offlineResult?.let { ResultCard(it, online = false) }
        }
        is ScanUiState.Result -> ResultCard(state.result, state.online)
    }
}

@Composable
fun ResultCard(result: com.cybershieldai.data.model.AnalysisResponse, online: Boolean) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(result.classification,
                    style = MaterialTheme.typography.titleLarge,
                    color = com.cybershieldai.ui.theme.severityColor(result.severity),
                    modifier = Modifier.weight(1f))
                SeverityChip(result.severity)
            }
            Spacer(Modifier.height(10.dp))
            RiskScoreGauge(result.riskScore, result.severity,
                modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(10.dp))
            Text("Detected by: ${result.detectionMethods.joinToString()}",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            Text("Why?", style = MaterialTheme.typography.titleMedium)
            IndicatorList(result.indicators)
            Spacer(Modifier.height(8.dp))
            Text("Recommended action", style = MaterialTheme.typography.titleMedium)
            Text(result.recommendation, style = MaterialTheme.typography.bodyLarge)
            result.aiExplanation?.let { ai ->
                Spacer(Modifier.height(10.dp))
                Text("AI Analysis (on-device)", style = MaterialTheme.typography.titleMedium)
                Text(ai, style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary)
            } ?: Text(
                "Local AI unavailable — CyberShield completed rule-based analysis.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }
    }
}
