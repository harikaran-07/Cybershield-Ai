package com.cybershieldai.ui.totalscan

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.engine.TotalScanEngine
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.*
import kotlinx.coroutines.launch

/** Screen state: idle → running(phase) → done(result). */
private sealed interface Ui {
    data object Idle : Ui
    data class Running(val phase: String) : Ui
    data class Done(val result: TotalScanEngine.TotalResult) : Ui
}

/**
 * 🛡 DEVICE TOTAL SCAN (spec §1/§5/§6/§7) — the central security workflow:
 * live phase progress → honest per-module results → deterministic score with
 * explainable deltas → transparent correlations → required actions with
 * deep-link "Fix" routes → explanation-only Local AI. Nothing fabricated;
 * unsupported modules are marked unavailable, not hidden.
 */
@Composable
fun TotalScanScreen(navController: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var ui by remember { mutableStateOf<Ui>(Ui.Idle) }

    fun start() {
        if (ui is Ui.Running) return
        ui = Ui.Running(TotalScanEngine.PHASES.first())
        scope.launch {
            val result = TotalScanEngine.run(context) { phase -> ui = Ui.Running(phase) }
            ui = Ui.Done(result)
        }
    }

    // Auto-start on first entry (the dashboard card opened this screen).
    LaunchedEffect(Unit) { if (ui is Ui.Idle) start() }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { navController.popBackStack() }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back", tint = TextSecondary)
            }
            Text("Device Total Scan", style = CS.Heading, color = TextPrimary,
                modifier = Modifier.weight(1f))
        }

        when (val s = ui) {
            is Ui.Idle -> {}
            is Ui.Running -> {
                // ---------------- Live progress (§1) --------------------------
                Card(Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(Dsn.CardCorner)) {
                    Column(
                        Modifier.fillMaxWidth().background(
                            Brush.verticalGradient(listOf(
                                Primary.copy(alpha = 0.18f),
                                androidx.compose.ui.graphics.Color.Transparent)))
                            .padding(Dsn.L),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(44.dp),
                            color = Primary, strokeWidth = 4.dp)
                        Spacer(Modifier.height(Dsn.M))
                        Text("🛡 Device Total Scan", style = CS.CardTitle, color = TextPrimary)
                        Spacer(Modifier.height(Dsn.S))
                        Text(s.phase, style = CS.Body, color = Primary)
                        Spacer(Modifier.height(Dsn.M))
                        Text(
                            "CyberShield only checks what Android exposes to it — " +
                                "no private app data is accessed.",
                            style = CS.Secondary, color = TextSecondary,
                            textAlign = TextAlign.Center)
                    }
                }
            }
            is Ui.Done -> {
                val r = s.result

                // ---------------- Result header (§7) --------------------------
                Card(Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(Dsn.CardCorner)) {
                    Column(
                        Modifier.fillMaxWidth().background(
                            Brush.verticalGradient(listOf(
                                (if (r.highRisk > 0) High else if (r.warnings > 0) Warning else Safe)
                                    .copy(alpha = 0.18f),
                                androidx.compose.ui.graphics.Color.Transparent)))
                            .padding(Dsn.L),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            if (r.highRisk > 0) "⚠ ACTION REQUIRED"
                            else if (r.warnings > 0) "⚠ REVIEW RECOMMENDED"
                            else "🟢 DEVICE SECURITY LOOKS GOOD",
                            style = CS.CardTitle, color = TextPrimary)
                        Spacer(Modifier.height(Dsn.S))
                        r.score?.let { score ->
                            Text("$score / 100", style = CS.ScreenTitle, color = Primary)
                            Text(
                                when {
                                    score >= 80 -> "LOW RISK"
                                    score >= 55 -> "MEDIUM RISK"
                                    else -> "HIGH RISK"
                                },
                                style = CS.Label, color = Primary)
                        } ?: Text("Score unavailable", style = CS.Body, color = TextSecondary)
                        Text(
                            "No high-risk indicators were detected in the areas checked." +
                                (if (r.highRisk == 0 && r.warnings == 0) "" else " Review findings below."),
                            style = CS.Secondary, color = TextSecondary,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(top = Dsn.S))
                        Text(
                            "${r.itemsChecked} items checked in ${r.durationMs / 1000}s · " +
                                "checked: ${r.modules.count { it.available }} module(s)",
                            style = CS.Secondary, color = TextTertiary)
                    }
                }

                // ---------------- Scan summary (§5) ---------------------------
                SectionCard {
                    Column(Modifier.padding(Dsn.M)) {
                        Text("SCAN SUMMARY", style = CS.CardTitle, color = TextPrimary)
                        Spacer(Modifier.height(Dsn.S))
                        r.modules.forEach { m ->
                            Row(
                                Modifier.fillMaxWidth().padding(vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    when {
                                        !m.available -> Icons.Filled.HelpOutline
                                        m.highRisk > 0 -> Icons.Filled.Error
                                        m.warnings > 0 -> Icons.Filled.Warning
                                        else -> Icons.Filled.CheckCircle
                                    },
                                    contentDescription = null,
                                    tint = when {
                                        !m.available -> TextTertiary
                                        m.highRisk > 0 -> High
                                        m.warnings > 0 -> Warning
                                        else -> Safe
                                    },
                                    modifier = Modifier.size(20.dp))
                                Spacer(Modifier.width(Dsn.S))
                                Column(Modifier.weight(1f)) {
                                    Text(m.label, style = CS.Body, color = TextPrimary)
                                    Text(
                                        if (m.available) m.summary
                                        else "Not available on this device",
                                        style = CS.Secondary, color = TextSecondary)
                                }
                                if (m.available && (m.highRisk > 0 || m.warnings > 0)) {
                                    TextButton(onClick = { navController.navigate(m.route) }) {
                                        Text("Review", style = CS.Label, color = Primary)
                                    }
                                }
                            }
                        }
                    }
                }

                // ---------------- Score deltas (§4: "why the score changed") --
                if (r.scoreDeltas.isNotEmpty()) {
                    SectionCard {
                        Column(Modifier.padding(Dsn.M)) {
                            Text("WHY THIS SCORE", style = CS.CardTitle, color = TextPrimary)
                            Text("Every factor, transparently (deterministic engine):",
                                style = CS.Secondary, color = TextSecondary,
                                modifier = Modifier.padding(top = 2.dp))
                            Spacer(Modifier.height(Dsn.S))
                            r.scoreDeltas.forEach { d ->
                                Row(Modifier.padding(vertical = 3.dp)) {
                                    Text(d, style = CS.BodyMedium, color = TextPrimary)
                                }
                            }
                        }
                    }
                }

                // ---------------- Correlations (§3) ---------------------------
                if (r.correlations.isNotEmpty()) {
                    SectionCard {
                        Column(Modifier.padding(Dsn.M)) {
                            Text("THREAT CORRELATION", style = CS.CardTitle, color = TextPrimary)
                            Spacer(Modifier.height(Dsn.S))
                            r.correlations.forEach { c ->
                                Surface(
                                    shape = RoundedCornerShape(Dsn.CardCornerSm),
                                    color = (if (c.severity == "HIGH") High else Warning)
                                        .copy(alpha = 0.10f),
                                    modifier = Modifier.fillMaxWidth()
                                        .padding(vertical = 4.dp)
                                ) {
                                    Column(Modifier.padding(Dsn.M)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Icon(Icons.Filled.Hub, contentDescription = null,
                                                tint = if (c.severity == "HIGH") High else Warning,
                                                modifier = Modifier.size(16.dp))
                                            Spacer(Modifier.width(6.dp))
                                            Text(c.title, style = CS.Body, color = TextPrimary,
                                                modifier = Modifier.weight(1f))
                                            Text(c.severity, style = CS.Label,
                                                color = if (c.severity == "HIGH") High else Warning)
                                        }
                                        Spacer(Modifier.height(4.dp))
                                        c.evidence.forEach { e ->
                                            Text("• $e", style = CS.Secondary,
                                                color = TextSecondary)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ---------------- Actions required (§6/§7) --------------------
                SectionCard {
                    Column(Modifier.padding(Dsn.M)) {
                        Text("🛠 ACTIONS REQUIRED", style = CS.CardTitle, color = TextPrimary)
                        Spacer(Modifier.height(Dsn.S))
                        if (r.actionsRequired.isEmpty()) {
                            Text("Nothing requires your attention right now.",
                                style = CS.BodyMedium, color = TextSecondary)
                        } else {
                            r.actionsRequired.forEachIndexed { i, a ->
                                Text("${i + 1}. $a", style = CS.BodyMedium, color = TextPrimary)
                            }
                        }
                        Spacer(Modifier.height(Dsn.M))
                        if (r.actionsRequired.isNotEmpty()) {
                            Button(
                                onClick = { navController.navigate("alerts") },
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = Primary, contentColor = Color.White)
                            ) { Text("VIEW & FIX", style = CS.Button) }
                        }
                        OutlinedButton(
                            onClick = { start() },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text("SCAN AGAIN", style = CS.Button) }
                    }
                }
            }
        }
    }
}
