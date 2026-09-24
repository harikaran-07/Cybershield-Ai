package com.cybershieldai.ui.media

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.media.MediaRiskEngine
import com.cybershieldai.media.MediaScanState
import com.cybershieldai.media.MediaSecurityResult
import com.cybershieldai.media.MediaSecurityRepository
import com.cybershieldai.ui.components.IndicatorList
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.*
import kotlinx.coroutines.launch

/**
 * AI MEDIA SECURITY (spec §2/§10): "Detect potential AI-generated and
 * manipulated media". The user picks a file via the SYSTEM document picker
 * (no broad storage permission); analysis is 100% on-device; the local LLM
 * (optional) only explains the final result.
 */
@Composable
fun MediaSecurityScreen(navController: NavHostController, eventId: Long = -1L) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repo = remember { MediaSecurityRepository(context) }

    var state by remember { mutableStateOf<MediaScanState>(MediaScanState.Idle) }
    var phase by remember { mutableStateOf("") }
    var withExplanation by remember { mutableStateOf(true) }
    var pickedKind by remember { mutableStateOf("") }

    val openDoc = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && pickedKind.isNotBlank()) {
            val kind = pickedKind
            scope.launch {
                state = repo.analyze(uri, kind, { phase = it }, withExplanation)
            }
        }
    }

    fun pick(kind: String) {
        if (state is MediaScanState.Running) return
        pickedKind = kind
        val mime = when (kind) {
            "AUDIO" -> "audio/*"
            "IMAGE" -> "image/*"
            else -> "video/*"
        }
        try {
            openDoc.launch(arrayOf(mime))
        } catch (_: Exception) {
            state = MediaScanState.Failed("The file picker is unavailable on this device.")
        }
    }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        // ---------------- Header ----------------
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { navController.popBackStack() }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back", tint = TextSecondary)
            }
        }
        Column(
            Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Surface(shape = CircleShape, color = Primary.copy(alpha = 0.15f)) {
                Icon(Icons.Filled.GraphicEq, contentDescription = null, tint = Primary,
                    modifier = Modifier.padding(18.dp).size(40.dp))
            }
            Spacer(Modifier.height(Dsn.S))
            Text("AI Media Security", style = CS.ScreenTitle, color = TextPrimary,
                textAlign = TextAlign.Center)
            Text("Detect potential AI-generated and manipulated media",
                style = CS.BodyMedium, color = TextSecondary, textAlign = TextAlign.Center)
        }

        // ---------------- What this does / privacy ----------------
        SectionCard {
            Text("HOW IT WORKS", style = CS.Label, color = Primary)
            Spacer(Modifier.height(Dsn.S))
            Text(
                "Pick an audio, image or video file. Analysis runs entirely on this " +
                    "device: the file is never uploaded and never opened in another app. " +
                    "The engine looks for signals commonly associated with AI generation " +
                    "or manipulation and reports them honestly — results are not proof.",
                style = CS.BodyMedium, color = TextSecondary)
            Spacer(Modifier.height(Dsn.S))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = withExplanation, onCheckedChange = { withExplanation = it })
                Spacer(Modifier.width(Dsn.S))
                Text("Add AI explanation (on-device model)",
                    style = CS.Secondary, color = TextSecondary)
            }
        }

        // ---------------- Pickers ----------------
        when (val s = state) {
            is MediaScanState.Idle -> {
                PickerCard(Icons.Filled.GraphicEq, "🎙 Analyze Voice",
                    "Check an audio recording for synthetic-speech signals") { pick("AUDIO") }
                PickerCard(Icons.Filled.Image, "🖼 Analyze Image",
                    "Check an image for AI-generation and manipulation signals") { pick("IMAGE") }
                PickerCard(Icons.Filled.Movie, "🎥 Analyze Video",
                    "Check sampled video frames and its audio track") { pick("VIDEO") }
            }
            is MediaScanState.Running -> {
                SectionCard {
                    Text("ANALYZING", style = CS.Label, color = Primary)
                    Spacer(Modifier.height(Dsn.S))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = Primary)
                        Spacer(Modifier.width(Dsn.M))
                        Text(s.phase.ifBlank { "Working…" },
                            style = CS.BodyMedium, color = TextSecondary)
                    }
                    Spacer(Modifier.height(Dsn.S))
                    Text("You can keep the app open — large files take longer. " +
                        "Analysis stays on this device.",
                        style = CS.Secondary, color = TextTertiary)
                }
            }
            is MediaScanState.Failed -> {
                SectionCard {
                    Text("Analysis problem", style = CS.CardTitle, color = Warning)
                    Spacer(Modifier.height(Dsn.S))
                    Text(s.userMessage, style = CS.BodyMedium, color = TextSecondary)
                    Spacer(Modifier.height(Dsn.S))
                    TextButton(onClick = { state = MediaScanState.Idle }) {
                        Text("Try another file", style = CS.Label)
                    }
                }
                PickerCard(Icons.Filled.GraphicEq, "🎙 Analyze Voice",
                    "Check an audio recording for synthetic-speech signals") { pick("AUDIO") }
                PickerCard(Icons.Filled.Image, "🖼 Analyze Image",
                    "Check an image for AI-generation and manipulation signals") { pick("IMAGE") }
                PickerCard(Icons.Filled.Movie, "🎥 Analyze Video",
                    "Check sampled video frames and its audio track") { pick("VIDEO") }
            }
            is MediaScanState.Done -> ResultView(s) { state = MediaScanState.Idle }
        }

        Spacer(Modifier.height(Dsn.L))
        Text(
            "Analysis is on-device only. Media is never uploaded. The optional local AI " +
                "model receives only sanitized findings — never the media itself.",
            style = CS.Secondary, color = TextTertiary, textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth())
    }
}

// ---------------------------------------------------------------------
// Result view (spec §10)
// ---------------------------------------------------------------------
@Composable
private fun ResultView(done: MediaScanState.Done, onNewScan: () -> Unit) {
    val r = done.result
    Column(verticalArrangement = Arrangement.spacedBy(Dsn.M)) {
        // ---- Status header ----
        SectionCard {
            Text("AI MEDIA SECURITY RESULT", style = CS.Label, color = Primary)
            Spacer(Modifier.height(Dsn.S))
            Text(r.statusLabel, style = CS.ScreenTitle, color = statusColor(r),
                textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(Dsn.S))
            Row(horizontalArrangement = Arrangement.SpaceEvenly,
                modifier = Modifier.fillMaxWidth()) {
                ResultStat("Confidence", "${r.confidence}%")
                ResultStat("Risk", r.riskLevel)
                ResultStat("Type", r.mediaType.lowercase())
            }
            Spacer(Modifier.height(Dsn.S))
            Text(r.recommendation, style = CS.BodyMedium, color = TextSecondary,
                textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        }

        // ---- What was detected (only real indicators) ----
        SectionCard {
            Text("WHAT WAS DETECTED", style = CS.Label, color = TextSecondary)
            Spacer(Modifier.height(Dsn.S))
            if (r.indicators.isEmpty()) {
                Text("No strong synthetic indicators were detected in this file.",
                    style = CS.BodyMedium, color = TextPrimary)
            } else {
                IndicatorList(r.indicators)
            }
        }

        // ---- Technical findings (deterministic measurements) ----
        if (r.technicalFindings.isNotEmpty()) {
            SectionCard {
                Text("TECHNICAL FINDINGS", style = CS.Label, color = TextSecondary)
                Spacer(Modifier.height(Dsn.S))
                IndicatorList(r.technicalFindings)
            }
        }

        // ---- AI explanation (optional, last, honest when absent) ----
        SectionCard {
            Text("AI EXPLANATION", style = CS.Label, color = TextSecondary)
            Spacer(Modifier.height(Dsn.S))
            if (done.explanationAvailable && done.explanation != null) {
                Text("✓ Explanation generated (on-device model)",
                    style = CS.Label, color = Safe)
                Spacer(Modifier.height(Dsn.S))
                Text(done.explanation, style = CS.BodyMedium, color = TextPrimary)
            } else {
                Text("○ AI explanation unavailable",
                    style = CS.Label, color = TextTertiary)
                Spacer(Modifier.height(Dsn.S))
                Text(
                    "The result above was produced by CyberShield's on-device security " +
                        "engine and stands unchanged. The optional explanation model is " +
                        "unavailable, busy or took too long on this device.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
        }

        // ---- Important (spec §10 disclaimer) ----
        SectionCard {
            Text("IMPORTANT", style = CS.Label, color = Warning)
            Spacer(Modifier.height(Dsn.S))
            Text(
                "Automated AI-media detection is not perfect. Results can contain " +
                    "false positives or false negatives. Do not treat any result as " +
                    "definitive proof.",
                style = CS.BodyMedium, color = TextSecondary)
        }

        // ---- Saved note + actions ----
        SectionCard {
            Text(
                if (done.eventId != null) "✓ Saved to your security history (Alerts & Timeline)."
                else "Not saved to history (recording failed).",
                style = CS.Secondary, color = TextTertiary)
            Spacer(Modifier.height(Dsn.S))
            Row(horizontalArrangement = Arrangement.spacedBy(Dsn.S)) {
                Button(
                    onClick = onNewScan,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(Dsn.ButtonCorner),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Primary, contentColor = Color.White)
                ) { Text("New Analysis", style = CS.Button) }
                if (done.eventId != null) {
                    Button(
                        onClick = { /* history opens via Alerts tab; kept simple */ },
                        enabled = false,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(Dsn.ButtonCorner)
                    ) { Text("View in Alerts", style = CS.Button) }
                }
            }
        }
    }
}

@Composable
private fun ResultStat(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = CS.ScoreSmall, color = TextPrimary)
        Text(label, style = CS.Secondary, color = TextTertiary)
    }
}

@Composable
private fun PickerCard(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(Dsn.CardCorner),
        color = Surface,
        border = androidx.compose.foundation.BorderStroke(1.dp, Primary.copy(alpha = 0.35f))
    ) {
        Row(Modifier.padding(Dsn.M), verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = CircleShape, color = Primary.copy(alpha = 0.15f)) {
                Icon(icon, contentDescription = null, tint = Primary,
                    modifier = Modifier.padding(10.dp).size(24.dp))
            }
            Spacer(Modifier.width(Dsn.M))
            Column(Modifier.weight(1f)) {
                Text(title, style = CS.CardTitle, color = TextPrimary)
                Text(subtitle, style = CS.Secondary, color = TextSecondary)
            }
            Text("→", style = CS.CardTitle, color = Primary)
        }
    }
}

private fun statusColor(r: MediaSecurityResult): Color = when (r.status) {
    MediaSecurityResult.Status.POTENTIALLY_AI_GENERATED,
    MediaSecurityResult.Status.POTENTIALLY_MANIPULATED ->
        if (r.confidence >= 60) High else Warning
    MediaSecurityResult.Status.ANALYSIS_FAILED -> High
    else -> Safe
}
