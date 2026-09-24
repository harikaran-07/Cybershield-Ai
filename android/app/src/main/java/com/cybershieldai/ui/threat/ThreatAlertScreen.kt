package com.cybershieldai.ui.threat

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PostAdd
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import kotlinx.coroutines.launch
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.SemicircleRiskGauge
import com.cybershieldai.ui.components.relativeTime
import com.cybershieldai.ui.theme.*

/**
 * THREAT ALERT — exact layout from the provided reference image:
 * back header → red "Possible Scam Detected" banner with High Risk pill and
 * timestamp → Detected Signals list → Risk Analysis card (semicircular gauge
 * with the ACTUAL calculated score + Indicators Found checklist showing ONLY
 * actually-detected indicators) → Recommended Action → purple View All
 * Details CTA → Mark as Reviewed / Dismiss.
 */
@Composable
fun ThreatAlertScreen(navController: NavHostController, eventId: Long) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var event by remember { mutableStateOf<SecurityEventEntity?>(null) }
    var missing by remember { mutableStateOf(false) }
    var reviewed by remember { mutableStateOf(false) }

    LaunchedEffect(eventId) {
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            event = try {
                com.cybershieldai.data.local.DatabaseProvider.get(context)
                    .securityEventDao().byId(eventId)
            } catch (_: Exception) { null }
            missing = event == null
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
            Text("Threat Alert", style = CS.Heading, color = TextPrimary,
                modifier = Modifier.weight(1f))
        }

        when {
            missing -> Text("This alert no longer exists.", style = CS.BodyMedium,
                color = TextSecondary)
            event == null -> com.cybershieldai.ui.components.LoadingView("Loading alert…")
            else -> {
                val ev = event!!
                val indicators = EventRepository.fromJsonList(ev.indicatorsJson)
                val scamLike = ev.classification == "SUSPICIOUS" || ev.severity == "HIGH" ||
                    ev.severity == "CRITICAL"

                // ---------------- Banner (image: red gradient + High Risk pill) -----
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(Dsn.CardCorner)
                ) {
                    Row(
                        Modifier.fillMaxWidth().background(
                            Brush.horizontalGradient(listOf(
                                High.copy(alpha = 0.30f), High.copy(alpha = 0.10f))))
                            .padding(Dsn.L),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(shape = CircleShape, color = High.copy(alpha = 0.25f)) {
                            Icon(Icons.Filled.WarningAmber, contentDescription = null,
                                tint = High, modifier = Modifier.padding(10.dp).size(28.dp))
                        }
                        Spacer(Modifier.width(Dsn.M))
                        Column(Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    when {
                                        scamLike -> "Possible Scam Detected"
                                        ev.classification == "UNKNOWN" -> "Call Could Not Be Classified"
                                        else -> "No Strong Scam Indicators"
                                    },
                                    style = CS.CardTitle, color = TextPrimary)
                                Spacer(Modifier.width(Dsn.S))
                                Surface(
                                    shape = RoundedCornerShape(50),
                                    color = High.copy(alpha = 0.2f)
                                ) {
                                    Text(
                                        when {
                                            scamLike -> "High Risk"
                                            ev.classification == "UNKNOWN" -> "Unknown"
                                            else -> "Safe"
                                        },
                                        style = CS.Caption,
                                        color = if (scamLike) High else if (ev.classification == "UNKNOWN") Warning else Safe,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp))
                                }
                            }
                            Text(
                                ev.summary,
                                style = CS.BodyMedium, color = TextSecondary)
                            Text("Today, " + relativeTime(ev.timestamp),
                                style = CS.Caption, color = TextTertiary)
                        }
                    }
                }

                // ---------------- Detected Signals (image section) ------------------
                Text("Detected Signals", style = CS.Heading, color = TextPrimary)
                if (indicators.isEmpty()) {
                    SectionCard {
                        Text("No specific indicators were detected for this event.",
                            style = CS.BodyMedium, color = TextSecondary)
                    }
                } else {
                    indicators.take(4).forEach { ind ->
                        SignalRow(iconFor(ind), ind)
                    }
                }

                // ---------------- Risk Analysis (gauge + indicators found) ----------
                Text("Risk Analysis", style = CS.Heading, color = TextPrimary)
                SectionCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SemicircleRiskGauge(
                            score = ev.riskScore,
                            severity = ev.severity,
                            modifier = Modifier.weight(1f))
                        Spacer(Modifier.width(Dsn.L))
                        Column(Modifier.weight(1.2f)) {
                            Text("Indicators Found", style = CS.CardTitle, color = TextPrimary)
                            Spacer(Modifier.height(Dsn.S))
                            if (indicators.isEmpty()) {
                                Text("None recorded", style = CS.BodyMedium,
                                    color = TextSecondary)
                            } else {
                                indicators.take(5).forEach {
                                    Row(Modifier.padding(vertical = 3.dp)) {
                                        Icon(Icons.Filled.CheckCircle, contentDescription = null,
                                            tint = High, modifier = Modifier.size(16.dp))
                                        Spacer(Modifier.width(Dsn.S))
                                        Text(it, style = CS.BodyMedium, color = TextPrimary)
                                    }
                                }
                            }
                        }
                    }
                }

                // ---------------- Recommended Action (image: shield card) -----------
                SectionCard {
                    Row(verticalAlignment = Alignment.Top) {
                        Icon(Icons.Filled.Shield, contentDescription = null,
                            tint = Primary, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(Dsn.M))
                        Column {
                            Text("Recommended Action", style = CS.CardTitle, color = Primary)
                            Text(
                                com.cybershieldai.engine.LocalRiskEngine.recommendationFor(
                                    ev.category, ev.severity),
                                style = CS.BodyMedium, color = TextSecondary)
                        }
                    }
                }

                // ---------------- CTA + lifecycle buttons ---------------------------
                Button(
                    onClick = { navController.navigate("timeline") },
                    modifier = Modifier.fillMaxWidth().height(Dsn.ButtonHeight),
                    shape = RoundedCornerShape(Dsn.ButtonCorner),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Primary, contentColor = Color_White)
                ) { Text("View All Details", style = CS.Button) }
                Row(horizontalArrangement = Arrangement.spacedBy(Dsn.M)) {
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                EventRepository(context).setEventStatus(ev.id, "Reviewed")
                                reviewed = true
                            }
                        },
                        modifier = Modifier.weight(1f).height(Dsn.ButtonHeight),
                        shape = RoundedCornerShape(Dsn.ButtonCorner)
                    ) {
                        Text(if (reviewed) "Reviewed ✓" else "Mark as Reviewed", style = CS.Label)
                    }
                    OutlinedButton(
                        onClick = { navController.popBackStack() },
                        modifier = Modifier.weight(1f).height(Dsn.ButtonHeight),
                        shape = RoundedCornerShape(Dsn.ButtonCorner)
                    ) { Text("Dismiss", style = CS.Label) }
                }
            }
        }
    }
}

/** Icon choice per indicator text (image-style signal cards). */
private fun iconFor(text: String): ImageVector = when {
    text.contains("call", true) || text.contains("caller", true) -> Icons.Filled.Call
    text.contains("link", true) || text.contains("url", true) -> Icons.Filled.Link
    text.contains("message", true) || text.contains("sms", true) ||
        text.contains("notification", true) -> Icons.Filled.PostAdd
    else -> Icons.Filled.Shield
}

private val Color_White = androidx.compose.ui.graphics.Color.White

/** One detected-signal row (image: rounded card, icon, chevron). */
@Composable
private fun SignalRow(icon: ImageVector, text: String) {
    SectionCard(modifier = Modifier.padding(vertical = Dsn.XS)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = CircleShape, color = Primary.copy(alpha = 0.16f)) {
                Icon(icon, contentDescription = null, tint = Primary,
                    modifier = Modifier.padding(8.dp).size(18.dp))
            }
            Spacer(Modifier.width(Dsn.M))
            Text(text, style = CS.BodyMedium, color = TextPrimary, modifier = Modifier.weight(1f))
            Icon(Icons.Filled.ChevronRight, contentDescription = null,
                tint = TextTertiary, modifier = Modifier.size(16.dp))
        }
    }
}
