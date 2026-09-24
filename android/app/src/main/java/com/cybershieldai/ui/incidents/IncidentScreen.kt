package com.cybershieldai.ui.incidents

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.engine.LocalThreatCorrelator
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.severityColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Incident Center (spec §16): aggregates evidence into an honest posture.
 * The wording is deliberately cautious — "Potential security incident" unless
 * the evidence genuinely supports a stronger statement. CyberShield never
 * tells users they were "definitely hacked".
 */
@Composable
fun IncidentScreen(navController: NavHostController) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var recent by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        recent = try { EventRepository(context).events(limit = 200) } catch (_: Exception) { emptyList() }
        loading = false
    }

    val now = System.currentTimeMillis()
    val window = recent.filter { now - it.timestamp <= 24 * 60 * 60 * 1000L }
    val highEvents = window.filter { it.severity == "HIGH" || it.severity == "CRITICAL" }
    val mediumEvents = window.filter { it.severity == "MEDIUM" }
    val correlated = LocalThreatCorrelator.assess(recent.filter { it.riskScore >= 50 }, 70)

    val (posture, postureColorKey, postureText) = when {
        highEvents.any { it.severity == "CRITICAL" } -> Triple(
            "🔴 Critical security event", "CRITICAL",
            "A critical event was detected. Review the evidence below — the label reflects the evidence, not speculation.")
        highEvents.isNotEmpty() -> Triple(
            "🟠 High-risk activity", "HIGH",
            "High-risk signals were detected in the last 24 hours. Review them and take the recommended actions.")
        mediumEvents.isNotEmpty() || correlated.boost > 0 -> Triple(
            "🟡 Suspicious activity", "MEDIUM",
            "Some signals need review. No critical evidence was found.")
        else -> Triple("🟢 No suspicious activity", "SAFE",
            "No suspicious activity detected in the last 24 hours. Keep monitoring enabled to stay informed.")
    }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("Incident Center", style = MaterialTheme.typography.headlineMedium)

        SectionCard {
            Text("Current posture", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text(posture, style = MaterialTheme.typography.titleLarge,
                color = severityColor(postureColorKey))
            Spacer(Modifier.height(6.dp))
            Text(postureText, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }

        if (correlated.boost > 0) {
            SectionCard {
                Text("Potential security incident", style = MaterialTheme.typography.titleMedium,
                    color = severityColor("MEDIUM"))
                Spacer(Modifier.height(4.dp))
                Text("Related signals co-occurring suggest a coordinated attempt (not yet confirmed):",
                    style = MaterialTheme.typography.bodyMedium)
                correlated.matchedSignals.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
            }
        }

        SectionCard {
            Text("Evidence-based events (24h)", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            when {
                loading -> com.cybershieldai.ui.components.LoadingView("Loading evidence…")
                window.isEmpty() -> Text(
                    "No security events in the last 24 hours.",
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                else -> {
                    val fmt = SimpleDateFormat("HH:mm", Locale.US)
                    window.sortedByDescending { it.timestamp }.take(15).forEach { ev ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Text(fmt.format(Date(ev.timestamp)),
                                style = MaterialTheme.typography.labelMedium,
                                color = TextSecondary, modifier = Modifier.width(52.dp))
                            Column(Modifier.weight(1f)) {
                                Text(ev.summary, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                                Text("Evidence: " + EventRepository.fromJsonList(ev.indicatorsJson)
                                    .firstOrNull()?.let { it.take(70) } ?: "none recorded",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = TextSecondary, maxLines = 1)
                            }
                            Text(ev.severity, style = MaterialTheme.typography.labelMedium,
                                color = severityColor(ev.severity), fontWeight = FontWeight.Bold)
                        }
                    }
                    if (highEvents.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text("Potential security incident — " +
                            "${highEvents.size} high-risk event(s) recorded. " +
                            "Each event links the evidence that justified its severity.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = severityColor("HIGH"))
                    }
                }
            }
        }

        SectionCard {
            Text("What CyberShield will not claim", style = MaterialTheme.typography.titleMedium)
            Text(
                "• It will not say you were \"hacked\" without reliable evidence.\n" +
                "• It will not call an app \"spyware\" merely for holding a permission.\n" +
                "• It will not invent threats to look useful.\n" +
                "Every incident label here is traceable to recorded evidence.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }
    }
}
