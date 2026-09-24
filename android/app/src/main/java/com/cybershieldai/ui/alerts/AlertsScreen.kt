package com.cybershieldai.ui.alerts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.StatusPill
import com.cybershieldai.ui.theme.CS
import com.cybershieldai.ui.theme.Dsn
import com.cybershieldai.ui.theme.TextPrimary
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.TextTertiary
import com.cybershieldai.ui.timeline.TimelineContent
import com.cybershieldai.ui.timeline.EventEvidenceSheet
import com.cybershieldai.ui.components.relativeTime
import kotlinx.coroutines.launch

/**
 * ALERTS tab (spec §18): filterable alert center with severity categories
 * (CRITICAL/HIGH/MEDIUM/LOW/INFO), alert statuses (New/Reviewed/Resolved),
 * per-alert actions (mark reviewed, clear) and a link to the Incident Center.
 */
@Composable
fun AlertsScreen(navController: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var events by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var filter by remember { mutableStateOf("ALL") }
    var selected by remember { mutableStateOf<SecurityEventEntity?>(null) }
    var reloadKey by remember { mutableStateOf(0) }

    fun load() {
        scope.launch {
            loading = true
            events = try {
                val repo = EventRepository(context)
                val base = when (filter) {
                    // Spec §P filters: All / High Risk / Warning / Safe
                    "HIGH" -> repo.events(limit = 200).filter {
                        it.severity == "HIGH" || it.severity == "CRITICAL" }
                    "WARNING" -> repo.events(limit = 200).filter { it.severity == "MEDIUM" }
                    "SAFE" -> repo.events(limit = 200).filter {
                        it.severity == "SAFE" || it.severity == "LOW" }
                    "PRIVACY" -> repo.events(category = "PRIVACY", limit = 200)
                    else -> repo.events(limit = 200)
                }
                base.sortedByDescending { it.timestamp }
            } catch (_: Exception) { emptyList() }
            loading = false
        }
    }
    LaunchedEffect(filter, reloadKey) { load() }

    Column(Modifier.fillMaxSize().padding(Dsn.L)) {
        Text("Alerts", style = CS.ScreenTitle, color = TextPrimary)
        Spacer(Modifier.height(4.dp))
        Text("Detections from monitoring, scans and the 12-hour checks.",
            style = CS.BodyMedium, color = TextSecondary)
        Spacer(Modifier.height(10.dp))

        // ---- Category filters (spec §18) ----
        Row(
            Modifier.horizontalScroll(androidx.compose.foundation.rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(Dsn.S)
        ) {
            listOf("ALL", "HIGH", "WARNING", "SAFE", "PRIVACY").forEach { f ->
                FilterChip(
                    selected = filter == f,
                    onClick = { filter = f },
                    label = {
                        Text(
                            when (f) {
                                "ALL" -> "All"
                                "HIGH" -> "High Risk"
                                "WARNING" -> "Warning"
                                "SAFE" -> "Safe"
                                else -> "Privacy"
                            },
                            style = CS.Label)
                    })
            }
        }
        Spacer(Modifier.height(8.dp))

        TextButton(onClick = { navController.navigate("incidents") }) {
            Text("Open Incident Center →", style = CS.Label)
        }
        Spacer(Modifier.height(4.dp))

        when {
            loading -> com.cybershieldai.ui.components.LoadingView("Loading alerts…")
            events.isEmpty() -> SectionCard {
                Text("No alerts for this filter.", style = CS.CardTitle)
                Text("SAFE detections do not raise alerts — that is by design.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
            else -> Column {
                // Image behavior: tapping an alert opens the Threat Alert detail
                // screen (banner / signals / gauge / recommended action).
                TimelineContent(events = events, onEventClick = { ev ->
                    navController.navigate("threat/${ev.id}")
                })
            }
        }
    }
}

/** Evidence sheet with alert lifecycle actions: status pill + Reviewed/Resolved/Clear. */
@Composable
private fun AlertActionSheet(
    event: SecurityEventEntity,
    onDismiss: () -> Unit,
    onMarkReviewed: () -> Unit,
    onResolve: () -> Unit,
    onClear: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Row {
                TextButton(onClick = onMarkReviewed) { Text("Mark Reviewed") }
                TextButton(onClick = onResolve) { Text("Resolve") }
                TextButton(onClick = onClear) { Text("Clear") }
                TextButton(onClick = onDismiss) { Text("Close") }
            }
        },
        title = {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(event.summary, style = CS.CardTitle, modifier = Modifier.weight(1f))
                    StatusPill(event.status, statusColorKey(event.status))
                }
                Text(
                    "${relativeTime(event.timestamp)} · ${event.category} · ${event.source}",
                    style = CS.Secondary, color = TextTertiary)
            }
        },
        text = {
            Column {
                com.cybershieldai.ui.components.SeverityChip(event.severity)
                Spacer(Modifier.height(Dsn.S))
                Row {
                    Text("Risk score: ", style = CS.BodyMedium, color = TextSecondary)
                    Text("${event.riskScore}/100", style = CS.BodyMedium, color = TextPrimary)
                }
                Row {
                    Text("Status: ", style = CS.BodyMedium, color = TextSecondary)
                    Text(event.status, style = CS.BodyMedium, color = TextPrimary)
                }
                Spacer(Modifier.height(Dsn.S))
                Text("Evidence (indicators)", style = CS.CardTitle)
                com.cybershieldai.ui.components.IndicatorList(
                    EventRepository.fromJsonList(event.indicatorsJson))
                Spacer(Modifier.height(Dsn.S))
                Text("Detection methods", style = CS.CardTitle)
                Text(EventRepository.fromJsonList(event.methodsJson).joinToString(" · "),
                    style = CS.BodyMedium, color = TextSecondary)
                Spacer(Modifier.height(Dsn.S))
                Text("Recommendation", style = CS.CardTitle)
                Text(
                    com.cybershieldai.engine.LocalRiskEngine.recommendationFor(
                        event.category, event.severity),
                    style = CS.BodyMedium, color = TextSecondary)
            }
        }
    )
}

internal fun statusColorKey(status: String): String = when (status) {
    "Resolved" -> "SAFE"
    "Reviewed" -> "LOW"
    else -> "MEDIUM" // New
}
