package com.cybershieldai.ui.timeline

import androidx.compose.foundation.background
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
import androidx.navigation.NavHostController
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.ui.components.IndicatorList
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.severityColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Security Timeline (spec §13): day-grouped history of every local security
 * event. Each entry opens an evidence sheet — what was detected, by which
 * methods, with which indicators, and the recommended action.
 */
@Composable
fun TimelineScreen(navController: NavHostController) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var events by remember { mutableStateOf<List<SecurityEventEntity>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var selected by remember { mutableStateOf<SecurityEventEntity?>(null) }

    LaunchedEffect(Unit) {
        events = try { EventRepository(context).events(limit = 300) } catch (_: Exception) { emptyList() }
        loading = false
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("Security Timeline", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(4.dp))
        Text("Every detection, with its evidence. Raw content is never stored.",
            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        Spacer(Modifier.height(12.dp))

        when {
            loading -> com.cybershieldai.ui.components.LoadingView("Loading timeline…")
            events.isEmpty() -> SectionCard {
                Text("No events recorded yet.",
                    style = MaterialTheme.typography.titleMedium)
                Text("Scans and monitoring events will appear here.",
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
            else -> TimelineContent(events = events, onEventClick = { selected = it })
        }
    }

    selected?.let { EventEvidenceSheet(it) { selected = null } }
}

/** Day-grouped, reusable timeline list (also embedded in the Alerts tab). */
@Composable
fun TimelineContent(events: List<SecurityEventEntity>, onEventClick: (SecurityEventEntity) -> Unit) {
    val dayFormat = SimpleDateFormat("EEEE, MMM d", Locale.US)
    val grouped = events.groupBy { dayFormat.format(Date(it.timestamp)) }
    val sortedDays = grouped.entries.sortedByDescending { parseDayKey(it.key, dayFormat) }

    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        sortedDays.forEach { (day, list) ->
            item(key = "day_$day") {
                Text(day.uppercase(), style = MaterialTheme.typography.labelMedium,
                    color = TextSecondary, modifier = Modifier.padding(top = 8.dp))
            }
            items(list, key = { it.id }) { ev ->
                TimelineRow(ev, onClick = { onEventClick(ev) })
            }
        }
    }
}

private fun parseDayKey(key: String, format: SimpleDateFormat): Long = try {
    format.parse(key)?.time ?: 0L
} catch (_: Exception) { 0L }

@Composable
fun TimelineRow(ev: SecurityEventEntity, onClick: () -> Unit) {
    val time = SimpleDateFormat("HH:mm", Locale.US).format(Date(ev.timestamp))
    SectionCard(modifier = Modifier.clickable(onClick = onClick)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // Colored status dot (image-style alert rows) — real severity color.
            Box(
                Modifier
                    .size(10.dp)
                    .background(severityColor(ev.severity), androidx.compose.foundation.shape.CircleShape)
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(ev.summary, style = MaterialTheme.typography.bodyLarge, maxLines = 2)
                Text("${ev.category} · risk ${ev.riskScore}/100 · ${ev.source}",
                    style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(ev.severity, style = MaterialTheme.typography.labelMedium,
                    color = severityColor(ev.severity), fontWeight = FontWeight.Bold)
                Text(time, style = MaterialTheme.typography.labelMedium,
                    color = TextSecondary)
            }
        }
    }
}

private fun severityDot(severity: String): String = when (severity) {
    "CRITICAL" -> "🔴"
    "HIGH" -> "🟠"
    "MEDIUM" -> "🟡"
    "LOW" -> "🔵"
    else -> "🟢"
}

/** Bottom-sheet style evidence view for one event (spec §13: open each event, see evidence). */
@Composable
fun EventEvidenceSheet(ev: SecurityEventEntity, onDismiss: () -> Unit) {
    val time = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(ev.timestamp))
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        title = {
            Column {
                Text(ev.summary, style = MaterialTheme.typography.titleMedium)
                Text("$time · ${ev.category} · ${ev.source}",
                    style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
        },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Severity", Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium)
                    com.cybershieldai.ui.components.SeverityChip(ev.severity)
                }
                Spacer(Modifier.height(6.dp))
                EvidenceLine("Risk score", "${ev.riskScore}/100")
                EvidenceLine("Confidence", "${(ev.confidence * 100).toInt()}%")
                EvidenceLine("Classification", ev.classification)
                Spacer(Modifier.height(8.dp))
                Text("Evidence (indicators)", style = MaterialTheme.typography.titleMedium)
                IndicatorList(EventRepository.fromJsonList(ev.indicatorsJson))
                Spacer(Modifier.height(8.dp))
                Text("Detection methods", style = MaterialTheme.typography.titleMedium)
                Text(EventRepository.fromJsonList(ev.methodsJson).joinToString(" · "),
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                Spacer(Modifier.height(8.dp))
                Text(
                    "The AI copilot can explain this event in plain language. " +
                    "It never changes the recorded result.",
                    style = MaterialTheme.typography.labelMedium, color = TextSecondary)
            }
        }
    )
}

@Composable
private fun EvidenceLine(label: String, value: String) {
    Row {
        Text("$label: ", style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
