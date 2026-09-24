package com.cybershieldai.ui.report

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.data.local.CommunityReportEntity
import com.cybershieldai.data.local.DatabaseProvider
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Report Scam (spec §25): file a LOCAL report of a scam number, SMS or URL.
 *
 * Privacy (shown on the screen before storing): everything stays on this
 * device — CyberShield has no community server. Reported numbers feed the
 * Call Risk Engine's caller-reputation signal, so a future call from a
 * number you reported is flagged as such.
 */
@Composable
fun ReportScreen(navController: NavHostController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var kind by remember { mutableStateOf("NUMBER") }
    var value by remember { mutableStateOf("") }
    var reportType by remember { mutableStateOf("SCAM") }
    var note by remember { mutableStateOf("") }
    var saved by remember { mutableStateOf<String?>(null) }
    var reports by remember { mutableStateOf<List<CommunityReportEntity>>(emptyList()) }
    var reload by remember { mutableStateOf(0) }

    LaunchedEffect(reload) {
        withContext(Dispatchers.IO) {
            reports = try {
                DatabaseProvider.get(context).communityReportDao().recent(20)
            } catch (_: Exception) { emptyList() }
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
            Text("Report Scam", style = CS.Heading, color = TextPrimary)
        }

        // ---------------- Privacy disclosure (before storing) ----------------
        SectionCard {
            Text("What happens with your report", style = CS.CardTitle, color = TextPrimary)
            Text(
                "Your report is stored ONLY on this device. CyberShield has no report " +
                    "server and nothing is uploaded — ever.\n\n" +
                    "How it is used: a number you report is flagged by the Call Risk " +
                    "Engine when it calls you again (\"Number previously reported by you\").",
                style = CS.BodyMedium, color = TextSecondary)
        }

        // ---------------- Form ----------------
        SectionCard {
            Text("Report type", style = CS.CardTitle, color = TextPrimary)
            Spacer(Modifier.height(Dsn.S))
            Row(Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(Dsn.S)) {
                listOf("NUMBER" to "Scam Number", "SMS" to "Scam SMS", "URL" to "Scam URL")
                    .forEach { (k, label) ->
                        FilterChip(
                            selected = kind == k,
                            onClick = { kind = k },
                            label = { Text(label, style = CS.Label) })
                    }
            }

            Spacer(Modifier.height(Dsn.M))
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = {
                    Text(when (kind) {
                        "NUMBER" -> "Phone number (e.g. +91 98765 43210)"
                        "SMS" -> "Sender or key phrase from the SMS"
                        else -> "Suspicious URL"
                    })
                })

            Spacer(Modifier.height(Dsn.M))
            Text("Category", style = CS.CardTitle, color = TextPrimary)
            Row(Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(Dsn.S)) {
                listOf(
                    "SCAM" to "Scam", "PHISHING" to "Phishing",
                    "SPAM" to "Spam", "FRAUDULENT_PAYMENT" to "Payment fraud")
                    .forEach { (k, label) ->
                        FilterChip(
                            selected = reportType == k,
                            onClick = { reportType = k },
                            label = { Text(label, style = CS.Label) })
                    }
            }

            Spacer(Modifier.height(Dsn.M))
            OutlinedTextField(
                value = note,
                onValueChange = { note = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Note (optional — stored on this device only)") },
                minLines = 2)

            Spacer(Modifier.height(Dsn.M))
            Button(
                onClick = {
                    val v = value.trim()
                    if (v.isEmpty()) {
                        saved = "Enter the ${when (kind) {
                            "NUMBER" -> "phone number"; "SMS" -> "sender or phrase"; else -> "URL"
                        }} first."
                        return@Button
                    }
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            try {
                                DatabaseProvider.get(context).communityReportDao().insert(
                                    CommunityReportEntity(
                                        createdAt = System.currentTimeMillis(),
                                        kind = kind, value = v,
                                        reportType = reportType, note = note.trim()))
                            } catch (_: Exception) { }
                        }
                        saved = "Report saved on this device. Future calls from this " +
                            "number will carry the reported-by-you indicator."
                        value = ""; note = ""
                        reload++
                    }
                },
                modifier = Modifier.fillMaxWidth().height(Dsn.ButtonHeight),
                shape = MaterialTheme.shapes.medium,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Primary, contentColor = Color_White)
            ) { Text("Save Report (local only)", style = CS.Button) }

            saved?.let {
                Spacer(Modifier.height(Dsn.S))
                Text(it, style = CS.BodyMedium, color = Safe)
            }
        }

        // ---------------- Saved reports ----------------
        if (reports.isNotEmpty()) {
            Text("Your Reports (${reports.size})", style = CS.Heading, color = TextPrimary)
            reports.forEach { r ->
                SectionCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(r.value.take(50), style = CS.CardTitle, color = TextPrimary)
                            Text(
                                "${r.kind} · ${r.reportType} · " +
                                    SimpleDateFormat("MMM d, HH:mm", Locale.US)
                                        .format(Date(r.createdAt)),
                                style = CS.Secondary, color = TextTertiary)
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
                        }) { Text("Remove", style = CS.Label, color = High) }
                    }
                }
            }
        }
    }
}

private val Color_White get() = androidx.compose.ui.graphics.Color.White
