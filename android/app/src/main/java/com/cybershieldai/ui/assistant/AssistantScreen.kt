package com.cybershieldai.ui.assistant

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cybershieldai.ai.CyberShieldChat
import com.cybershieldai.ai.ChatContextBuilder
import com.cybershieldai.ui.theme.Primary
import com.cybershieldai.ui.theme.SurfaceVariant
import com.cybershieldai.ui.theme.TextSecondary
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * CyberShield AI (spec §4) — fully on-device chat around [CyberShieldChat].
 * No network access anywhere in this screen (spec §1/§18). Polished security
 * cards, formatted responses, quick actions, honest model states, IME-safe
 * input; releases model memory when the user leaves (§21).
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AssistantScreen(aiModelSettings: () -> Unit) {
    val context = LocalContext.current
    val chat = remember { CyberShieldChat(context) }
    DisposableEffect(Unit) { onDispose { chat.dispose() } }

    val state by chat.messages.collectAsState()
    val busy by chat.busy.collectAsState()
    val modelState by chat.modelState.collectAsState()
    val clipboard = LocalClipboardManager.current
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    var input by remember { mutableStateOf("") }
    val timeFmt = remember { SimpleDateFormat("HH:mm", Locale.US) }

    fun ask(question: String) {
        if (busy) return
        scope.launch {
            val ctx = ChatContextBuilder.build(context)
            chat.send(question, ctx)
        }
    }

    LaunchedEffect(state.size) {
        if (state.isNotEmpty()) listState.animateScrollToItem(state.size - 1)
    }

    Column(Modifier.fillMaxSize()
        .windowInsetsPadding(WindowInsets.ime)
        .windowInsetsPadding(WindowInsets.navigationBars)
        .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)) {

        // ---- Header ---------------------------------------------------------
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("CyberShield AI",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold)
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusDot(ready = modelState == CyberShieldChat.ModelState.READY)
                    Text("On-device • Offline",
                        style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
            // Compact model chip — never oversized (§1)
            Surface(
                shape = RoundedCornerShape(50),
                color = when (modelState) {
                    CyberShieldChat.ModelState.READY -> MaterialTheme.colorScheme.primaryContainer
                    CyberShieldChat.ModelState.LOADING -> MaterialTheme.colorScheme.secondaryContainer
                    else -> MaterialTheme.colorScheme.errorContainer
                }
            ) {
                Text(
                    modelStatusLabel(modelState),
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                )
            }
        }

        // ---- Model missing banner ------------------------------------------
        if (modelState == CyberShieldChat.ModelState.NOT_INSTALLED) {
            Surface(shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.errorContainer) {
                Column(Modifier.fillMaxWidth().padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("AI model unavailable.",
                        style = MaterialTheme.typography.titleSmall)
                    Text(
                        "Basic CyberShield security guidance is still available. " +
                            "Install the on-device model to enable full answers.",
                        style = MaterialTheme.typography.bodySmall)
                    Button(onClick = aiModelSettings) { Text("AI Model Settings") }
                }
            }
        }

        // ---- Messages -------------------------------------------------------
        LazyColumn(
            modifier = Modifier.weight(1f),
            state = listState,
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(state, key = { it.timestamp to it.content.hashCode() }) { msg ->
                val isUser = msg.role == CyberShieldChat.ChatMessage.Role.USER
                val isLastAi = !isUser && msg == state.lastOrNull {
                    it.role == CyberShieldChat.ChatMessage.Role.ASSISTANT
                } && msg.content.isNotBlank()
                if (isUser) {
                    UserBubble(msg.content, timeFmt.format(msg.timestamp))
                } else {
                    AiResponseCard(
                        content = msg.content,
                        time = timeFmt.format(msg.timestamp),
                        showActions = isLastAi,
                        onCopy = { clipboard.setText(AnnotatedString(msg.content)) },
                        onRegenerate = { chat.retry() }
                    )
                }
            }
            if (busy) item {
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CircularProgressIndicator(
                        Modifier.size(16.dp), strokeWidth = 2.dp, color = Primary)
                    Text(
                        if (modelState == CyberShieldChat.ModelState.LOADING)
                            "THINKING…" else "GENERATING…",
                        style = MaterialTheme.typography.labelMedium, color = TextSecondary)
                }
            }
            // Quick actions under the latest AI response (§5) — real requests.
            if (!busy && state.any {
                    it.role == CyberShieldChat.ChatMessage.Role.ASSISTANT &&
                        it.content.isNotBlank()
                }) {
                item {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        QuickChip("How it works") {
                            ask("How does CyberShield call screening work?")
                        }
                        QuickChip("Common threats") {
                            ask("What are the most common phone scams I should know about?")
                        }
                        QuickChip("Scan a message") {
                            ask("How do I check whether a text message is a scam?")
                        }
                        QuickChip("Security tips") {
                            ask("Give me practical tips to stay safe from scam calls.")
                        }
                        QuickChip("More details") {
                            ask("Summarize the security alerts recorded on this device.")
                        }
                    }
                }
            }
        }

        // ---- Input row (§6) -------------------------------------------------
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Ask a cybersecurity question...") },
                maxLines = 4,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary)
            )
            if (busy) {
                FilledTonalIconButton(onClick = { chat.stop() }) {
                    Icon(Icons.Filled.Stop, contentDescription = "Stop generation")
                }
            } else {
                Button(
                    onClick = {
                        val text = input
                        input = ""
                        ask(text)
                    },
                    enabled = input.isNotBlank() &&
                        modelState != CyberShieldChat.ModelState.NOT_INSTALLED
                ) { Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send") }
            }
        }

        // ---- Subtle footer controls (§9) ------------------------------------
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { chat.retry() },
                enabled = !busy && state.isNotEmpty()) {
                Icon(Icons.Filled.Refresh, null, Modifier.size(16.dp)); Text(" Retry",
                style = MaterialTheme.typography.labelMedium)
            }
            TextButton(onClick = { chat.clear() },
                enabled = !busy && state.isNotEmpty()) {
                Icon(Icons.Filled.Delete, null, Modifier.size(16.dp)); Text(" Clear chat",
                style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

@Composable
private fun StatusDot(ready: Boolean) {
    val color = if (ready) androidx.compose.ui.graphics.Color(0xFF4ADE80)
    else androidx.compose.ui.graphics.Color(0xFFFBBF24)
    androidx.compose.foundation.Canvas(Modifier.size(8.dp)) {
        drawCircle(color)
    }
}

@Composable
private fun UserBubble(text: String, time: String) {
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.End) {
        Surface(
            shape = RoundedCornerShape(
                topStart = 16.dp, topEnd = 16.dp,
                bottomStart = 16.dp, bottomEnd = 4.dp),
            color = Primary.copy(alpha = 0.22f),
            border = BorderStroke(1.dp, Primary.copy(alpha = 0.35f))
        ) {
            Text(text,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp))
        }
        Text(time, style = MaterialTheme.typography.labelSmall,
            color = TextSecondary, modifier = Modifier.padding(top = 2.dp, end = 4.dp))
    }
}

@Composable
private fun AiResponseCard(
    content: String,
    time: String,
    showActions: Boolean,
    onCopy: () -> Unit,
    onRegenerate: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(
            topStart = 4.dp, topEnd = 16.dp, bottomStart = 16.dp, bottomEnd = 16.dp),
        color = SurfaceVariant,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp)) {
            // Card header (§3)
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Filled.Security, contentDescription = null,
                    tint = Primary, modifier = Modifier.size(18.dp))
                Column {
                    Text("CyberShield AI",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold)
                    Text("Cybersecurity Assistant",
                        style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                }
            }
            HorizontalDivider(
                Modifier.padding(vertical = 8.dp),
                color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))

            if (content.isBlank()) {
                Text("…", color = TextSecondary, fontSize = 14.sp)
            } else {
                FormattedSecurityText(content)
            }

            Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(time, style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                Spacer(Modifier.weight(1f))
                if (showActions) {
                    IconButton(onClick = onCopy, modifier = Modifier.size(30.dp)) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy response",
                            tint = TextSecondary, modifier = Modifier.size(16.dp))
                    }
                    IconButton(onClick = onRegenerate, modifier = Modifier.size(30.dp)) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Regenerate response",
                            tint = TextSecondary, modifier = Modifier.size(16.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun QuickChip(label: String, onClick: () -> Unit) {
    AssistChip(
        onClick = onClick,
        label = { Text(label, style = MaterialTheme.typography.labelMedium) },
        colors = AssistChipDefaults.assistChipColors(
            containerColor = MaterialTheme.colorScheme.surface,
            labelColor = Primary
        ),
        border = BorderStroke(1.dp, Primary.copy(alpha = 0.4f))
    )
}

// ---- Response formatting (§3/§4) -------------------------------------------

private val SECURITY_TERMS = listOf(
    "phishing", "smishing", "vishing", "scam", "fraud", "malware", "spyware",
    "ransomware", "spoofing", "OTP", "PIN", "CVV", "password", "2FA",
    "two-factor", "verification code", "phishing link", "caller ID"
)

/** Renders model output with headings, bullets, numbered lists and highlighted security terms. */
@Composable
fun FormattedSecurityText(content: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        content.lines().forEach { raw ->
            val line = raw.trim()
            when {
                line.isEmpty() -> Spacer(Modifier.height(4.dp))
                line.startsWith("#") -> Text(
                    line.trimStart('#', ' ', '*'),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = Primary)
                line.startsWith("•") || line.startsWith("- ") || line.startsWith("* ") ->
                    BulletRow(line.dropWhile { it == '•' || it == '-' || it == '*' }.trim())
                Regex("^\\d+[.)]\\s").containsMatchIn(line) -> BulletRow(line, numbered = true)
                line.endsWith(":") && line.length <= 48 -> Text(
                    line, style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold)
                else -> Text(inlineStylized(line),
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun BulletRow(text: String, numbered: Boolean = false) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(if (numbered) text.takeWhile { !it.isWhitespace() }.trimEnd('.', ')')
             else "•",
            style = MaterialTheme.typography.bodyMedium,
            color = Primary, fontWeight = FontWeight.Bold)
        Text(inlineStylized(
            if (numbered) text.dropWhile { !it.isWhitespace() }.trim() else text),
            style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * Inline styling: `**bold**` spans become accent-colored semibold; known
 * security terms get the accent color for at-a-glance scanning (§3).
 */
fun inlineStylized(text: String): AnnotatedString = buildAnnotatedString {
    val boldSplit = text.split("**")
    boldSplit.forEachIndexed { idx, part ->
        if (idx % 2 == 1) {
            withStyle(SpanStyle(fontWeight = FontWeight.SemiBold, color = Primary)) {
                append(part)
            }
        } else {
            var cursor = 0
            val lower = part.lowercase()
            val hits = mutableListOf<Triple<Int, Int, String>>()
            SECURITY_TERMS.forEach { term ->
                var from = 0
                val needle = term.lowercase()
                while (true) {
                    val at = lower.indexOf(needle, from)
                    if (at < 0) break
                    if (hits.none { at < it.second && it.first <= at + needle.length }) {
                        hits.add(Triple(at, at + needle.length, term))
                    }
                    from = at + needle.length
                }
            }
            hits.sortedBy { it.first }.forEach { (start, end, term) ->
                if (start > cursor) append(part.substring(cursor, start))
                withStyle(SpanStyle(fontWeight = FontWeight.SemiBold, color = Primary)) {
                    append(part.substring(start, end))
                }
                cursor = end
            }
            if (cursor < part.length) append(part.substring(cursor))
        }
    }
}

private fun modelStatusLabel(s: CyberShieldChat.ModelState): String = when (s) {
    CyberShieldChat.ModelState.READY -> "MODEL: READY"
    CyberShieldChat.ModelState.LOADING -> "THINKING…"
    CyberShieldChat.ModelState.ERROR -> "ERROR"
    else -> "MODEL UNAVAILABLE"
}
