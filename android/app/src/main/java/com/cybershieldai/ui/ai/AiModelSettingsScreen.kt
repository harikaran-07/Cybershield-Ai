package com.cybershieldai.ui.ai

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
import com.cybershieldai.ai.AiModelManager
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.TextSecondary
import kotlinx.coroutines.launch
import java.util.Locale

/**
 * AI Model Settings (spec §20): real install state, download with live
 * progress, delete. The security scanner NEVER depends on this model (§20/§21).
 */
@Composable
fun AiModelSettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val installState by AiModelManager.state.collectAsState()
    val scope = rememberCoroutineScope()

    // Real install state, refreshed when the screen opens.
    var installed by remember { mutableStateOf(AiModelManager.isInstalled(context)) }
    var sizeBytes by remember { mutableStateOf(AiModelManager.installedSizeBytes(context)) }
    LaunchedEffect(installState.idle) {
        if (installState.idle) {
            installed = AiModelManager.isInstalled(context)
            sizeBytes = AiModelManager.installedSizeBytes(context)
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("AI Model Settings", style = MaterialTheme.typography.headlineMedium)
        Text("The chatbot runs entirely on this device. No cloud, no API key, " +
            "no account. CyberShield security scanning works with or without the model.",
            style = MaterialTheme.typography.bodyMedium, color = TextSecondary)

        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(AiModelManager.MODEL_ID, style = MaterialTheme.typography.titleSmall)
                    Text("Quantization: q8 on-device package", style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary)
                    Text(
                        "Storage: " + if (installed)
                            formatBytes(sizeBytes) else "not installed",
                        style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    Text(
                        "Free space: " + formatBytes(AiModelManager.freeSpaceBytes(context)),
                        style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = if (installed) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.errorContainer
                ) {
                    Text(
                        if (installed) "Installed" else "Not installed",
                        Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                        style = MaterialTheme.typography.labelMedium)
                }
            }

            if (installState.downloading) {
                Column(Modifier.padding(top = 10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    LinearProgressIndicator(
                        progress = { installState.progress / 100f },
                        modifier = Modifier.fillMaxWidth())
                    Text("Downloading… ${installState.progress}%",
                        style = MaterialTheme.typography.bodySmall)
                }
            }

            installState.error?.let { err ->
                Text("Install failed: $err", color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 6.dp))
            }

            Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!installed) {
                    Button(
                        onClick = { scope.launch { AiModelManager.install(context) } },
                        enabled = !installState.downloading
                    ) { Text("Install Model") }
                } else {
                    OutlinedButton(
                        onClick = { scope.launch { AiModelManager.delete(context) } },
                        enabled = !installState.downloading
                    ) { Text("Delete Model") }
                }
            }
        }

        SectionCard {
            Text(
                "Short answers by default • streaming generation • model memory is " +
                    "released when the chat closes • the model is never loaded during " +
                    "incoming calls.",
                style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }

        Text(
            "Privacy: the model file, your chats and your reports never leave this " +
                "device. Nothing is uploaded — there is no server to upload to.",
            style = MaterialTheme.typography.bodySmall, color = TextSecondary)
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1L shl 30 -> String.format(Locale.US, "%.1f GB", bytes / 1073741824f)
    bytes >= 1L shl 20 -> String.format(Locale.US, "%.1f MB", bytes / 1048576f)
    bytes >= 1L shl 10 -> String.format(Locale.US, "%.1f KB", bytes / 1024f)
    else -> "$bytes B"
}
