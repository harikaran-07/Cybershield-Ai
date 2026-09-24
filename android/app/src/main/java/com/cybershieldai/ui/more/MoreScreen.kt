package com.cybershieldai.ui.more

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.*

/**
 * MORE tab: security tools, reports and settings.
 */
@Composable
fun MoreScreen(navController: NavHostController) {
    val context = LocalContext.current

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        Text("More", style = CS.ScreenTitle, color = TextPrimary)
        Text("Security tools, reports and settings.",
            style = CS.BodyMedium, color = TextSecondary)

        MoreLink(Icons.Filled.Shield, "Scanner",
            "URL, message, QR, file and APK analysis") { navController.navigate("scan") }
        MoreLink(Icons.Filled.Timeline, "Security Timeline",
            "Every detection with its evidence, chronologically") { navController.navigate("timeline") }
        MoreLink(Icons.Filled.Build, "Incident Center",
            "Correlated security incidents with their evidence") { navController.navigate("incidents") }
        MoreLink(Icons.Filled.Build, "Report Scam",
            "Report a scam number, SMS or URL — stored on this device only") { navController.navigate("report") }
        MoreLink(Icons.Filled.Psychology, "AI Assistant",
            "Offline on-device chatbot — CyberShield AI") { navController.navigate("assistant") }
        MoreLink(Icons.Filled.Memory, "AI Model Settings",
            "Install or remove the on-device AI model (546 MB)") { navController.navigate("ai_model_settings") }
        MoreLink(Icons.Filled.GraphicEq, "AI Media Security",
            "Check audio, images and videos for AI-generation signals") { navController.navigate("media_scan") }
        MoreLink(Icons.Filled.HealthAndSafety, "Notification Diagnostics",
            "Real pipeline status, delivery trail and test notification") { navController.navigate("diagnostics") }
        MoreLink(Icons.Filled.Settings, "Settings",
            "Monitoring, notifications, data and about") { navController.navigate("settings") }

        SectionCard {
            Text("CyberShield AI", style = CS.CardTitle, color = TextPrimary)
            Text("Version 2.1 · Security engine v2",
                style = CS.Secondary, color = TextTertiary)
        }
    }
}

@Composable
private fun MoreLink(
    icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = Surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = MaterialTheme.shapes.small, color = Primary.copy(alpha = 0.16f)) {
                Icon(icon, contentDescription = null, tint = Primary,
                    modifier = Modifier.padding(8.dp).size(20.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title, style = CS.CardTitle, color = TextPrimary)
                Text(subtitle, style = CS.Secondary, color = TextTertiary)
            }
        }
    }
}
