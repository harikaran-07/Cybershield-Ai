package com.cybershieldai.ui.apps

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.cybershieldai.ui.components.AppIconTile
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.components.StatusPill
import com.cybershieldai.ui.theme.CS
import com.cybershieldai.ui.theme.Dsn
import com.cybershieldai.ui.theme.TextPrimary
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.TextTertiary
import com.cybershieldai.ui.theme.severityColor
import com.cybershieldai.utils.AppRiskAnalyzer
import com.cybershieldai.utils.AppScanCache

/**
 * App detail screen (spec §6): full per-app security/privacy breakdown with
 * permission review. Honest wording throughout — a sensitive permission is a
 * "reason to review", never proof of spying or malware.
 */
@Composable
fun AppDetailScreen(packageName: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val result = remember(packageName) {
        (AppScanCache.userRisks + AppScanCache.systemRisks)
            .firstOrNull { it.app.packageName == packageName }
    }

    Column(
        Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Dsn.L),
        verticalArrangement = Arrangement.spacedBy(Dsn.M)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back", tint = TextSecondary)
            }
            Text("App Security", style = CS.ScreenTitle, color = TextPrimary)
        }

        if (result == null) {
            SectionCard {
                Text("App details unavailable", style = CS.CardTitle)
                Text(
                    "This app's analysis is no longer in the cache. Run a scan from Home and try again.",
                    style = CS.BodyMedium, color = TextSecondary)
            }
            return@Column
        }

        // ---- Header card: identity + scores ----
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AppIconTile(packageName = result.app.packageName, size = 52)
                Spacer(Modifier.width(Dsn.M))
                Column(Modifier.weight(1f)) {
                    Text(result.appName, style = CS.Heading, color = TextPrimary)
                    Text(result.app.packageName, style = CS.Secondary,
                        color = TextTertiary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    result.versionName?.let {
                        Text("version $it", style = CS.Secondary, color = TextTertiary)
                    }
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text("${result.overallScore}", style = CS.ScoreSmall,
                        color = severityColor(AppRiskAnalyzer.statusColorKey(result.status)))
                    StatusPill(result.status, AppRiskAnalyzer.statusColorKey(result.status))
                }
            }
            Spacer(Modifier.height(Dsn.M))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                ScoreBlock("Security Score", result.securityScore)
                ScoreBlock("Privacy Score", result.privacyScore)
                ScoreBlock("Malware", result.malwareEvidence,
                    suffix = if (result.malwareEvidence == 0) " (none)" else "")
            }
        }

        // ---- Honest framing ----
        SectionCard {
            Text("Why review?", style = CS.CardTitle)
            Text(
                when {
                    result.app.isSystemApp ->
                        "This is a platform component. Powerful permissions are expected " +
                        "for system software and are not user malware."
                    result.status == AppRiskAnalyzer.SAFE ->
                        "No elevated permission risk indicators found for this app."
                    else ->
                        "The app has sensitive permissions that may be relevant to its " +
                        "functionality. A permission is a reason to review — it does not " +
                        "prove spying, malware, or data theft."
                },
                style = CS.BodyMedium, color = TextSecondary)
        }

        // ---- Permission categories (sensitive only) ----
        SectionCard {
            Text("Permissions", style = CS.CardTitle)
            Spacer(Modifier.height(Dsn.S))
            val granted = result.grantedSensitive
            if (granted.isEmpty()) {
                Text("No sensitive permissions are granted to this app.",
                    style = CS.BodyMedium, color = TextSecondary)
            } else {
                granted.forEach { perm ->
                    val label = AppRiskAnalyzer.SENSITIVE[perm] ?: perm.substringAfterLast('.')
                    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Text("⚠", style = CS.BodyMedium,
                            color = severityColor("MEDIUM"))
                        Spacer(Modifier.width(Dsn.S))
                        Text("$label — sensitive permission granted",
                            style = CS.BodyMedium, color = TextPrimary)
                    }
                }
            }
            val others = result.permissions.size - granted.size
            if (others > 0) {
                Spacer(Modifier.height(Dsn.S))
                Text("Plus $others other (non-sensitive) permission(s) requested.",
                    style = CS.Secondary, color = TextTertiary)
            }
        }

        // ---- Findings ----
        SectionCard {
            Text("Findings", style = CS.CardTitle)
            result.findings.forEach { f ->
                Text("• $f", style = CS.BodyMedium, color = TextSecondary,
                    modifier = Modifier.padding(vertical = 2.dp))
            }
        }

        // ---- Install info ----
        result.installSource?.let {
            SectionCard {
                Text("Install information", style = CS.CardTitle)
                Text("Source: $it", style = CS.BodyMedium, color = TextSecondary)
            }
        }

        Button(
            onClick = { openAppSettings(context, result.app.packageName) },
            modifier = Modifier.fillMaxWidth().height(Dsn.ButtonHeight),
            shape = RoundedCornerShape(Dsn.ButtonCorner),
            colors = ButtonDefaults.buttonColors(
                containerColor = com.cybershieldai.ui.theme.Primary,
                contentColor = androidx.compose.ui.graphics.Color.Black)
        ) { Text("Review in Android Settings", style = CS.Button) }
    }
}

@Composable
private fun ScoreBlock(label: String, value: Int, suffix: String = "") {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text("$value$suffix", style = CS.ScoreSmall, color = TextPrimary)
        Text(label, style = CS.Secondary, color = TextTertiary)
    }
}

private fun openAppSettings(context: Context, packageName: String) {
    try {
        context.startActivity(
            android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(android.net.Uri.parse("package:$packageName"))
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    } catch (_: Exception) { }
}
