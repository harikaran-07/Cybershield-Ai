package com.cybershieldai.ui.components

import android.content.pm.PackageManager
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cybershieldai.ui.theme.*

/** Animated circular score ring (Phone Manager-style) — centralized score typography. */
@Composable
fun ScoreRing(score: Int?, color: Color, modifier: Modifier = Modifier, scanning: Boolean = false, scanningLabel: String = "") {
    var started by remember { mutableStateOf(false) }
    val fraction by animateFloatAsState(
        targetValue = if (started) (score ?: 0) / 100f else 0f,
        animationSpec = tween(900), label = "scoreRing"
    )
    LaunchedEffect(Unit) { started = true }
    val ringColor = if (scanning) Primary else color
    Box(modifier = modifier.size(Dsn.ScoreRingSize), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(
            progress = { if (scanning) 0.75f else fraction },
            modifier = Modifier.fillMaxSize(),
            strokeWidth = 10.dp,
            trackColor = SurfaceVariant,
            color = ringColor
        )
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            if (scanning) {
                Text("…", style = CS.Score, color = Primary)
            } else if (score != null) {
                Text("$score", style = CS.Score, color = color)
                Text("pts", style = CS.ScoreUnit, color = TextSecondary)
            } else {
                ScoreEmpty()
            }
            if (scanning && scanningLabel.isNotBlank()) {
                Spacer(Modifier.height(Dsn.XS))
                Text(
                    scanningLabel, style = CS.Label, color = TextSecondary,
                    maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )
            }
        }
    }
}

/** Honest empty state inside the ring — no fake score. */
@Composable
fun ScoreEmpty(modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text("Scan", style = CS.CardTitle, color = TextPrimary)
        Text("required", style = CS.Secondary, color = TextSecondary)
    }
}

/** App icon in a rounded tile — falls back to the Android default icon. */
@Composable
fun AppIconTile(packageName: String, modifier: Modifier = Modifier, size: Int = 44) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val pm = context.packageManager
    val icon = remember(packageName) {
        try {
            pm.getApplicationIcon(packageName)
        } catch (_: Exception) {
            pm.defaultActivityIcon
        }
    }
    Box(
        modifier = modifier.size(size.dp).clip(RoundedCornerShape(12.dp)),
        contentAlignment = Alignment.Center
    ) {
        val bmp = remember(icon) { (icon as? android.graphics.drawable.BitmapDrawable)?.bitmap }
        if (bmp != null) {
            Image(
                bitmap = bmp.asImageBitmap(),
                contentDescription = null,
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize().padding(2.dp)
            )
        } else {
            // AdaptiveIconDrawable etc.: draw via Canvas, else letter fallback.
            val canvasBmp = remember(icon) {
                try {
                    android.graphics.Bitmap.createBitmap(96, 96, android.graphics.Bitmap.Config.ARGB_8888).also { bmp2 ->
                        icon.setBounds(0, 0, 96, 96)
                        icon.draw(android.graphics.Canvas(bmp2))
                    }
                } catch (_: Exception) { null }
            }
            if (canvasBmp != null) {
                Image(
                    bitmap = canvasBmp.asImageBitmap(),
                    contentDescription = null,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize()
                )
            } else {
                Surface(shape = RoundedCornerShape(12.dp), color = SurfaceVariant) {
                    Text(
                        packageName.substringAfterLast('.').take(1).uppercase(),
                        fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Primary,
                        modifier = Modifier.padding(8.dp)
                    )
                }
            }
        }
    }
}

/** Rounded status pill (SAFE / REVIEW / HIGH RISK / severity words). */
@Composable
fun StatusPill(text: String, colorKey: String, modifier: Modifier = Modifier) {
    val color = severityColor(colorKey)
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(Dsn.ChipCorner),
        color = color.copy(alpha = 0.16f)
    ) {
        Text(
            text,
            style = CS.Status,
            color = color,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
        )
    }
}

/** Compact relative time for events ("just now", "12m ago", "3h ago", date). */
fun relativeTime(timestamp: Long, now: Long = System.currentTimeMillis()): String {
    val diff = now - timestamp
    val m = diff / 60000
    return when {
        m < 1 -> "just now"
        m < 60 -> "${m}m ago"
        m < 1440 -> "${m / 60}h ago"
        m < 10080 -> "${m / 1440}d ago"
        else -> java.text.DateFormat.getDateInstance(java.text.DateFormat.SHORT).format(java.util.Date(timestamp))
    }
}

/** Rounded card used across all screens — dark surface with the subtle
 *  border treatment from the reference image. */
@Composable
fun SectionCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp), content = content)
    }
}

/**
 * Semicircular risk gauge from the reference Threat Alert screen: 180° arc
 * colored by severity, with the numeric score centered inside and a label
 * underneath. The track/value arcs are drawn on a Canvas — a real component,
 * driven entirely by the actual risk score.
 */

/**
 * Circular protection score (Phone-Manager-style, spec §2): large arc, score
 * in the middle, "pts" caption. The value comes from the REAL score engine —
 * never random. Optional [subtitle] shows live scan phase or status line.
 */
@Composable
fun CircularProtectionScore(
    score: Int?,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    scanning: Boolean = false,
    onClick: (() -> Unit)? = null
) {
    val display = score ?: 0
    val color = when {
        score == null -> TextTertiary
        display >= 80 -> Safe
        display >= 50 -> Warning
        else -> High
    }
    val progress = remember(display) { Animatable(0f) }
    LaunchedEffect(display) {
        progress.animateTo(
            display / 100f,
            animationSpec = tween(900, easing = FastOutSlowInEasing))
    }
    val stroke = 14.dp
    Box(modifier = modifier.size(220.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val strokePx = stroke.toPx()
            val inset = strokePx / 2f + 2.dp.toPx()
            val arc = androidx.compose.ui.geometry.Size(size.width - inset * 2, size.height - inset * 2)
            drawArc(
                color = color.copy(alpha = 0.15f),
                startAngle = -90f, sweepAngle = 360f, useCenter = false,
                topLeft = androidx.compose.ui.geometry.Offset(inset, inset),
                size = arc,
                style = Stroke(strokePx, cap = StrokeCap.Round))
            drawArc(
                color = color,
                startAngle = -90f, sweepAngle = 360f * progress.value, useCenter = false,
                topLeft = androidx.compose.ui.geometry.Offset(inset, inset),
                size = arc,
                style = Stroke(strokePx, cap = StrokeCap.Round))
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                if (score == null) "—" else "$display",
                style = TextStyle(fontSize = 64.sp, fontWeight = FontWeight.Bold, color = TextPrimary))
            Text("pts", style = TextStyle(fontSize = 16.sp, color = TextTertiary))
            if (!subtitle.isNullOrEmpty()) {
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (scanning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(12.dp), strokeWidth = 2.dp, color = Primary)
                        Spacer(Modifier.width(6.dp))
                    }
                    Text(subtitle, style = TextStyle(fontSize = 13.sp, color = TextSecondary))
                }
            }
        }
        onClick?.let {
            Box(Modifier.fillMaxSize().clickable(onClick = it))
        }
    }
}

@Composable
fun SemicircleRiskGauge(score: Int, severity: String, modifier: Modifier = Modifier) {
    val color = severityColor(severity)
    var started by remember { mutableStateOf(false) }
    val sweep by animateFloatAsState(
        targetValue = if (started) (score.coerceIn(0, 100) / 100f) * 180f else 0f,
        animationSpec = tween(900), label = "gaugeSweep"
    )
    LaunchedEffect(Unit) { started = true }

    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Box(modifier = Modifier.size(124.dp, 76.dp), contentAlignment = Alignment.BottomCenter) {
            androidx.compose.foundation.Canvas(Modifier.fillMaxSize()) {
                val stroke = 12.dp.toPx()
                val diameter = size.width - stroke
                val arcSize = androidx.compose.ui.geometry.Size(diameter, diameter)
                val topLeft = androidx.compose.ui.geometry.Offset(
                    stroke / 2f, size.height - diameter / 2f - stroke / 2f)
                drawArc(
                    color = SurfaceVariant, startAngle = 180f, sweepAngle = 180f,
                    useCenter = false, topLeft = topLeft, size = arcSize,
                    style = androidx.compose.ui.graphics.drawscope.Stroke(
                        stroke, cap = androidx.compose.ui.graphics.StrokeCap.Round))
                drawArc(
                    color = color, startAngle = 180f, sweepAngle = sweep,
                    useCenter = false, topLeft = topLeft, size = arcSize,
                    style = androidx.compose.ui.graphics.drawscope.Stroke(
                        stroke, cap = androidx.compose.ui.graphics.StrokeCap.Round))
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    "$score",
                    fontSize = 30.sp, fontWeight = FontWeight.Bold, color = color)
                Text("/100", fontSize = 12.sp, color = TextSecondary)
            }
        }
        Spacer(Modifier.height(6.dp))
        Text("Risk Score", fontSize = 12.sp, color = TextSecondary)
    }
}

/** Severity chip (SAFE/LOW/MEDIUM/HIGH/CRITICAL). */
@Composable
fun SeverityChip(severity: String, modifier: Modifier = Modifier) {
    val color = severityColor(severity)
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(50),
        color = color.copy(alpha = 0.15f)
    ) {
        Text(
            text = severity,
            color = color,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp)
        )
    }
}

/** Animated 0–100 risk gauge (circular variant, kept for detail screens). */
@Composable
fun RiskScoreGauge(score: Int, severity: String, modifier: Modifier = Modifier) {
    val color = severityColor(severity)
    var started by remember { mutableStateOf(false) }
    val fraction by animateFloatAsState(
        targetValue = if (started) score / 100f else 0f,
        animationSpec = tween(900), label = "risk"
    )
    LaunchedEffect(Unit) { started = true }

    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            modifier = Modifier
                .size(132.dp)
                .clip(RoundedCornerShape(66.dp))
                .background(SurfaceVariant),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("$score", fontSize = 34.sp, fontWeight = FontWeight.Bold, color = color)
                Text("/ 100", fontSize = 12.sp, color = TextSecondary)
            }
        }
        Spacer(Modifier.height(6.dp))
        Box(
            Modifier
                .fillMaxWidth(0.7f)
                .height(8.dp)
                .clip(RoundedCornerShape(4.dp))
                .background(SurfaceVariant)
        ) {
            Box(
                Modifier
                    .fillMaxWidth(fraction)
                    .fillMaxHeight()
                    .clip(RoundedCornerShape(4.dp))
                    .background(color)
            )
        }
        Spacer(Modifier.height(4.dp))
        SeverityChip(severity)
    }
}

/** Quick-action tile for the home/scan grids. */
@Composable
fun QuickScanCard(title: String, subtitle: String, icon: String, onClick: () -> Unit,
                  modifier: Modifier = Modifier) {
    Card(
        onClick = onClick,
        modifier = modifier.height(112.dp),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceVariant)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(14.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text(icon, fontSize = 24.sp)
            Spacer(Modifier.height(8.dp))
            Text(title, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        }
    }
}

/** Simple horizontal bar used in dashboard charts. */
@Composable
fun StatBar(label: String, value: Int, maxValue: Int, color: Color) {
    val fraction = if (maxValue > 0) value.toFloat() / maxValue else 0f
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, style = MaterialTheme.typography.bodyMedium,
                color = TextPrimary, modifier = Modifier.weight(1f))
            Text("$value", style = MaterialTheme.typography.labelMedium, color = TextSecondary)
        }
        Spacer(Modifier.height(4.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp))
                .background(SurfaceVariant)
        ) {
            Box(
                Modifier
                    .fillMaxWidth(fraction)
                    .fillMaxHeight()
                    .clip(RoundedCornerShape(3.dp))
                    .background(color)
            )
        }
        Spacer(Modifier.height(8.dp))
    }
}

/** Friendly state views. */
@Composable
fun LoadingView(message: String = "Analyzing…") {
    Column(
        modifier = Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        CircularProgressIndicator(color = Primary)
        Spacer(Modifier.height(14.dp))
        Text(message, color = TextSecondary, textAlign = TextAlign.Center)
    }
}

@Composable
fun ErrorView(message: String) {
    SectionCard {
        Text("⚠ $message", color = High, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
fun OfflineBanner(visible: Boolean) {
    if (!visible) return
    Surface(
        color = Warning.copy(alpha = 0.12f),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            "Offline protection mode — limited local checks only",
            color = Warning,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
        )
    }
}

@Composable
fun IndicatorList(indicators: List<String>) {
    Column {
        indicators.take(8).forEach { ind ->
            Row(modifier = Modifier.padding(vertical = 3.dp)) {
                Text("• ", color = Primary)
                Text(ind, style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
            }
        }
    }
}
