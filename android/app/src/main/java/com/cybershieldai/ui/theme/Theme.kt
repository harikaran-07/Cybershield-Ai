package com.cybershieldai.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * CYBERSHIELD THEME — now SKIN-REACTIVE (UI/UX redesign, functionality untouched).
 *
 * Every color/gradient below used to be a hardcoded val of the single dark
 * theme. They are now live getters into the ACTIVE SKIN (see Skin.kt), so the
 * five design concepts restyle the whole app without any screen-code change:
 * screens keep importing `Primary`, `Surface`, `TextSecondary`, … exactly as
 * before; they simply resolve per selected concept.
 */
val Background: Color get() = SkinState.colors.background
val Surface: Color get() = SkinState.colors.surface
val SurfaceVariant: Color get() = SkinState.colors.surfaceVariant
val Border: Color get() = SkinState.colors.border
val Primary: Color get() = SkinState.colors.primary
val PrimaryDark: Color get() = SkinState.colors.primaryDark
val Safe: Color get() = SkinState.colors.safe
val Warning: Color get() = SkinState.colors.warning
val High: Color get() = SkinState.colors.high
val Critical: Color get() = SkinState.colors.critical
val ScamAmber: Color get() = SkinState.colors.warning // Scam Protection accent
val TextPrimary: Color get() = SkinState.colors.textPrimary
val TextSecondary: Color get() = SkinState.colors.textSecondary
val TextTertiary: Color get() = SkinState.colors.textTertiary

/** Subtle vertical gradient used as the app-wide screen background (live). */
val ScreenGradient: Brush get() = skinGradient(SkinState.colors)

/**
 * One font family for the whole app: the Android system sans-serif
 * (Roboto on every shipping Android device). No bundled or downloaded fonts.
 */
val AppFontFamily = FontFamily.Default

/**
 * CENTRALIZED TYPOGRAPHY SYSTEM (spec §3–§6).
 *
 * Every screen pulls styles from here — no per-screen font sizes.
 * Weights follow the controlled hierarchy: 400 regular, 500 medium,
 * 600 semibold, 700 bold reserved for major emphasis only.
 * Line heights: headings ~1.2×, body 1.4–1.5×.
 * Body/label tiers are skin-adjustable (see SkinType); heading tiers are
 * shared across concepts for consistent hierarchy.
 */
val AppTypography = Typography(
    // Screen title — "CyberShield AI"
    displayLarge = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 32.sp, lineHeight = 40.sp, letterSpacing = 0.sp
    ),
    // Large section heading
    displayMedium = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 26.sp, lineHeight = 32.sp, letterSpacing = 0.sp
    ),
    // Section heading
    displaySmall = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp, lineHeight = 28.sp, letterSpacing = 0.sp
    ),
    // Card title — "AI Media Security"
    headlineLarge = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp, lineHeight = 26.sp, letterSpacing = 0.sp
    ),
    // Sub-card title / emphasis
    headlineMedium = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 18.sp, lineHeight = 24.sp, letterSpacing = 0.sp
    ),
    // Prominent value (e.g. "92", "4 flagged")
    headlineSmall = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 17.sp, lineHeight = 22.sp, letterSpacing = 0.sp
    ),
    // List item title — app names
    titleLarge = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp, lineHeight = 26.sp, letterSpacing = 0.sp
    ),
    titleMedium = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 16.sp, lineHeight = 22.sp, letterSpacing = 0.sp
    ),
    titleSmall = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.sp
    ),
    // Body — descriptions (skin-adjustable via CS getters below)
    bodyLarge = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Normal,
        fontSize = 16.sp, lineHeight = 24.sp, letterSpacing = 0.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Normal,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.sp
    ),
    // Secondary / supporting
    bodySmall = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Normal,
        fontSize = 13.sp, lineHeight = 18.sp, letterSpacing = 0.sp
    ),
    // Label — buttons, tabs, small annotations
    labelLarge = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.2.sp
    ),
    labelMedium = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.2.sp
    ),
    // Caption — timestamps, metadata (tertiary tier)
    labelSmall = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Normal,
        fontSize = 11.sp, lineHeight = 15.sp, letterSpacing = 0.2.sp
    )
)

// ---- Named aliases so screens never hardcode sizes (spec §3) ----
// Body/secondary/label tiers resolve from the ACTIVE SKIN (SkinType) so each
// concept controls text density; heading/display tiers stay shared.
object CS {
    /** Screen title: "CyberShield AI" */
    val ScreenTitle = AppTypography.displayLarge
    /** Page heading: "App Security" */
    val Heading = AppTypography.displayMedium
    /** Section heading */
    val SectionHeading = AppTypography.displaySmall
    /** Card title: "Call Protection" */
    val CardTitle = AppTypography.headlineLarge
    /** Prominent card value: "92", "4 flagged" */
    val CardValue = AppTypography.headlineSmall
    /** Card secondary: "42 apps checked" */
    val CardSecondary: TextStyle get() = SkinState.type.bodyLarge
    /** Body description */
    val Body: TextStyle get() = SkinState.type.bodyLarge
    /** Body medium */
    val BodyMedium: TextStyle get() = SkinState.type.bodyMedium
    /** Secondary text (package names) */
    val Secondary: TextStyle get() = SkinState.type.secondary
    /** Caption / tertiary metadata (timestamps) */
    val Caption: TextStyle get() = SkinState.type.bodySmall
    /** Small label */
    val Label: TextStyle get() = SkinState.type.label
    /** Button text: SCAN NOW */
    val Button = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 16.sp, lineHeight = 20.sp, letterSpacing = 0.5.sp
    )
    /** Big security score: "92" */
    val Score = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 68.sp, lineHeight = 72.sp, letterSpacing = 0.sp
    )
    /** Score unit: "pts" */
    val ScoreUnit = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 18.sp, lineHeight = 24.sp, letterSpacing = 0.sp
    )
    /** Risk score per app row: "24" */
    val ScoreSmall = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp, lineHeight = 30.sp, letterSpacing = 0.sp
    )
    /** Status: SAFE / REVIEW / HIGH RISK */
    val Status = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 14.sp, lineHeight = 18.sp, letterSpacing = 0.3.sp
    )
    /** Bottom navigation label */
    val Nav = TextStyle(
        fontFamily = AppFontFamily, fontWeight = FontWeight.Medium,
        fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.3.sp
    )
    /** Scanning status line */
    val Scanning: TextStyle get() = SkinState.type.bodyLarge
}


@Composable
fun CyberShieldTheme(content: @Composable () -> Unit) {
    // Material scheme follows the ACTIVE skin (light or dark per concept).
    MaterialTheme(
        colorScheme = skinColorScheme(SkinState.colors),
        typography = AppTypography,
        content = content
    )
    // Status-bar icon contrast follows the concept (dark text on light skins).
    val view = LocalView.current
    val dark = SkinState.colors.darkTheme
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            val controller = androidx.core.view.WindowCompat.getInsetsController(window, window.decorView)
            controller.isAppearanceLightStatusBars = !dark
            controller.isAppearanceLightNavigationBars = !dark
        }
    }
}

fun severityColor(severity: String): Color = when (severity) {
    "CRITICAL" -> Critical
    "HIGH" -> High
    "MEDIUM" -> Warning
    "LOW" -> Primary
    else -> Safe
}
