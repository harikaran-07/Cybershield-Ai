package com.cybershieldai.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * UI/UX SKIN SYSTEM (design-concept switcher).
 *
 * Five complete design concepts share ONE app: every screen keeps reading the
 * same tokens (Primary, Surface, Dsn.M, CS.CardTitle, …), but those tokens are
 * resolved live from the ACTIVE SKIN. Switching the concept in Settings
 * re-skins the entire app instantly — no screen code changes, no functional
 * changes. Only visuals (colors, spacing, corners, type density) differ.
 *
 * DESIGN 1 — Modern Security Dashboard  (clean light dashboard)
 * DESIGN 2 — Premium Dark Cybersecurity (glass-dark, glowing accents)
 * DESIGN 3 — Minimal & Professional     (ultra-clean light, sharp corners)
 * DESIGN 4 — Guided Security Experience (friendly dark, large touch targets)
 * DESIGN 5 — Advanced Security Center   (dense dark pro, steel accent)
 */

enum class UiConcept(val id: String, val label: String, val description: String) {
    DASHBOARD("dashboard", "Modern Dashboard",
        "Clean modern dashboard, rounded cards, light mode"),
    PREMIUM_DARK("premium_dark", "Premium Dark",
        "Glass-dark cybersecurity look with glowing violet accents"),
    MINIMAL("minimal", "Minimal Pro",
        "Ultra-clean, minimal colors, large whitespace"),
    GUIDED("guided", "Guided Experience",
        "Step-by-step friendly flows with large touch targets"),
    ADVANCED("advanced", "Security Center",
        "Dense professional center for advanced users");

    companion object {
        fun fromId(id: String?): UiConcept =
            entries.firstOrNull { it.id == id } ?: DASHBOARD
    }
}

/** All color tokens a skin can restyle. */
data class SkinColors(
    val background: Color,
    val surface: Color,
    val surfaceVariant: Color,
    val border: Color,
    val primary: Color,
    val primaryDark: Color,
    val safe: Color,
    val warning: Color,
    val high: Color,
    val critical: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textTertiary: Color,
    val gradientTop: Color,
    val gradientBottom: Color,
    val darkTheme: Boolean
)

/** Spacing / corner / control-dimension tokens a skin can restyle. */
data class SkinDims(
    val xs: Dp, val s: Dp, val m: Dp, val l: Dp,
    val xl: Dp, val xxl: Dp, val xxxl: Dp,
    val cardCorner: Dp,
    val cardCornerSm: Dp,
    val buttonCorner: Dp,
    val buttonHeight: Dp,
    val cardElevation: Dp
)

/** Typography density a skin can restyle (body/label tiers). */
data class SkinType(
    val bodyLarge: TextStyle,
    val bodyMedium: TextStyle,
    val bodySmall: TextStyle,
    val label: TextStyle,
    val secondary: TextStyle
)

/** One complete design concept. */
data class Skin(
    val colors: SkinColors,
    val dims: SkinDims,
    val type: SkinType
)

/** Central skin definitions (declared before SkinState: no forward refs). */
object Skins {

    private val baseType = AppTypography

    private fun typeVariant(bodyL: Int, bodyM: Int, bodyS: Int, label: Int, sec: Int) = SkinType(
        bodyLarge = baseType.bodyLarge.copy(fontSize = bodyL.sp, lineHeight = (bodyL + 8).sp),
        bodyMedium = baseType.bodyMedium.copy(fontSize = bodyM.sp, lineHeight = (bodyM + 6).sp),
        bodySmall = baseType.bodySmall.copy(fontSize = bodyS.sp, lineHeight = (bodyS + 5).sp),
        label = baseType.labelMedium.copy(fontSize = label.sp, lineHeight = (label + 4).sp),
        secondary = baseType.bodySmall.copy(fontSize = sec.sp, lineHeight = (sec + 5).sp)
    )

    private val defaultDims = SkinDims(
        xs = 4.dp, s = 8.dp, m = 12.dp, l = 16.dp,
        xl = 20.dp, xxl = 24.dp, xxxl = 32.dp,
        cardCorner = 20.dp, cardCornerSm = 14.dp, buttonCorner = 28.dp,
        buttonHeight = 56.dp, cardElevation = 2.dp
    )

    // ------------------------------------------------------------------
    // DESIGN 1 — Modern Security Dashboard (light, clean, professional)
    // ------------------------------------------------------------------
    val DASHBOARD = Skin(
        colors = SkinColors(
            background = Color(0xFFF6F7FB), surface = Color(0xFFFFFFFF),
            surfaceVariant = Color(0xFFEEF0F8), border = Color(0xFFE1E5F0),
            primary = Color(0xFF5B54E8), primaryDark = Color(0xFF4A43C9),
            safe = Color(0xFF16A34A), warning = Color(0xFFD97706),
            high = Color(0xFFDC2626), critical = Color(0xFFB91C1C),
            textPrimary = Color(0xFF0F172A), textSecondary = Color(0xFF475569),
            textTertiary = Color(0xFF64748B),
            gradientTop = Color(0xFFF7F8FC), gradientBottom = Color(0xFFECEFF8),
            darkTheme = false
        ),
        dims = defaultDims,
        type = typeVariant(16, 14, 13, 12, 13)
    )

    // ------------------------------------------------------------------
    // DESIGN 2 — Premium Dark (glass surfaces, glowing violet)
    // ------------------------------------------------------------------
    val PREMIUM_DARK = Skin(
        colors = SkinColors(
            background = Color(0xFF05070D), surface = Color(0xFF0D1424),
            surfaceVariant = Color(0xFF141D33), border = Color(0xFF2C3A66),
            primary = Color(0xFF7C6CFF), primaryDark = Color(0xFF5A4BD4),
            safe = Color(0xFF2ED573), warning = Color(0xFFFFB020),
            high = Color(0xFFFF5A5F), critical = Color(0xFFE11D48),
            textPrimary = Color(0xFFF4F6FF), textSecondary = Color(0xFF9BA6C6),
            textTertiary = Color(0xFF66719A),
            gradientTop = Color(0xFF05070D), gradientBottom = Color(0xFF0B1026),
            darkTheme = true
        ),
        dims = defaultDims.copy(
            cardCorner = 24.dp, cardCornerSm = 18.dp,
            buttonCorner = 30.dp, cardElevation = 6.dp
        ),
        type = typeVariant(16, 14, 13, 12, 13)
    )

    // ------------------------------------------------------------------
    // DESIGN 3 — Minimal & Professional (light, sharp, quiet)
    // ------------------------------------------------------------------
    val MINIMAL = Skin(
        colors = SkinColors(
            background = Color(0xFFFAFAFB), surface = Color(0xFFFFFFFF),
            surfaceVariant = Color(0xFFF2F3F5), border = Color(0xFFE5E7EB),
            primary = Color(0xFF4F46E5), primaryDark = Color(0xFF4338CA),
            safe = Color(0xFF15803D), warning = Color(0xFFB45309),
            high = Color(0xFFB91C1C), critical = Color(0xFF991B1B),
            textPrimary = Color(0xFF111827), textSecondary = Color(0xFF4B5563),
            textTertiary = Color(0xFF6B7280),
            gradientTop = Color(0xFFFAFAFB), gradientBottom = Color(0xFFF3F4F6),
            darkTheme = false
        ),
        dims = defaultDims.copy(
            cardCorner = 12.dp, cardCornerSm = 10.dp,
            buttonCorner = 12.dp, buttonHeight = 52.dp, cardElevation = 0.dp
        ),
        type = typeVariant(16, 14, 13, 12, 13)
    )

    // ------------------------------------------------------------------
    // DESIGN 4 — Guided Security Experience (friendly dark, big targets)
    // ------------------------------------------------------------------
    val GUIDED = Skin(
        colors = SkinColors(
            background = Color(0xFF0B1020), surface = Color(0xFF141B33),
            surfaceVariant = Color(0xFF1B2547), border = Color(0xFF2E3C6E),
            primary = Color(0xFF8B7CFF), primaryDark = Color(0xFF6C5CE7),
            safe = Color(0xFF34D399), warning = Color(0xFFFBBF24),
            high = Color(0xFFF87171), critical = Color(0xFFEF4444),
            textPrimary = Color(0xFFF8FAFF), textSecondary = Color(0xFFA5B0D4),
            textTertiary = Color(0xFF707CA8),
            gradientTop = Color(0xFF0B1020), gradientBottom = Color(0xFF121A38),
            darkTheme = true
        ),
        dims = defaultDims.copy(
            xs = 6.dp, s = 10.dp, m = 14.dp, l = 18.dp,
            xl = 22.dp, xxl = 26.dp, xxxl = 34.dp,
            cardCorner = 24.dp, cardCornerSm = 18.dp,
            buttonCorner = 32.dp, buttonHeight = 64.dp
        ),
        type = typeVariant(17, 15, 14, 13, 14) // roomier type for newcomers
    )

    // ------------------------------------------------------------------
    // DESIGN 5 — Advanced Security Center (dense dark pro, steel accent)
    // ------------------------------------------------------------------
    val ADVANCED = Skin(
        colors = SkinColors(
            background = Color(0xFF06080F), surface = Color(0xFF0D1117),
            surfaceVariant = Color(0xFF161C26), border = Color(0xFF263043),
            primary = Color(0xFF4F8CFF), primaryDark = Color(0xFF3B6FD1),
            safe = Color(0xFF2EA043), warning = Color(0xFFD29922),
            high = Color(0xFFDA3633), critical = Color(0xFFB62324),
            textPrimary = Color(0xFFE6EDF3), textSecondary = Color(0xFF8B98AB),
            textTertiary = Color(0xFF5C6B80),
            gradientTop = Color(0xFF06080F), gradientBottom = Color(0xFF0A0F1A),
            darkTheme = true
        ),
        dims = defaultDims.copy(
            xs = 3.dp, s = 6.dp, m = 10.dp, l = 13.dp,
            xl = 16.dp, xxl = 20.dp, xxxl = 26.dp,
            cardCorner = 14.dp, cardCornerSm = 10.dp,
            buttonCorner = 14.dp, buttonHeight = 50.dp
        ),
        type = typeVariant(15, 14, 13, 12, 13) // data-dense
    )
}

/**
 * Live skin state. Plain top-level theme vals delegate to `colors` — Compose
 * snapshot observation recomposes every reading screen when the concept flips.
 */
object SkinState {
    var concept: UiConcept by mutableStateOf(UiConcept.DASHBOARD)
    var colors: SkinColors by mutableStateOf(Skins.DASHBOARD.colors)
    var dims: SkinDims by mutableStateOf(Skins.DASHBOARD.dims)
    var type: SkinType by mutableStateOf(Skins.DASHBOARD.type)

    fun apply(c: UiConcept) {
        concept = c
        val skin = when (c) {
            UiConcept.DASHBOARD -> Skins.DASHBOARD
            UiConcept.PREMIUM_DARK -> Skins.PREMIUM_DARK
            UiConcept.MINIMAL -> Skins.MINIMAL
            UiConcept.GUIDED -> Skins.GUIDED
            UiConcept.ADVANCED -> Skins.ADVANCED
        }
        colors = skin.colors
        dims = skin.dims
        type = skin.type
    }
}

/** Material3 scheme built from the ACTIVE skin (light or dark). */
fun skinColorScheme(c: SkinColors): ColorScheme =
    if (c.darkTheme) darkColorScheme(
        primary = c.primary, onPrimary = Color.White,
        secondary = c.primaryDark, background = c.background,
        onBackground = c.textPrimary, surface = c.surface,
        onSurface = c.textPrimary, surfaceVariant = c.surfaceVariant,
        onSurfaceVariant = c.textSecondary, error = c.critical, outline = c.border
    ) else lightColorScheme(
        primary = c.primary, onPrimary = Color.White,
        secondary = c.primaryDark, background = c.background,
        onBackground = c.textPrimary, surface = c.surface,
        onSurface = c.textPrimary, surfaceVariant = c.surfaceVariant,
        onSurfaceVariant = c.textSecondary, error = c.critical, outline = c.border
    )

/** Live screen background gradient from the ACTIVE skin. */
fun skinGradient(c: SkinColors): Brush =
    Brush.verticalGradient(listOf(c.gradientTop, c.gradientBottom))
