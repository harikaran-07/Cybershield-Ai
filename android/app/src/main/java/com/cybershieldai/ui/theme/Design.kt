package com.cybershieldai.ui.theme

import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Centralized design tokens (spec §28–§30): one spacing scale, one corner
 * scale, one set of component dimensions. Screens never invent values.
 *
 * SKIN-REACTIVE (UI/UX redesign): every dimension now resolves from the
 * ACTIVE SKIN so each design concept controls density (Guided = roomier
 * targets, Advanced = compact) without touching any screen code.
 */
object Dsn {
    // ---- Spacing scale (spec §28) — live from the active skin ----
    val XS get() = SkinState.dims.xs
    val S get() = SkinState.dims.s
    val M get() = SkinState.dims.m
    val L get() = SkinState.dims.l
    val XL get() = SkinState.dims.xl
    val XXL get() = SkinState.dims.xxl
    val XXXL get() = SkinState.dims.xxxl

    // ---- Corner radius scale ----
    val CardCorner get() = SkinState.dims.cardCorner
    val CardCornerSm get() = SkinState.dims.cardCornerSm
    val ChipCorner = 50
    val ButtonCorner get() = SkinState.dims.buttonCorner

    // ---- Component dimensions ----
    val ButtonHeight get() = SkinState.dims.buttonHeight
    val CardMinHeight = 112.dp // fixed content floor (unchanged across skins)
    val ScoreRingSize = 168.dp // fixed gauge size (unchanged across skins)
    val AppIconSize = 44.dp    // fixed icon tile (unchanged across skins)
    val NavItemFontSize = 12.sp

    // ---- Card elevation ----
    val CardElevation get() = SkinState.dims.cardElevation
}
