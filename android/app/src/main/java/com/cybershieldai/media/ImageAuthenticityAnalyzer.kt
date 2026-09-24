package com.cybershieldai.media

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.media.ExifInterface
import android.net.Uri
import java.io.BufferedInputStream

/**
 * ImageAuthenticityAnalyzer (spec §5) — deterministic, on-device image
 * forensics. Honest layers:
 *
 *  1. C2PA / Content Credentials provenance: when present, the embedded
 *     manifest is reported verbatim (the ONLY authoritative "AI-generated"
 *     signal); absence is NOT proof of authenticity.
 *  2. EXIF metadata: missing camera metadata + software tags commonly
 *     written by generation tools — a weak indicator, never used alone.
 *  3. Pixel-consistency signals: noise/residual uniformity across the image
 *     (GAN/Diffusion outputs tend toward globally uniform noise texture;
 *     camera photos vary by optics/sensor/demosaic).
 *
 * Never executes media, never uploads it. Missing metadata alone is NOT
 * treated as proof the image is fake (spec §5).
 */
object ImageAuthenticityAnalyzer {

    private const val MAX_DECODE_DIM = 1280

    fun analyze(context: Context, uri: Uri): MediaSecurityResult {
        val limitations = mutableListOf(
            "Automated detection can produce false positives and false negatives",
            "Missing metadata alone does not prove an image is AI-generated",
            "Screenshots, heavy recompression and edits change forensic signals"
        )
        val findings = mutableListOf<String>()
        val indicators = mutableListOf<MediaRiskEngine.Indicator>()
        var provenanceBacked = false
        try {
            val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
                input.readBytes()
            } ?: return failed("The image file could not be opened.")

            // ---- 1. C2PA / Content Credentials (JUMBF marker inside JPEG) ----
            // ACCURACY RULE: the mere PRESENCE of a manifest is a NEUTRAL
            // finding — real cameras and editors ship them too. Only an
            // explicit AI-generation declaration or a generator tool hint
            // counts as evidence, and it is the ONLY strong evidence here.
            val c2pa = c2paProbe(bytes)
            if (c2pa != null) {
                findings.add("Content Credentials: ${c2pa}")
                if (c2pa.contains("declares AI-generated") || c2pa.contains("tool hint")) {
                    provenanceBacked = true
                    indicators += MediaRiskEngine.Indicator(
                        "Embedded provenance declares AI generation",
                        strength = 0.85,
                        detail = c2pa)
                }
            } else {
                findings.add("Content Credentials (C2PA): not present")
            }

            // ---- 2. EXIF metadata layer ----
            val exif = exifLayer(context, uri, bytes)
            findings.addAll(exif.findings)
            indicators += exif.indicators
            if (exif.generatorTag) provenanceBacked = true

            // ---- 3. Decode (bounded) and measure pixel consistency ----
            val bmp = decodeBounded(bytes)
            if (bmp == null) {
                return MediaSecurityResult(
                    "IMAGE", MediaSecurityResult.Status.INCONCLUSIVE, "LOW", 0,
                    emptyList(), findings,
                    limitations + "The image could not be decoded by this device",
                    MediaRiskEngine.recommendationFor(MediaSecurityResult.Status.INCONCLUSIVE, "image"))
            }
            findings.add("Dimensions: ${bmp.width}×${bmp.height}")

            // Noise-uniformity across 3×3 grid tiles.
            val noise = noiseUniformity(bmp)
            findings.add(String.format(java.util.Locale.US,
                "Noise-texture uniformity across tiles: %.3f (lower = more uniform)", noise))
            if (noise < 0.55 && bmp.width >= 400 && bmp.height >= 400) {
                indicators += MediaRiskEngine.Indicator(
                    "Globally uniform noise texture",
                    strength = ((0.55 - noise) / 0.55).coerceIn(0.2, 0.7),
                    detail = String.format(java.util.Locale.US,
                        "Sensor-noise statistics are unusually uniform across the image (%.2f)", noise))
            }

            // Grid-aliasing check: generation pipelines trained on fixed-size
            // inputs often leave periodic seams; camera demosaic does not.
            val seam = seamEnergy(bmp)
            findings.add(String.format(java.util.Locale.US,
                "Periodic seam energy: %.4f", seam))
            if (seam > 0.05) {
                indicators += MediaRiskEngine.Indicator(
                    "Periodic seam artifacts",
                    strength = ((seam - 0.05) / 0.2).coerceIn(0.2, 0.65),
                    detail = String.format(java.util.Locale.US,
                        "Repeating block-boundary energy detected (%.3f) — seen in some generation pipelines", seam))
            }

            // Chromatic-aberration consistency: real lenses bend channels
            // coherently toward the edges; full-frame synthetic images often
            // show none or incoherent direction.
            val ca = chromaticAberration(bmp)
            findings.add(String.format(java.util.Locale.US,
                "Edge chromatic coherence: %.3f", ca))
            if (ca < 0.2 && bmp.width >= 400) {
                indicators += MediaRiskEngine.Indicator(
                    "No coherent lens chromatic signature",
                    strength = 0.28,
                    detail = String.format(java.util.Locale.US,
                        "Edge channel-shift coherence %.2f is below typical camera optics", ca))
            }

            val (confidence, status) = MediaRiskEngine.assess(
                indicators, limitations, "image", provenanceBacked = provenanceBacked)
            return MediaSecurityResult(
                mediaType = "IMAGE",
                status = status,
                riskLevel = MediaRiskEngine.riskLevelFor(confidence),
                confidence = confidence,
                indicators = indicators.sortedByDescending { it.strength }
                    .map { "${it.label} — ${it.detail}" },
                technicalFindings = findings,
                limitations = limitations,
                recommendation = MediaRiskEngine.recommendationFor(status, "image")
            )
        } catch (_: Exception) {
            return failed("The image could not be processed — it may be corrupted or use an unsupported format.")
        }
    }

    private fun failed(msg: String) = MediaSecurityResult(
        "IMAGE", MediaSecurityResult.Status.ANALYSIS_FAILED, "LOW", 0,
        emptyList(), emptyList(), listOf(msg),
        MediaRiskEngine.recommendationFor(MediaSecurityResult.Status.ANALYSIS_FAILED, "image"))

    // ------------------------------------------------------------------
    // 1. C2PA / Content Credentials probe (JPEG APP11 JUMBF, PNG caBX)
    // ------------------------------------------------------------------

    /**
     * Returns a short description of the embedded provenance manifest, or
     * null. JPEG: APP11 marker segments ("c2pa"/"jumb" payload). PNG: caBX
     * chunk. This is evidence the file CARRIES credentials — their content
     * (claims, signatures) is not cryptographically validated here; the
     * wording says so.
     */
    private fun c2paProbe(bytes: ByteArray): String? {
        try {
            // JPEG: scan marker segments for APP11.
            if (bytes.size > 4 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte()) {
                var i = 2
                var app11 = 0
                while (i + 4 < bytes.size && app11 < 64) {
                    if (bytes[i] != 0xFF.toByte()) break
                    val marker = bytes[i + 1].toInt() and 0xFF
                    if (marker == 0xD9 || marker == 0xDA) break // EOI / SOS: header scan done
                    val len = ((bytes[i + 2].toInt() and 0xFF) shl 8) or (bytes[i + 3].toInt() and 0xFF)
                    if (marker == 0xEB) { // APP11
                        app11++
                        val seg = String(bytes, i + 4, (len - 2).coerceAtMost(2048), Charsets.ISO_8859_1)
                        val lower = seg.lowercase()
                        val isAi = lower.contains("trainedalgorithmicmedia")
                        val genTool = sequenceOf("openai", "dall", "midjourney", "stable diffusion",
                            "stablediffusion", "firefly", "imagen", "grok", "flux", "sora", "runway", "leonardo")
                            .firstOrNull { lower.contains(it) }
                        return when {
                            isAi -> "manifest present, declares AI-generated media" +
                                (genTool?.let { " (tool hint: $it)" } ?: "")
                            genTool != null -> "manifest present, tool hint: $genTool"
                            else -> "manifest present (claims not verified offline)"
                        }
                    }
                    i += 2 + len
                }
            }
            // PNG: search first 512 KB for the caBX chunk type.
            val limit = minOf(bytes.size, 512 * 1024)
            val head = String(bytes, 0, limit, Charsets.ISO_8859_1)
            if (head.contains("caBX")) {
                val lower = head.lowercase()
                val isAi = lower.contains("trainedalgorithmicmedia")
                return if (isAi) "manifest present, declares AI-generated media"
                else "manifest present (claims not verified offline)"
            }
        } catch (_: Exception) { }
        return null
    }

    // ------------------------------------------------------------------
    // 2. EXIF layer
    // ------------------------------------------------------------------
    private class ExifLayer(
        val findings: MutableList<String>,
        val indicators: MutableList<MediaRiskEngine.Indicator>,
        val generatorTag: Boolean
    )

    private fun exifLayer(context: Context, uri: Uri, bytes: ByteArray): ExifLayer {
        val findings = mutableListOf<String>()
        val indicators = mutableListOf<MediaRiskEngine.Indicator>()
        var generatorTag = false
        try {
            val input = context.contentResolver.openInputStream(uri)
            val exif = try {
                input?.let { ExifInterface(it) }
            } catch (_: Exception) { null } finally { input?.close() }
            if (exif == null) {
                findings.add("EXIF: not readable for this format")
                return ExifLayer(findings, indicators, generatorTag = false)
            }
            val make = exif.getAttribute(ExifInterface.TAG_MAKE)
            val model = exif.getAttribute(ExifInterface.TAG_MODEL)
            val software = exif.getAttribute(ExifInterface.TAG_SOFTWARE)
            val datetime = exif.getAttribute(ExifInterface.TAG_DATETIME)
            val lens = exif.getAttribute(ExifInterface.TAG_F_NUMBER)
            val gps = exif.getAttribute(ExifInterface.TAG_GPS_LATITUDE)
            findings.add("EXIF camera make/model: " +
                (if (!make.isNullOrBlank() || !model.isNullOrBlank()) "${make ?: "?"} ${model ?: "?"}" else "absent"))
            findings.add("EXIF capture time: " + (datetime?.takeIf { it.isNotBlank() } ?: "absent"))
            software?.takeIf { it.isNotBlank() }?.let { findings.add("EXIF software tag: $it") }

            val genTool = software?.lowercase()?.let { sw ->
                sequenceOf("openai", "dall", "midjourney", "stable diffusion", "stablediffusion",
                    "firefly", "imagen", "grok", "flux", "sora", "runway", "comfyui",
                    "automatic1111", "invokeai", "leonardo")
                    .firstOrNull { sw.contains(it) }
            }
            if (genTool != null) {
                generatorTag = true
                indicators += MediaRiskEngine.Indicator(
                    "Generator software tag in metadata",
                    strength = 0.85,
                    detail = "Software tag references a generation tool ($genTool)")
            } else if (make.isNullOrBlank() && model.isNullOrBlank() && lens == null && gps == null) {
                // Weak, capped: absence of ALL camera metadata — very common for
                // AI images but ALSO for messenger-recompressed photos.
                indicators += MediaRiskEngine.Indicator(
                    "Complete absence of camera metadata",
                    strength = 0.22,
                    detail = "No make, model, lens or GPS data — consistent with both generation and recompression")
            }
        } catch (_: Exception) { }
        return ExifLayer(findings, indicators, generatorTag = generatorTag)
    }

    // ------------------------------------------------------------------
    // 3. Pixel-consistency measurements
    // ------------------------------------------------------------------

    private fun decodeBounded(bytes: ByteArray): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (bounds.outWidth / (sample * 2) >= MAX_DECODE_DIM &&
            bounds.outHeight / (sample * 2) >= MAX_DECODE_DIM) sample *= 2
        val opts = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
    }

    /**
     * Per-tile noise residual (high-pass energy) → coefficient of variation
     * across the 3×3 grid. Camera optics/sensor produce uneven texture;
     * many generators produce one global texture.
     */
    private fun noiseUniformity(bmp: Bitmap): Double {
        val tiles = 3
        val tw = bmp.width / tiles
        val th = bmp.height / tiles
        if (tw < 48 || th < 48) return 1.0
        val residuals = mutableListOf<Double>()
        for (ty in 0 until tiles) for (tx in 0 until tiles) {
            residuals.add(tileResidual(bmp, tx * tw, ty * th, tw, th))
        }
        val mean = residuals.average()
        if (mean <= 1e-9) return 1.0
        val sd = Math.sqrt(residuals.sumOf { (it - mean) * (it - mean) } / residuals.size)
        return sd / mean
    }

    /** Mean absolute Laplacian response (noise proxy) of one tile. */
    private fun tileResidual(bmp: Bitmap, x0: Int, y0: Int, w: Int, h: Int): Double {
        var acc = 0.0
        var n = 0
        for (y in y0 + 1 until y0 + h - 1 step 2) {
            for (x in x0 + 1 until x0 + w - 1 step 2) {
                val c = Color.luminance(bmp.getPixel(x, y))
                val l = Color.luminance(bmp.getPixel(x - 1, y))
                val r = Color.luminance(bmp.getPixel(x + 1, y))
                val u = Color.luminance(bmp.getPixel(x, y - 1))
                val d = Color.luminance(bmp.getPixel(x, y + 1))
                acc += Math.abs(4 * c - l - r - u - d)
                n++
            }
        }
        return if (n > 0) acc / n else 0.0
    }

    /** Energy concentrated on a fixed block grid (8-px) relative to total. */
    private fun seamEnergy(bmp: Bitmap): Double {
        val w = bmp.width; val h = bmp.height
        if (w < 96 || h < 96) return 0.0
        var onGrid = 0.0; var total = 0.0
        var n = 0
        val y0 = h / 4; val y1 = h * 3 / 4
        val x0 = w / 4; val x1 = w * 3 / 4
        var y = y0
        while (y < y1 - 1 && n < 20000) {
            var x = x0
            while (x < x1 - 1 && n < 20000) {
                val d = Math.abs(Color.luminance(bmp.getPixel(x + 1, y)) - Color.luminance(bmp.getPixel(x, y)))
                total += d
                if (((x + 1) and 7) == 0) onGrid += d
                n++; x++
            }
            y += 3
        }
        return if (total > 0) onGrid / total else 0.0
    }

    /**
     * Coherence of channel shifts on strong edges (chromatic aberration
     * proxy): mean directional consistency of R/B vs G offsets.
     */
    private fun chromaticAberration(bmp: Bitmap): Double {
        val w = bmp.width; val h = bmp.height
        if (w < 200 || h < 200) return 1.0
        var consistent = 0; var strongEdges = 0
        val y0 = h / 4; val y1 = h * 3 / 4; val x0 = w / 4; val x1 = w * 3 / 4
        var n = 0
        var y = y0
        while (y < y1 - 2 && n < 20000) {
            var x = x0
            while (x < x1 - 2 && n < 20000) {
                val gL = Color.green(bmp.getPixel(x, y)); val gR = Color.green(bmp.getPixel(x + 2, y))
                val gC = Color.green(bmp.getPixel(x + 1, y))
                if (Math.abs(gL - gR) > 60) { // strong edge
                    strongEdges++
                    val rC = Color.red(bmp.getPixel(x + 1, y))
                    val bC = Color.blue(bmp.getPixel(x + 1, y))
                    val rSign = Math.signum((rC - gC).toFloat())
                    val bSign = Math.signum((bC - gC).toFloat())
                    if (rSign != 0f && rSign == bSign) consistent++
                    n++
                }
                x++
            }
            y += 4
        }
        return if (strongEdges >= 20) consistent.toDouble() / strongEdges else 1.0
    }
}
