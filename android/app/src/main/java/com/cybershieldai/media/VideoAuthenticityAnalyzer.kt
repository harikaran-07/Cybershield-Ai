package com.cybershieldai.media

import android.content.Context
import android.graphics.Bitmap
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMetadataRetriever
import android.net.Uri
import java.nio.ByteOrder

/**
 * VideoAuthenticityAnalyzer (spec §6) — lightweight, on-device sampling:
 *
 *  - A few representative frames are decoded (start / middle / end) and run
 *    through the SAME image forensics as still images.
 *  - The audio track, when present, is decoded (bounded) and measured with
 *    the voice/synthetic-speech DSP.
 *  - Results are aggregated into frame findings + audio findings + overall.
 *
 * The whole video is never processed; decode work is bounded by sample count
 * and a wall-clock deadline (spec §16).
 */
object VideoAuthenticityAnalyzer {

    private const val FRAMES_TO_SAMPLE = 3
    private const val DEADLINE_MS = 45_000L

    data class Aggregated(
        val result: MediaSecurityResult,
        val frameFindings: List<String>,
        val audioFindings: List<String>
    )

    fun analyze(context: Context, uri: Uri): Aggregated {
        val limitations = mutableListOf(
            "Automated detection can produce false positives and false negatives",
            "Only sampled frames are analyzed — the full video is not processed",
            "Heavy platform compression (messengers) weakens forensic signals"
        )
        val frameFindings = mutableListOf<String>()
        val audioFindings = mutableListOf<String>()
        val indicators = mutableListOf<MediaRiskEngine.Indicator>()
        try {
            val retriever = MediaMetadataRetriever()
            var durationMs = 0L
            try {
                context.contentResolver.openFileDescriptor(uri, "r")?.use {
                    retriever.setDataSource(it.fileDescriptor)
                } ?: return failedAgg("The video file could not be opened.")
                durationMs = retriever.extractMetadata(
                    MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L
                frameFindings.add("Duration: ${if (durationMs > 0) "${durationMs / 1000} s" else "unknown"}")
                val rotation = retriever.extractMetadata(
                    MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION)
                rotation?.let { frameFindings.add("Rotation: $it") }

                // ---- Sample frames at start / middle / end ----
                val positions = if (durationMs > 0) {
                    (0 until FRAMES_TO_SAMPLE).map {
                        durationMs * (it + 1) / (FRAMES_TO_SAMPLE + 1)
                    }
                } else listOf(0L)
                val deadline = System.currentTimeMillis() + DEADLINE_MS
                val imageIndicators = mutableListOf<MediaRiskEngine.Indicator>()
                frames@ for ((idx, pos) in positions.withIndex()) {
                    if (System.currentTimeMillis() > deadline) {
                        limitations.add("Analysis stopped early — device resources were needed elsewhere")
                        break@frames
                    }
                    val bmp = retriever.getFrameAtTime(pos * 1000,
                        MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                    if (bmp == null) continue
                    frameFindings.add("Frame ${idx + 1}/${positions.size} @ ${pos / 1000} s decoded (${bmp.width}×${bmp.height})")
                    // Reuse the image forensics on the decoded frame.
                    val noise = frameNoiseUniformity(bmp)
                    val seam = frameSeamEnergy(bmp)
                    frameFindings.add(String.format(java.util.Locale.US,
                        "Frame %d: noise uniformity %.3f, seam energy %.4f", idx + 1, noise, seam))
                    if (noise < 0.55 && bmp.width >= 400) {
                        imageIndicators += MediaRiskEngine.Indicator(
                            "Uniform noise texture in sampled frame",
                            strength = ((0.55 - noise) / 0.55).coerceIn(0.2, 0.65),
                            detail = "Frame ${idx + 1}: globally uniform sensor-noise statistics")
                    }
                    if (seam > 0.05) {
                        imageIndicators += MediaRiskEngine.Indicator(
                            "Periodic seam artifacts in sampled frame",
                            strength = ((seam - 0.05) / 0.2).coerceIn(0.2, 0.6),
                            detail = "Frame ${idx + 1}: repeating block-boundary energy")
                    }
                }

                // Inter-frame temporal check: near-duplicate consecutive frames
                // (generation stutter) vs natural motion.
                if (durationMs > 2000 && System.currentTimeMillis() < deadline) {
                    val f1 = retriever.getFrameAtTime(durationMs * 400, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                    val f2 = retriever.getFrameAtTime(durationMs * 400 + 200_000, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                    if (f1 != null && f2 != null) {
                        val diff = frameDifference(f1, f2)
                        frameFindings.add(String.format(java.util.Locale.US,
                            "Temporal motion (200 ms apart): %.4f", diff))
                        if (diff < 0.0008) {
                            imageIndicators += MediaRiskEngine.Indicator(
                                "Frozen-motion segment",
                                strength = 0.3,
                                detail = "Frames 200 ms apart are nearly identical — unusual for live-action footage")
                        }
                    }
                }
                indicators += imageIndicators
            } finally {
                try { retriever.release() } catch (_: Exception) {}
            }

            // ---- Audio track: separate analysis with the voice DSP ----
            val audio = analyzeAudioTrack(context, uri)
            audioFindings.addAll(audio.findings)
            indicators += audio.indicators
            if (audio.present == false) {
                audioFindings.add("No audio track found — visual analysis only")
                limitations.add("No audio was available for synthetic-voice analysis")
            }

            val (confidence, status) = MediaRiskEngine.assess(indicators, limitations, "video")
            val result = MediaSecurityResult(
                mediaType = "VIDEO",
                status = if (indicators.isEmpty()) MediaSecurityResult.Status.NO_STRONG_INDICATORS else status,
                riskLevel = MediaRiskEngine.riskLevelFor(confidence),
                confidence = confidence,
                indicators = indicators.sortedByDescending { it.strength }
                    .map { "${it.label} — ${it.detail}" },
                technicalFindings = frameFindings + audioFindings,
                limitations = limitations,
                recommendation = MediaRiskEngine.recommendationFor(status, "video")
            )
            return Aggregated(result, frameFindings.toList(), audioFindings.toList())
        } catch (_: Exception) {
            return failedAgg("The video could not be processed — it may be corrupted or use an unsupported codec.")
        }
    }

    private fun failedAgg(msg: String): Aggregated = Aggregated(
        MediaSecurityResult(
            "VIDEO", MediaSecurityResult.Status.ANALYSIS_FAILED, "LOW", 0,
            emptyList(), emptyList(), listOf(msg),
            MediaRiskEngine.recommendationFor(MediaSecurityResult.Status.ANALYSIS_FAILED, "video")),
        emptyList(), emptyList())

    // ------------------------------------------------------------------
    // Audio track analysis (bounded decode + voice DSP reuse)
    // ------------------------------------------------------------------
    private class AudioOut(
        val present: Boolean?,
        val findings: MutableList<String>,
        val indicators: MutableList<MediaRiskEngine.Indicator>
    )

    private fun analyzeAudioTrack(context: Context, uri: Uri): AudioOut {
        val findings = mutableListOf<String>()
        val indicators = mutableListOf<MediaRiskEngine.Indicator>()
        val extractor = MediaExtractor()
        try {
            context.contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                extractor.setDataSource(pfd.fileDescriptor)
            }
            var track = -1
            var fmt: MediaFormat? = null
            for (i in 0 until extractor.trackCount) {
                val f = extractor.getTrackFormat(i)
                if (f.getString(MediaFormat.KEY_MIME)?.startsWith("audio/") == true) { track = i; fmt = f; break }
            }
            if (track < 0 || fmt == null) return AudioOut(false, findings, indicators)
            findings.add("Audio track present (${fmt.getString(MediaFormat.KEY_MIME)})")
            extractor.selectTrack(track)
            val mime = fmt.getString(MediaFormat.KEY_MIME)!!
            val sr = fmt.getInteger(MediaFormat.KEY_SAMPLE_RATE)
            val ch = fmt.getInteger(MediaFormat.KEY_CHANNEL_COUNT)

            // Reuse the bounded MediaCodec decode + DSP from the voice
            // analyzer's internal core so both pipelines measure identically.
            val pcm = VoiceAuthenticityAnalyzerInternal.decodeWindow(extractor, mime, sr, ch)
            if (pcm == null || pcm.samples.isEmpty()) {
                findings.add("Audio could not be decoded — skipped")
                return AudioOut(true, findings, indicators)
            }
            val flat = VoiceAuthenticityAnalyzerInternal.spectralFlatness(pcm.samples, pcm.sampleRate)
            val pause = VoiceAuthenticityAnalyzerInternal.pauseUniformity(pcm.samples, pcm.sampleRate)
            findings.add(String.format(java.util.Locale.US,
                "Audio: flatness %.3f, pause CV %.3f (%d pauses)", flat, pause.first, pause.second))
            if (flat < 0.045) {
                indicators += MediaRiskEngine.Indicator(
                    "Synthetic-speech texture in audio track",
                    strength = ((0.045 - flat) / 0.045).coerceIn(0.15, 0.6),
                    detail = String.format(java.util.Locale.US, "Voiced-band flatness %.3f is very smooth", flat))
            }
            if (pause.second >= 3 && pause.first < 0.08) {
                indicators += MediaRiskEngine.Indicator(
                    "Machine-like pause regularity in audio track",
                    strength = ((0.08 - pause.first) / 0.08).coerceIn(0.2, 0.55),
                    detail = "Inter-phrase silences are unusually uniform")
            }
            return AudioOut(true, findings, indicators)
        } catch (_: Exception) {
            findings.add("Audio analysis skipped (decoding failed)")
            return AudioOut(null, findings, indicators)
        } finally {
            try { extractor.release() } catch (_: Exception) {}
        }
    }

    // ------------------------------------------------------------------
    // Frame-level DSP (mirrors image forensics without the metadata layer)
    // ------------------------------------------------------------------

    private fun frameNoiseUniformity(bmp: Bitmap): Double {
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

    private fun tileResidual(bmp: Bitmap, x0: Int, y0: Int, w: Int, h: Int): Double {
        var acc = 0.0; var n = 0
        for (y in y0 + 1 until y0 + h - 1 step 2) {
            for (x in x0 + 1 until x0 + w - 1 step 2) {
                val c = android.graphics.Color.luminance(bmp.getPixel(x, y))
                val l = android.graphics.Color.luminance(bmp.getPixel(x - 1, y))
                val r = android.graphics.Color.luminance(bmp.getPixel(x + 1, y))
                val u = android.graphics.Color.luminance(bmp.getPixel(x, y - 1))
                val d = android.graphics.Color.luminance(bmp.getPixel(x, y + 1))
                acc += Math.abs(4 * c - l - r - u - d)
                n++
            }
        }
        return if (n > 0) acc / n else 0.0
    }

    private fun frameSeamEnergy(bmp: Bitmap): Double {
        val w = bmp.width; val h = bmp.height
        if (w < 96 || h < 96) return 0.0
        var onGrid = 0.0; var total = 0.0
        var n = 0
        var y = h / 4
        while (y < h * 3 / 4 - 1 && n < 20000) {
            var x = w / 4
            while (x < w * 3 / 4 - 1 && n < 20000) {
                val d = Math.abs(
                    android.graphics.Color.luminance(bmp.getPixel(x + 1, y)) -
                    android.graphics.Color.luminance(bmp.getPixel(x, y)))
                total += d
                if (((x + 1) and 7) == 0) onGrid += d
                n++; x++
            }
            y += 3
        }
        return if (total > 0) onGrid / total else 0.0
    }

    /** Mean |Δ| between two frames scaled to [0,1]. */
    private fun frameDifference(a: Bitmap, b: Bitmap): Double {
        val w = minOf(a.width, b.width)
        val h = minOf(a.height, b.height)
        if (w == 0 || h == 0) return 0.0
        // Downscale both to 128×128 for a stable, cheap comparison.
        val sa = Bitmap.createScaledBitmap(a, 128, 128, true)
        val sb = Bitmap.createScaledBitmap(b, 128, 128, true)
        var acc = 0.0
        for (y in 0 until 128 step 2) for (x in 0 until 128 step 2) {
            acc += Math.abs(
                android.graphics.Color.luminance(sa.getPixel(x, y)) -
                android.graphics.Color.luminance(sb.getPixel(x, y)))
        }
        return acc / (64 * 64 * 255.0)
    }
}
