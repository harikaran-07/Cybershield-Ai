package com.cybershieldai.media

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns

/**
 * AI Media Security — common result model.
 *
 * Every analyzer produces this shape. Wording rule (hard requirement):
 * results are HONEST SIGNALS, never verdicts. Detectors can produce false
 * positives and negatives; "Potentially AI-generated" is the strongest
 * claim this engine is allowed to make.
 */
data class MediaSecurityResult(
    val mediaType: String,                 // AUDIO | IMAGE | VIDEO
    val status: Status,
    val riskLevel: String,                 // LOW | MEDIUM | HIGH (severity words)
    val confidence: Int,                   // 0..100 — engine confidence in the status
    val indicators: List<String>,          // only actually-detected indicators
    val technicalFindings: List<String>,   // deterministic measured evidence
    val limitations: List<String>,         // honest caveats of this analysis
    val recommendation: String,
    val timestamp: Long = System.currentTimeMillis()
) {
    enum class Status {
        LIKELY_AUTHENTIC,
        NO_STRONG_INDICATORS,
        POTENTIALLY_AI_GENERATED,
        POTENTIALLY_MANIPULATED,
        INCONCLUSIVE,
        ANALYSIS_FAILED
    }

    /** Honest user-facing label for a status. */
    val statusLabel: String = when (status) {
        Status.LIKELY_AUTHENTIC -> "No strong synthetic indicators"
        Status.NO_STRONG_INDICATORS -> "No strong indicators detected"
        Status.POTENTIALLY_AI_GENERATED -> "Potentially AI-generated"
        Status.POTENTIALLY_MANIPULATED -> "Potentially manipulated"
        Status.INCONCLUSIVE -> "Inconclusive"
        Status.ANALYSIS_FAILED -> "Analysis failed"
    }
}

/** Progress states surfaced by the repository while an analysis runs. */
sealed class MediaScanState {
    object Idle : MediaScanState()
    data class Running(val phase: String, val progress: Int = 0) : MediaScanState()
    data class Done(
        val result: MediaSecurityResult,
        val explanation: String?,
        val explanationAvailable: Boolean,
        val eventId: Long?
    ) : MediaScanState()
    data class Failed(val userMessage: String) : MediaScanState()
}

/**
 * Privacy sanitizer (spec §9): builds the structured payload handed to the
 * LLM explanation service. Contains ONLY sanitized, aggregated findings —
 * never file paths, filenames (extension only), raw bytes or metadata blobs.
 */
object MediaPrivacySanitizer {

    data class SanitizedFindings(
        val mediaType: String,
        val riskLevel: String,
        val confidence: Int,
        val indicators: List<String>,
        val limitations: List<String>
    )

    fun sanitize(result: MediaSecurityResult, fileExtension: String?): SanitizedFindings =
        SanitizedFindings(
            mediaType = result.mediaType.lowercase(),
            riskLevel = result.riskLevel.lowercase(),
            confidence = result.confidence,
            indicators = result.indicators.take(8).map { it.take(120) },
            limitations = result.limitations.take(4).map { it.take(140) }
        )

    /** Structured JSON for the explanation LLM — sanitized findings only. */
    fun toJson(f: SanitizedFindings): String {
        val indicators = f.indicators.joinToString(",") { "\"" + it.replace("\"", "'") + "\"" }
        val limitations = f.limitations.joinToString(",") { "\"" + it.replace("\"", "'") + "\"" }
        return """{"mediaType":"${f.mediaType}","riskLevel":"${f.riskLevel}",""" +
            """"confidence":${f.confidence},"indicators":[$indicators],"limitations":[$limitations]}"""
    }
}

/**
 * Shared file intake for the analyzers: type sniffing from the magic bytes,
 * display-name lookup (for the extension only) and hard size limits.
 * Analyzers NEVER execute media and never upload it — everything stays local.
 */
object MediaIntake {

    /** Analysis is skipped above these sizes (spec §16 performance budget). */
    const val MAX_IMAGE_BYTES: Long = 60L * 1024 * 1024
    const val MAX_AUDIO_BYTES: Long = 200L * 1024 * 1024
    const val MAX_VIDEO_BYTES: Long = 400L * 1024 * 1024

    data class Intake(
        val kind: String,          // AUDIO | IMAGE | VIDEO | UNSUPPORTED
        val extension: String?,    // sanitized: extension only, no name
        val sizeBytes: Long,
        val headerBytes: ByteArray
    )

    sealed class Open {
        data class Ok(val intake: Intake, val pfd: android.os.ParcelFileDescriptor) : Open()
        data class Reject(val userMessage: String) : Open()
    }

    /** Open + sniff the picked document. Reject with an honest user message. */
    fun open(context: Context, uri: Uri, expected: String): Open {
        return try {
            val resolver = context.contentResolver
            val size = querySize(resolver, uri)
            if (size < 0) return Open.Reject("Could not read the selected file. Please try a different file.")
            if (size == 0L) return Open.Reject("The selected file is empty and cannot be analyzed.")
            val limit = when (expected) {
                "AUDIO" -> MAX_AUDIO_BYTES
                "IMAGE" -> MAX_IMAGE_BYTES
                else -> MAX_VIDEO_BYTES
            }
            if (size > limit) return Open.Reject(
                "This file is too large for on-device analysis (limit " +
                    "${limit / (1024 * 1024)} MB). Choose a smaller file.")

            val pfd = resolver.openFileDescriptor(uri, "r")
                ?: return Open.Reject("Could not open the selected file.")
            val header = pfd.use {
                val input = java.io.FileInputStream(it.fileDescriptor)
                val buf = ByteArray(64)
                val n = input.read(buf)
                if (n <= 0) ByteArray(0) else buf.copyOf(n)
            }
            val kind = sniffKind(header)
            if (kind == "UNSUPPORTED") {
                Open.Reject("Unsupported file type. Please select a real ${labelFor(expected)} file.")
            } else {
                Open.Ok(
                    Intake(kind, extensionOf(resolver, uri), size, header),
                    // Re-open for the analyzer (pfd was closed by use()).
                    resolver.openFileDescriptor(uri, "r")!!)
            }
        } catch (_: SecurityException) {
            Open.Reject("Permission to read this file was denied. Pick the file again.")
        } catch (_: Exception) {
            Open.Reject("The file could not be opened — it may be corrupted.")
        }
    }

    val labelFor: (String) -> String = { t ->
        when (t) { "AUDIO" -> "audio"; "IMAGE" -> "image"; else -> "video" }
    }

    /** Magic-byte sniffing — the file picker's MIME type is not trusted. */
    fun sniffKind(header: ByteArray): String {
        if (header.size < 12) return "UNSUPPORTED"
        fun starts(vararg bytes: Int) = bytes.indices.all { header[it].toInt() and 0xFF == bytes[it] }
        val ascii = header.toString(Charsets.ISO_8859_1)
        return when {
            // ---- Audio containers / codecs ----
            starts(0xFF, 0xFB) || starts(0xFF, 0xF3) || starts(0xFF, 0xF2) ||
                starts(0xFF, 0xFA) || starts(0x49, 0x44, 0x33) -> "AUDIO"     // MP3 (frame sync / ID3)
            starts(0x66, 0x4C, 0x61, 0x43) -> "AUDIO"                          // FLAC
            starts(0x4F, 0x67, 0x67, 0x53) -> "AUDIO"                          // OGG
            starts(0x66, 0x74, 0x79, 0x70) && ascii.regionMatches(
                8, "M4A ", 0, 4, ignoreCase = true) -> "AUDIO"                 // M4A
            starts(0x66, 0x74, 0x79, 0x70) && ascii.regionMatches(
                8, "M4B ", 0, 4, ignoreCase = true) -> "AUDIO"                 // M4B audiobook
            starts(0x66, 0x74, 0x79, 0x70) && ascii.regionMatches(
                8, "M4P ", 0, 4, ignoreCase = true) -> "AUDIO"                 // M4P audio
            starts(0x52, 0x49, 0x46, 0x46) && ascii.regionMatches(8, "WAVE", 0, 4) -> "AUDIO" // WAV
            starts(0x23, 0x21, 0x41, 0x4D, 0x52) -> "AUDIO"                    // AMR
            starts(0x66, 0x74, 0x79, 0x70) && ascii.regionMatches(
                8, "qt  ", 0, 4, ignoreCase = true) -> "VIDEO"                 // MOV
            // ---- HEIF-family still images MUST be checked BEFORE the generic
            // ftyp→video branch, or iPhone photos get rejected as video. ----
            starts(0x66, 0x74, 0x79, 0x70) && (
                ascii.regionMatches(8, "heic", 0, 4, ignoreCase = true) ||
                ascii.regionMatches(8, "heix", 0, 4, ignoreCase = true) ||
                ascii.regionMatches(8, "heif", 0, 4, ignoreCase = true) ||
                ascii.regionMatches(8, "mif1", 0, 4, ignoreCase = true) ||
                ascii.regionMatches(8, "msf1", 0, 4, ignoreCase = true)
                ) -> "IMAGE"                                                   // HEIC/HEIF
            // ---- Video containers (ftyp brands: mp42/isom/avc1/msdh/…) ----
            starts(0x66, 0x74, 0x79, 0x70) -> "VIDEO"
            starts(0x1A, 0x45, 0xDF, 0xA3) -> "VIDEO"                          // MKV/WebM
            starts(0x41, 0x56, 0x49, 0x20) -> "VIDEO"                          // AVI
            // ---- Images ----
            starts(0xFF, 0xD8, 0xFF) -> "IMAGE"                                // JPEG
            starts(0x89, 0x50, 0x4E, 0x47) -> "IMAGE"                          // PNG
            starts(0x52, 0x49, 0x46, 0x46) && ascii.regionMatches(8, "WEBP", 0, 4) -> "IMAGE"
            starts(0x47, 0x49, 0x46, 0x38) -> "IMAGE"                          // GIF
            else -> "UNSUPPORTED"
        }
    }

    private fun querySize(resolver: android.content.ContentResolver, uri: Uri): Long {
        resolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
            val idx = c.getColumnIndex(OpenableColumns.SIZE)
            if (idx >= 0 && c.moveToFirst() && !c.isNull(idx)) return c.getLong(idx)
        }
        return try {
            resolver.openFileDescriptor(uri, "r")?.use { it.statSize } ?: -1L
        } catch (_: Exception) { -1L }
    }

    /** Extension only (privacy: the filename never leaves the sanitizer). */
    private fun extensionOf(resolver: android.content.ContentResolver, uri: Uri): String? {
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) {
                val name = c.getString(idx) ?: return null
                val dot = name.lastIndexOf('.')
                return if (dot >= 0) name.substring(dot + 1).lowercase().take(5) else null
            }
        }
        return null
    }
}

/**
 * Deterministic risk mapping shared by all analyzers (spec §4/§6/§7/§11):
 * confidence comes ONLY from measured indicator strengths — never random,
 * never from the LLM. The wording stays conservative at every band.
 */
object MediaRiskEngine {

    data class Indicator(val label: String, val strength: Double, val detail: String)

    /**
     * Combine weighted indicator strengths into a 0..100 confidence that the
     * media MAY be AI-generated/manipulated, and pick the honest status.
     *
     * Accuracy rules (hard):
     *  - provenanceBacked (C2PA declares AI / generator software tag): the
     *    only evidence allowed into the strong band.
     *  - Statistic-only evidence (pixels/DSP heuristics) is CAPPED: audio 65,
     *    image/video 49 unless 3+ INDEPENDENT signals corroborate (then 65).
     *    Statistics alone must never yield a HIGH-confidence allegation.
     *  - The 30–54 band stays NO_STRONG_INDICATORS: weak signals are listed
     *    as findings but the STATUS does not allege AI generation.
     */
    fun assess(
        indicators: List<Indicator>,
        limitations: List<String>,
        mediaType: String,
        provenanceBacked: Boolean = false
    ): Pair<Int, MediaSecurityResult.Status> {
        val valid = indicators.filter { it.strength > 0.0 }
        if (valid.isEmpty()) return 0 to MediaSecurityResult.Status.NO_STRONG_INDICATORS
        // Weighted blend: the strongest indicator dominates, the count adds
        // corroboration. Capped, transparent, deterministic.
        val sorted = valid.sortedByDescending { it.strength }
        val primary = sorted.first().strength
        val corroboration = (sorted.drop(1).sumOf { it.strength } * 0.35)
            .coerceAtMost(0.45)
        var confidence = ((primary * 0.75 + corroboration) * 100).toInt().coerceIn(0, 97)
        // 3+ corroborating signals lift the assessment into the strong band.
        if (sorted.size >= 3 && primary >= 0.55) {
            confidence = (confidence + 8).coerceAtMost(95)
        }
        // Honest evidence caps — statistics alone never allege strongly.
        confidence = when {
            provenanceBacked -> confidence.coerceAtMost(95)
            mediaType.equals("AUDIO", ignoreCase = true) -> confidence.coerceAtMost(65)
            valid.size >= 3 -> confidence.coerceAtMost(65)
            else -> confidence.coerceAtMost(49)
        }
        val status = when {
            confidence >= 55 -> MediaSecurityResult.Status.POTENTIALLY_AI_GENERATED
            else -> MediaSecurityResult.Status.NO_STRONG_INDICATORS
        }
        return confidence to status
    }

    fun riskLevelFor(confidence: Int): String = when {
        confidence >= 60 -> "HIGH"
        confidence >= 30 -> "MEDIUM"
        else -> "LOW"
    }

    fun recommendationFor(status: MediaSecurityResult.Status, mediaType: String): String = when (status) {
        MediaSecurityResult.Status.POTENTIALLY_AI_GENERATED,
        MediaSecurityResult.Status.POTENTIALLY_MANIPULATED ->
            "Verify the original source and context before trusting or sharing this $mediaType. " +
                "Compare with material from the claimed source through an official channel."
        MediaSecurityResult.Status.ANALYSIS_FAILED ->
            "The file could not be analyzed. Treat it cautiously if the source is unknown."
        else ->
            "No strong synthetic indicators were found. This is not a guarantee of authenticity — " +
                "consider the source before sharing sensitive contexts."
    }
}
