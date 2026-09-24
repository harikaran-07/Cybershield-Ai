package com.cybershieldai.media

import android.content.Context
import android.net.Uri
import com.cybershieldai.data.local.DatabaseProvider
import com.cybershieldai.data.local.SecurityEventEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * MediaSecurityExplanationService (spec §8/§10) — the LLM is the LAST stage
 * and ONLY explains sanitized findings produced by the deterministic
 * analyzers. It can never create, change or strengthen a detection.
 *
 * Privacy pipeline: media → analyzers → structured result → sanitizer
 * (no filename, no path, no metadata blobs) → local LLM → prose.
 * If the LLM is unavailable, callers show the engine result with an honest
 * "AI explanation unavailable" note (spec §15).
 */
object MediaSecurityExplanationService {

    private const val SYSTEM_PROMPT =
        "You are CyberShield AI, an offline assistant that explains media-authenticity " +
            "results to a non-technical user. The local security engine ALREADY analyzed a " +
            "media file and produced a FINAL result with indicators. Explain ONLY that result " +
            "in 2-4 short sentences: what was detected, why the confidence level was assigned, " +
            "and one safe next step. Never invent new findings. Never claim the media IS fake " +
            "or IS real — the detection is probabilistic. Do not claim you viewed or listened " +
            "to the media. Be calm, clear and conservative."

    /**
     * Produce a human-readable explanation for an already-final result, or
     * null when the local LLM is unavailable/slow/invalid (spec §10: the
     * result must still be displayed either way).
     */
    suspend fun explain(context: Context, result: MediaSecurityResult): String? {
        val sanitized = MediaPrivacySanitizer.sanitize(result, null)
        val payload = MediaPrivacySanitizer.toJson(sanitized)
        return com.cybershieldai.ai.ScannerAiAnalyzer.explain(
            context,
            "Media type: ${sanitized.mediaType}. Security engine final result: $payload. " +
                "Explain this media-authenticity result for the user."
        )
    }
}

/**
 * Media Security Repository (spec §12 architecture): UI → ViewModel → here →
 * analyzers → risk engine → history. The LLM explanation stage runs after the
 * result is final and can be skipped without affecting detection.
 */
class MediaSecurityRepository(private val context: Context) {

    /** One full analysis of a picked document. Runs on Dispatchers.IO. */
    suspend fun analyze(
        uri: Uri,
        expectedKind: String,             // AUDIO | IMAGE | VIDEO
        onPhase: (String) -> Unit,
        withExplanation: Boolean
    ): MediaScanState = withContext(Dispatchers.IO) {
        try {
            onPhase("Checking file…")
            when (val open = MediaIntake.open(context, uri, expectedKind)) {
                is MediaIntake.Open.Reject -> return@withContext MediaScanState.Failed(open.userMessage)
                is MediaIntake.Open.Ok -> {
                    val intake = open.intake
                    if (intake.kind != expectedKind) {
                        open.pfd.close()
                        return@withContext MediaScanState.Failed(
                            "That file is a ${MediaIntake.labelFor(intake.kind)} file, " +
                                "not ${MediaIntake.labelFor(expectedKind)}. Please pick the right type.")
                    }
                    onPhase("Analyzing ${MediaIntake.labelFor(intake.kind).lowercase()} on this device…")
                    val result = try {
                        when (intake.kind) {
                            "AUDIO" -> VoiceAuthenticityAnalyzer.analyze(context, uri)
                            "IMAGE" -> ImageAuthenticityAnalyzer.analyze(context, uri)
                            else -> VideoAuthenticityAnalyzer.analyze(context, uri).result
                        }
                    } finally {
                        try { open.pfd.close() } catch (_: Exception) {}
                    }

                    onPhase("Recording result…")
                    val eventId = recordHistory(result, intake.extension)

                    // Explanation is OPTIONAL and last (spec §3/§8): a failure
                    // here never changes the displayed detection result.
                    var explanation: String? = null
                    if (withExplanation && result.status != MediaSecurityResult.Status.ANALYSIS_FAILED) {
                        onPhase("Generating AI explanation…")
                        explanation = try {
                            MediaSecurityExplanationService.explain(context, result)
                        } catch (_: Exception) { null }
                    }
                    MediaScanState.Done(
                        result = result,
                        explanation = explanation,
                        explanationAvailable = explanation != null,
                        eventId = eventId
                    )
                }
            }
        } catch (oom: OutOfMemoryError) {
            MediaScanState.Failed("The file was too large for this device's memory. Try a smaller file.")
        } catch (_: Exception) {
            MediaScanState.Failed("Unable to complete the analysis. Please try again.")
        }
    }

    /**
     * History (spec §11): store the MINIMUM — timestamp, media type, result,
     * confidence, risk level, summary. Never the media itself, never a path.
     */
    private suspend fun recordHistory(result: MediaSecurityResult, extension: String?): Long? = try {
        val repo = com.cybershieldai.data.repository.EventRepository(context)
        val summary = buildString {
            append("AI Media: ${result.mediaType.lowercase()} file")
            extension?.let { append(" (.$it)") }
            append(" — ${result.statusLabel}")
        }
        val outcome = repo.recordManual(
            category = "MEDIA",
            classification = when (result.status) {
                MediaSecurityResult.Status.POTENTIALLY_AI_GENERATED,
                MediaSecurityResult.Status.POTENTIALLY_MANIPULATED -> "SUSPICIOUS"
                MediaSecurityResult.Status.ANALYSIS_FAILED -> "INFO"
                else -> "SAFE"
            },
            riskScore = result.confidence,
            indicators = result.indicators.take(6),
            summary = summary
        )
        outcome.eventId
    } catch (_: Exception) {
        null
    }

    /** Load one stored analysis event (used when reopening from history). */
    suspend fun storedEvent(eventId: Long): SecurityEventEntity? =
        withContext(Dispatchers.IO) {
            try {
                DatabaseProvider.get(context).securityEventDao().byId(eventId)
            } catch (_: Exception) { null }
        }
}
