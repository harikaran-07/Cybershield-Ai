package com.cybershieldai.ai

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import com.cybershieldai.data.local.SettingsStore
import org.json.JSONObject

/**
 * Scanner AI engine (spec §2/§3/§10): intelligent analysis of rule-engine
 * signals by the SAME on-device LLM the chat uses (Qwen2.5-0.5B via
 * MediaPipe tasks-genai). 100% local — no API key, no cloud, no Ollama host.
 *
 * Design:
 *  - The LLM NEVER decides security alone. The deterministic rule engine runs
 *    first; the LLM receives the extracted signals and must explain/classify
 *    ONLY that evidence (§3, §11: never invent evidence).
 *  - Output is strict JSON (§10). Invalid/absent JSON → one constrained
 *    retry → deterministic rule fallback. Never crashes on bad output (§18).
 *  - Inference is serialized by a mutex and time-boxed (§19: no concurrent
 *    sessions, no main-thread work, no unbounded generation).
 *  - Status is honest (§2): LOCAL_READY only when the model file exists and
 *    loads; otherwise RULE_ENGINE and callers say so.
 */
object ScannerAiAnalyzer {

    private const val TAG = "CyberShieldScannerAi"

    /** Honest engine state for the UI (§2/§14). */
    enum class Engine { LOCAL_READY, RULE_ENGINE }

    /** Structured evidence for one scan (§3: extracted signals, not raw dumps). */
    data class Signals(
        val type: String,                 // URL | MESSAGE | QR | FILE | DEVICE
        val title: String,                // URL text / filename / short subject
        val features: List<String>,       // "key: value" evidence lines
        val ruleClassification: String,   // deterministic engine result
        val ruleRiskScore: Int,           // deterministic 0..100
        val ruleIndicators: List<String>  // only actually-detected indicators
    )

    /** LLM verdict after validation (never trusted blindly, §10/§12). */
    data class Verdict(
        val classification: String,   // SAFE | SUSPICIOUS | DANGEROUS
        val riskScore: Int,           // 0..100
        val confidence: Double,       // 0..1
        val reasons: List<String>,
        val recommendations: List<String>,
        val summary: String
    )

    @Volatile private var cachedEngine: Engine? = null
    private val inferMutex = Mutex()

    /** Worst-case ceiling per inference (§18 LLM timeout). Typical runs are
     *  far shorter; slow/low-end devices get the full budget rather than a
     *  truncated JSON that would needlessly fall back to rules. */
    private const val GENERATE_TIMEOUT_MS = 60_000L

    /** Ceiling for the model load itself. On real phones a cold load can be
     *  slow — or stall entirely on memory pressure. Without this bound the
     *  scan would hang at "Analyzing..." forever (§18). On timeout we fall
     *  back to rules; a load that eventually completes in the background is
     *  still reusable by the next call. */
    private const val LOAD_TIMEOUT_MS = 45_000L

    /** Below this free RAM (bytes) the LLM is skipped on phones (§21) —
     *  loading into a memory-pressured process risks a native crash that a
     *  Kotlin try/catch cannot intercept. Rule analysis is always available. */
    private const val MIN_FREE_RAM_BYTES = 350L * 1024 * 1024

    /** System prompt (spec §11) — strict, evidence-only, JSON-only. */
    private const val SYSTEM_PROMPT =
        "You are CyberShield's offline security analysis engine. " +
            "Analyze only the security evidence provided to you. " +
            "Never invent URLs, permissions, malware names, vulnerabilities, or threat intelligence. " +
            "Do not claim certainty when the evidence is insufficient. " +
            "Distinguish between SAFE, SUSPICIOUS, DANGEROUS. " +
            "A suspicious indicator does not automatically prove malware or fraud. " +
            "Return concise structured JSON containing: classification, risk_score, " +
            "confidence, reasons, recommendations, summary. " +
            "Your task is security analysis, not generic conversation."

    /** Current honest engine state (checks the real model file each call). */
    fun currentEngine(context: Context): Engine =
        if (AiModelManager.isInstalled(context)) Engine.LOCAL_READY else Engine.RULE_ENGINE

    /**
     * Analyze one scan's signals. Returns a validated LLM verdict, or a
     * deterministic rule-based verdict when the model is unavailable/invalid
     * (`source` tells the truth either way).
     */
    suspend fun analyze(
        context: Context,
        signals: Signals
    ): Pair<Verdict, Engine> = withContext(Dispatchers.IO) {
        when (val handle = readyModel(context)) {
            is ModelHandle.Skip ->
                ruleFallback(signals, handle.reason) to Engine.RULE_ENGINE
            ModelHandle.Ready -> {
                val prompt = buildPrompt(signals, constrained = false)
                val parsed = infer(prompt)?.let { parseVerdict(it) }
                if (parsed != null) {
                    cachedEngine = Engine.LOCAL_READY
                    disarm(context)
                    return@withContext parsed to Engine.LOCAL_READY
                }
                // §10: one constrained retry before falling back.
                val retryParsed = infer(buildPrompt(signals, constrained = true))
                    ?.let { parseVerdict(it) }
                if (retryParsed != null) {
                    cachedEngine = Engine.LOCAL_READY
                    disarm(context)
                    return@withContext retryParsed to Engine.LOCAL_READY
                }
                Log.w(TAG, "LLM output invalid twice — rule fallback")
                cachedEngine = Engine.RULE_ENGINE
                disarm(context) // native path fine; just bad JSON
                ruleFallback(signals) to Engine.RULE_ENGINE
            }
        }
    }

    /** Result of the shared model-acquisition guards. */
    private sealed class ModelHandle {
        object Ready : ModelHandle()
        data class Skip(val reason: String) : ModelHandle()
    }

    /**
     * All guards before ANY native work: install check, crash circuit,
     * RAM floor, watchdog arm, bounded load. Shared by `analyze` (verdict
     * mode, non-URL scans) and `explain` (explanation-only, URL pipeline).
     */
    private suspend fun readyModel(context: Context): ModelHandle = withContext(Dispatchers.IO) {
        if (!AiModelManager.isInstalled(context)) {
            cachedEngine = Engine.RULE_ENGINE
            return@withContext ModelHandle.Skip(
                "Local LLM unavailable — rule-based analysis of the detected signals.")
        }

        val settings = SettingsStore(context)

        // Crash watchdog (phone-only failure mode): if the process died during
        // scanner LLM use last time, the native runtime is unstable on this
        // device — run rules permanently until the model is reinstalled.
        // 2+ consecutive deaths = circuit open. Kotlin cannot catch SIGSEGV;
        // this persisted counter is the only defense.
        if (settings.scannerLlmCrashesOnce() >= 2) {
            Log.w(TAG, "LLM circuit open (prior native crashes) — rule engine only")
            cachedEngine = Engine.RULE_ENGINE
            return@withContext ModelHandle.Skip(
                "Local AI disabled after repeated crashes on this device — reinstall the model in AI Model Settings to retry.")
        }

        // §21 low-end guard: skip the LLM when the device is memory-pressured.
        val mem = context.getSystemService(Context.ACTIVITY_SERVICE)
            as? android.app.ActivityManager
        val freeRam = mem?.let { m ->
            val mi = android.app.ActivityManager.MemoryInfo()
            m.getMemoryInfo(mi)
            mi.availMem
        } ?: Long.MAX_VALUE
        if (freeRam < MIN_FREE_RAM_BYTES) {
            Log.w(TAG, "Low RAM (${freeRam / (1024 * 1024)} MB free) — rule engine only")
            cachedEngine = Engine.RULE_ENGINE
            return@withContext ModelHandle.Skip(
                "Local AI skipped — the device is low on memory right now. Rule-based analysis completed.")
        }

        // Arm BEFORE any native work: if the process dies during load or
        // inference, the next launch sees the counter and stops trying.
        try {
            settings.setScannerLlmCrashes(settings.scannerLlmCrashesOnce() + 1)
        } catch (_: Exception) {}

        // Load once; repeated scans reuse the resident model (§19). Bounded so
        // a stalled load can never leave the scan UI spinning (§18).
        val loaded = withTimeoutOrNull(LOAD_TIMEOUT_MS) { LocalLlmRuntime.load(context) }
        if (loaded == null || loaded.isFailure) {
            Log.w(TAG, if (loaded == null) "LLM load timed out" else "LLM load failed: ${loaded.exceptionOrNull()?.message}")
            cachedEngine = Engine.RULE_ENGINE
            return@withContext ModelHandle.Skip(if (loaded == null)
                "Local AI model took too long to load on this device — rule-based analysis completed."
            else
                "Local AI model failed to load (${loaded.exceptionOrNull()?.message ?: "unknown error"}) — rule-based analysis completed.")
        }
        ModelHandle.Ready
    }

    /** The process completed a native round-trip — reset the watchdog. */
    private suspend fun disarm(context: Context) {
        try { SettingsStore(context).setScannerLlmCrashes(0) } catch (_: Exception) {}
    }

    // ------------------------------------------------------------------
    // EXPLANATION-ONLY STAGE (hard architecture rule): the URL security
    // engine produces the FINAL verdict; the LLM may only narrate it in
    // natural language. It can never change the score, classification,
    // signals or recommendation — `explain` returns prose or null, and
    // null simply means "AI explanation unavailable" in the UI.
    // ------------------------------------------------------------------

    /** System prompt for explanation generation — never classification. */
    private const val EXPLAIN_PROMPT =
        "You are CyberShield AI, an offline assistant that explains security results to a " +
            "non-technical user. The local security engine has ALREADY analyzed a URL and " +
            "produced a FINAL verdict. Explain that verdict in 2-4 short sentences. " +
            "Do not change the risk score, classification or signals. Do not invent new " +
            "security findings. Do not claim you visited or verified the website. " +
            "Be clear and conservative."

    /**
     * Human-readable explanation of an already-final engine result.
     * Input: the structured JSON of the FINAL result. Output: prose only.
     * Null = explanation unavailable; the engine result stands unchanged.
     */
    suspend fun explain(context: Context, finalResultJson: String): String? =
        explainWithPrompt(context, finalResultJson, EXPLAIN_PROMPT)

    /**
     * Shared explanation stage for every CyberShield detector (URL, media,
     * AI-voice). The caller passes the FINAL structured result plus its own
     * system prompt; the LLM only narrates. Null = explanation unavailable.
     */
    suspend fun explainWithPrompt(
        context: Context,
        finalResultJson: String,
        systemPrompt: String
    ): String? = withContext(Dispatchers.IO) {
        when (val handle = readyModel(context)) {
            is ModelHandle.Skip -> {
                Log.i(TAG, "explain unavailable: ${handle.reason}")
                null
            }
            ModelHandle.Ready -> {
                val prompt = buildString {
                    append(systemPrompt)
                    append("\n\nFinal security engine result (do not change):\n")
                    append(finalResultJson.take(1400))
                    append("\n\nAssistant:")
                }
                val text = inferProse(prompt)
                disarm(context) // the process survived — reset the watchdog
                if (text != null) cachedEngine = Engine.LOCAL_READY
                text
            }
        }
    }

    /** One serialized, time-boxed PROSE generation (no JSON contract). */
    private suspend fun inferProse(prompt: String): String? = try {
        inferMutex.withLock {
            withTimeoutOrNull(GENERATE_TIMEOUT_MS) {
                val sb = StringBuilder()
                LocalLlmRuntime.generate(prompt).take(350).collect { sb.append(it) }
                sb.toString().trim()
                    .removePrefix("Assistant:").trim()
                    .take(700)
                    .ifEmpty { null }
            }
        }
    } catch (t: Throwable) {
        Log.w(TAG, "explanation inference failed: ${t.message}")
        null
    }

    /** One serialized, time-boxed generation. Returns raw text or null. */
    private suspend fun infer(prompt: String): String? =
        try {
            inferMutex.withLock {
                withTimeoutOrNull(GENERATE_TIMEOUT_MS) {
                    val sb = StringBuilder()
                    LocalLlmRuntime.generate(prompt).take(200).collect { sb.append(it) }
                    val text = sb.toString().trim()
                    text.ifEmpty { null }
                }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "inference failed: ${t.message}")
            null
        }

    private fun buildPrompt(s: Signals, constrained: Boolean): String {
        val evidence = buildString {
            appendLine("Scan type: ${s.type}")
            appendLine("Subject: ${s.title.take(200)}")
            s.features.take(10).forEach { appendLine(it.take(160)) }
            appendLine("Rule engine findings (deterministic, verified):")
            appendLine("- classification: ${s.ruleClassification}")
            appendLine("- risk_score: ${s.ruleRiskScore}")
            if (s.ruleIndicators.isEmpty()) appendLine("- indicators: none detected")
            else s.ruleIndicators.take(6).forEach { appendLine("- indicator: ${it.take(140)}") }
        }
        return buildString {
            append(SYSTEM_PROMPT)
            append("\n\nSecurity evidence:\n").append(evidence)
            if (constrained) {
                append("\nRespond with ONE JSON object only. No prose, no markdown, no code fences.")
            } else {
                append("\n\nRespond with ONLY the JSON object.")
            }
            append("\n\nAssistant:")
        }
    }

    /** Validate + clamp LLM JSON. Null when invalid (§10). */
    private fun parseVerdict(raw: String): Verdict? = try {
        val start = raw.indexOf('{')
        val end = raw.lastIndexOf('}')
        if (start < 0 || end <= start) null
        else {
            val obj = JSONObject(raw.substring(start, end + 1))
            val classification = when (obj.optString("classification").uppercase().trim()) {
                "SAFE" -> "SAFE"
                "SUSPICIOUS", "REVIEW" -> "SUSPICIOUS"
                "DANGEROUS", "SCAM", "PHISHING", "MALICIOUS", "HIGH RISK", "THREAT" -> "DANGEROUS"
                else -> return null
            }
            val risk = obj.optInt("risk_score", -1).coerceIn(0, 100)
            val conf = when {
                obj.isNull("confidence") -> 0.5
                else -> obj.optDouble("confidence", 0.5).coerceIn(0.0, 1.0)
            }
            val reasons = obj.optJSONArray("reasons")?.let { arr ->
                (0 until arr.length()).mapNotNull { i ->
                    arr.optString(i).trim().takeIf { it.isNotEmpty() }
                }
            } ?: emptyList()
            val recs = obj.optJSONArray("recommendations")?.let { arr ->
                (0 until arr.length()).mapNotNull { i ->
                    arr.optString(i).trim().takeIf { it.isNotEmpty() }
                }
            } ?: emptyList()
            Verdict(
                classification = classification,
                riskScore = risk,
                confidence = conf,
                reasons = reasons.take(6),
                recommendations = recs.take(3),
                summary = obj.optString("summary").trim().take(500)
            )
        }
    } catch (_: Exception) {
        null
    }

    /**
     * Deterministic fallback (§13/§18): derived ONLY from rule-engine output —
     * the same data the UI would have shown without the model.
     */
    private fun ruleFallback(s: Signals, reason: String = "Local LLM unavailable — rule-based analysis of the detected signals."): Verdict {
        val classification = when {
            s.ruleClassification in setOf("SCAM", "PHISHING", "DANGEROUS") -> "DANGEROUS"
            s.ruleClassification in setOf("SUSPICIOUS", "RISKY", "REVIEW") -> "SUSPICIOUS"
            s.ruleRiskScore >= 60 -> "DANGEROUS"
            s.ruleRiskScore >= 30 -> "SUSPICIOUS"
            else -> "SAFE"
        }
        return Verdict(
            classification = classification,
            riskScore = s.ruleRiskScore,
            confidence = 0.5,
            reasons = s.ruleIndicators,
            recommendations = emptyList(),
            summary = reason
        )
    }
}
