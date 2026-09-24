package com.cybershieldai.data.repository

import com.cybershieldai.data.model.*
import com.cybershieldai.utils.OfflineAnalyzer
import com.cybershieldai.utils.OfflineResult
import com.cybershieldai.utils.UrlSecurity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Outcome of a scan: online (full ML) or offline (local heuristic rules). */
sealed class ScanOutcome {
    data class Success(val result: AnalysisResponse, val online: Boolean) : ScanOutcome()
    data class Error(val message: String, val offlineResult: AnalysisResponse? = null) : ScanOutcome()
}

class ScanRepository {

    /** v1 result card output: local rules mapped exactly as the original APK. */
    private fun offlineOutcome(local: OfflineResult): ScanOutcome.Success =
        ScanOutcome.Success(
            result = AnalysisResponse(
                scanId = "local-${System.currentTimeMillis()}",
                type = local.type,
                riskScore = local.riskScore,
                severity = local.severity,
                classification = local.classification,
                confidence = 0.5,
                indicators = local.indicators,
                detectionMethods = listOf("Offline Rules"),
                recommendation = local.recommendation,
                aiExplanation = null
            ),
            online = false
        )

    // ------------------------------------------------------------------
    // Message scan — rule engine first, then the ON-DEVICE LLM explains and
    // classifies the extracted evidence (§3 hybrid). No network at all.
    // ------------------------------------------------------------------
    suspend fun scanMessage(text: String, context: android.content.Context? = null): ScanOutcome {
        val local = OfflineAnalyzer.analyzeMessage(text)
            ?: return ScanOutcome.Error("Please paste a message to scan.", null)
        return enrichWithLocalAi(
            context, local, type = "MESSAGE", title = text.take(120),
            features = messageFeatures(text)
        )
    }

    // ------------------------------------------------------------------
    // URL scan — validate → parse → rule features → on-device LLM.
    // The URL is NEVER opened or contacted (§4/§16).
    // ------------------------------------------------------------------
    suspend fun scanUrl(url: String, context: android.content.Context? = null): ScanOutcome {
        if (!isValidUrl(url)) return ScanOutcome.Error("Invalid URL — check the address and try again.", null)
        val local = OfflineAnalyzer.analyzeUrl(url)
        return enrichWithLocalAi(
            context, local, type = "URL", title = url.take(160),
            features = urlFeatures(url)
        )
    }

    // ------------------------------------------------------------------
    // Dedicated phishing-URL pipeline (URL-scanner spec §2): normalizer →
    // deterministic signal engine → prior-scan lookup → reputation provider
    // (full scan only, §9) → optional on-device LLM reasoning. The URL is
    // analyzed as TEXT and never opened.
    // ------------------------------------------------------------------

    /** Outcome of the dedicated URL scan (signal cards + final engine verdict). */
    data class UrlScanOutcome(
        val urlResult: UrlSecurity.UrlResult,
        val aiNote: String?,                 // LLM EXPLANATION of the final result; null = unavailable
        val detectionMethods: List<String>,
        val error: String? = null
    )

    /** Stable prior-scan key: canonical analysis form, truncated identically
     *  on write and read (Room summary column truncates at 140). */
    private fun urlPriorLabel(analysisUrl: String) =
        "URL: " + UrlSecurity.normalize(analysisUrl).analysis.take(128)

    suspend fun scanUrlDetailed(
        rawUrl: String,
        context: android.content.Context?,
        full: Boolean
    ): UrlScanOutcome {
        val norm = UrlSecurity.normalize(rawUrl)
        if (!norm.valid) {
            return UrlScanOutcome(
                urlResult = UrlSecurity.UrlResult(
                    riskScore = 0, classification = "INVALID", severity = "SAFE",
                    signals = emptyList(), indicators = emptyList(),
                    recommendation = norm.problem ?: "Please enter a valid URL.",
                    summary = norm.problem ?: "Please enter a valid URL."),
                aiNote = null, detectionMethods = emptyList(),
                error = norm.problem ?: "Please enter a valid URL.")
        }

        // Prior-scan lookup (§8) — real Room history, honestly labeled.
        val prior = context?.let { ctx ->
            try {
                val entity = com.cybershieldai.data.local.DatabaseProvider.get(ctx)
                    .securityEventDao().latestByUrlLabel(urlPriorLabel(norm.analysis))
                entity?.let {
                    UrlSecurity.PriorScan(it.timestamp, it.classification, it.riskScore)
                }
            } catch (_: Exception) { null }
        }

        // Deterministic signal engine (§4-§7) — THE decision stage.
        var result = UrlSecurity.analyze(norm.analysis, prior)
        val methods = mutableListOf("Structure rules", "Pattern analysis")
        if (prior != null) methods += "Prior-scan history"

        // Reputation provider (§9) — full scan only; honest when unconfigured.
        val provider = if (full) UrlSecurity.reputationProvider() else null
        if (provider != null) {
            val repSignal = provider.check(norm.analysis)
            if (repSignal != null) {
                result = UrlSecurity.withExtraSignal(result, repSignal)
                methods += "Reputation check"
            } else {
                result = UrlSecurity.withExtraSignal(
                    result,
                    UrlSecurity.Signal(
                        "Reputation check", UrlSecurity.Status.WARNING,
                        provider.unavailableMessage, 0))
                methods += "Reputation (unavailable)"
            }
        }

        // result is now FINAL — score, classification, signals and
        // recommendation are locked by the security engine.

        // LAST STAGE: the local LLM may only EXPLAIN the final result (hard
        // architecture rule). It cannot change score/classification/signals.
        // Runs for both quick and full scans; null = "AI explanation
        // unavailable" and the engine result is shown unchanged.
        val aiNote: String? = context?.let { ctx ->
            try {
                val signalsJson = result.signals.joinToString("; ") {
                    "${it.title} (${it.status}): ${it.description}".take(180)
                }
                val finalJson = org.json.JSONObject().apply {
                    put("url", norm.analysis.take(200))
                    put("risk_score", result.riskScore)
                    put("classification", result.classification)
                    put("signals", org.json.JSONArray().apply {
                        result.signals.take(8).forEach { s ->
                            put(org.json.JSONObject().apply {
                                put("name", s.title)
                                put("severity", s.status.name)
                                put("finding", s.description.take(120))
                            })
                        }
                    })
                    put("recommendation", result.recommendation.take(200))
                }.toString()
                com.cybershieldai.ai.ScannerAiAnalyzer.explain(ctx, finalJson)
            } catch (_: Exception) { null }
        }
        if (aiNote != null) methods += "AI explanation"

        return UrlScanOutcome(result, aiNote, methods)
    }

    // ------------------------------------------------------------------
    // QR scan — same hybrid path; content routed by type (§8).
    // ------------------------------------------------------------------
    suspend fun scanQr(content: String, context: android.content.Context? = null): ScanOutcome {
        val isUrl = content.startsWith("http://") || content.startsWith("https://") ||
            content.contains("www.", ignoreCase = true)
        val local = if (isUrl) OfflineAnalyzer.analyzeUrl(content)
        else OfflineAnalyzer.analyzeMessage(content)
            ?: OfflineAnalyzer.analyzeUrl(content)
        return enrichWithLocalAi(
            context, local, type = "QR", title = content.take(160),
            features = (if (isUrl) urlFeatures(content) else messageFeatures(content)) +
                listOf("source: QR code scan")
        )
    }

    // ------------------------------------------------------------------
    // Explanation stage (hard architecture rule): the deterministic rule
    // engine produces the FINAL verdict; the local LLM may only explain it.
    // aiExplanation carries prose honestly labeled — null when the model
    // is unavailable, and the engine result is shown unchanged.
    // ------------------------------------------------------------------
    private suspend fun enrichWithLocalAi(
        context: android.content.Context?,
        local: OfflineResult,
        type: String,
        title: String,
        features: List<String>
    ): ScanOutcome {
        val base = offlineOutcome(local)
        val ctx = context ?: return base

        // The rule result is FINAL — score, classification, indicators and
        // recommendation are locked before the LLM is ever invoked.
        val final = base.result

        // LAST STAGE: explanation-only prose. Never a verdict, never a score.
        val aiNote = try {
            val finalJson = org.json.JSONObject().apply {
                put("type", type)
                put("subject", title.take(150))
                put("risk_score", final.riskScore)
                put("classification", final.classification)
                put("indicators", org.json.JSONArray().apply {
                    final.indicators.take(6).forEach { put(it.take(120)) }
                })
                put("recommendation", final.recommendation.take(200))
            }.toString()
            com.cybershieldai.ai.ScannerAiAnalyzer.explain(ctx, finalJson)
        } catch (_: Exception) { null }

        return ScanOutcome.Success(
            result = final.copy(
                aiExplanation = aiNote,
                detectionMethods = if (aiNote != null)
                    listOf("Offline Rules", "AI explanation") else listOf("Offline Rules")
            ),
            online = false
        )
    }

    private fun isValidUrl(url: String): Boolean = try {
        val u = java.net.URI(url.trim())
        u.scheme in setOf("http", "https") && !u.host.isNullOrBlank()
    } catch (_: Exception) { false }

    /** Deterministic URL evidence lines (§4) — no fetching, structure only. */
    private fun urlFeatures(url: String): List<String> = buildList {
        val low = url.lowercase()
        add("scheme: ${low.substringBefore("://")}")
        val host = low.removePrefix("https://").removePrefix("http://").substringBefore('/')
        add("host: $host")
        add("domain_ending: .${host.substringAfterLast('.', "?")}")
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)) add("host_is_raw_ip: true")
        if ("@" in low) add("contains_userinfo_at: true")
        if (host.count { it == '.' } >= 4) add("deep_subdomains: true")
        add("length: ${url.length}")
    }

    /** Deterministic message evidence lines (§5). */
    private fun messageFeatures(text: String): List<String> = buildList {
        add("length: ${text.length}")
        Regex("(https?://|www\\.)[^\\s]+", RegexOption.IGNORE_CASE).find(text)?.let {
            add("contains_link: ${it.value.take(80)}")
        }
        add("has_digits: ${text.any { c -> c.isDigit() }}")
    }

}

