package com.cybershieldai.engine

import com.cybershieldai.data.local.SecurityEventEntity
import kotlin.math.min

/** Local risk engine — transparent weighted combination, works fully offline. */
object LocalRiskEngine {

    fun severityFor(score: Int): String = when {
        score >= 90 -> "CRITICAL"
        score >= 75 -> "HIGH"
        score >= 50 -> "MEDIUM"
        score >= 25 -> "LOW"
        else -> "SAFE"
    }

    /** Confidence heuristic — LOW until multiple indicators or backend ML agree. */
    fun confidenceFor(indicatorCount: Int, backendUsed: Boolean): Double = when {
        backendUsed && indicatorCount >= 3 -> 0.85
        backendUsed -> 0.7
        indicatorCount >= 3 -> 0.6
        indicatorCount >= 1 -> 0.45
        else -> 0.3
    }

    /**
     * Combine base detector score with correlation boost and indicator breadth.
     * Weights: base 0.65, correlation boost 0.25, breadth 0.10 — capped at 100.
     */
    fun combine(baseScore: Int, correlationBoost: Int, indicatorCount: Int): Int {
        val breadth = min(100, indicatorCount * 15)
        val combined = (0.65 * baseScore) + (0.25 * correlationBoost) + (0.10 * breadth)
        return min(100, Math.round(combined)).toInt().coerceAtLeast(baseScore / 2)
    }

    fun recommendationFor(category: String, severity: String): String = when {
        severity == "SAFE" -> "No significant risk indicators found. Stay cautious with links and attachments."
        category == "URL" -> "Do not open this link or enter any credentials. Type the official address yourself."
        category == "MESSAGE" -> "Do not reply or open links. Verify through the organization's official app or website."
        category == "QR" -> "Do not scan codes from unknown posters. Verify payment QRs with the payee through another channel."
        category == "FILE" || category == "APK" -> "Do not open or install this file unless you fully trust the source."
        category == "APP" -> "Review this application's permissions in Android Settings."
        category == "PRIVACY" -> "Review app permissions and revoke anything you don't recognize."
        category == "NETWORK" -> "Avoid sensitive accounts on this network until verified. Consider a trusted VPN."
        else -> "Review the indicators and take standard precautions."
    }
}

/** Local threat correlation — escalates risk when related signals co-occur. */
object LocalThreatCorrelator {

    data class CorrelationResult(val boost: Int, val matchedSignals: List<String>)

    private val relatedCategories = setOf("URL", "MESSAGE", "QR", "APP")

    /**
     * Assess whether recent high-risk events plus the current one form a chain.
     * Boost scales with the number of distinct related categories seen in the
     * last hour — mirroring the backend correlation semantics.
     */
    fun assess(recentHighRisk: List<SecurityEventEntity>, currentScore: Int): CorrelationResult {
        val cutoff = System.currentTimeMillis() - 60 * 60 * 1000L
        val recent = recentHighRisk.filter {
            it.timestamp >= cutoff && it.riskScore >= 50
        }
        if (currentScore < 50 || recent.isEmpty()) return CorrelationResult(0, emptyList())

        val categories = (recent.map { it.category } + "CURRENT").distinct()
        val relatedCount = categories.count { it in relatedCategories }
        val signals = mutableListOf<String>()
        var boost = 0

        if (relatedCount >= 2) { boost += 12; signals += "Multiple related threat categories in the last hour" }
        if (relatedCount >= 3) { boost += 10; signals += "Coordinated pattern across message, URL and app signals" }

        // Repeated host/summary overlap (same brand or domain across events)
        val summaries = recent.map { it.summary.lowercase() }
        val overlap = summaries.groupingBy { it }.eachCount().any { it.value >= 2 }
        if (overlap) { boost += 8; signals += "Repeated indicator across multiple events" }

        return CorrelationResult(min(30, boost), signals)
    }
}
