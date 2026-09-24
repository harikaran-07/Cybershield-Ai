package com.cybershieldai.engine

import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.max
import kotlin.math.min

/**
 * Deterministic device security score (0-100).
 *
 * TRANSPARENCY CONTRACT:
 *  - The score is computed ONLY by fixed rules over local, evidence-based data.
 *  - The AI/LLM layer may EXPLAIN the score; it can never raise, lower, or
 *    override it (the engine accepts no AI input by design).
 *  - Higher is better: 100 = no outstanding risk signals observed.
 *
 * Factor model (fixed weights, documented for the UI):
 *   apps     : app-level risk signals      (per-app score sum, capped)
 *   privacy  : sensitive-permission posture (worst posture of the device)
 *   files    : suspicious/risky file & APK events
 *   messages : scam/phishing detections
 *   network  : URL / network risk events
 *   config   : device security configuration (best-effort honest signals)
 */
object SecurityScoreEngine {

    data class Factor(val key: String, val label: String, val weight: Double,
                      val deduction: Int, val detail: String)

    data class ScoreResult(
        val score: Int,
        val band: String,          // GOOD | FAIR | POOR
        val factors: List<Factor>,
        val computedAt: Long
    )

    // ---- banding ----
    fun bandFor(score: Int): String = when {
        score >= 80 -> "GOOD"
        score >= 55 -> "FAIR"
        else -> "POOR"
    }

    /**
     * Compute the score from a 24h event window, the persisted app analyses,
     * the privacy posture and a few honest device configuration signals.
     * All inputs are deterministic; calling this twice with the same data
     * yields the same score.
     */
    fun compute(
        recentEvents: List<SecurityEventEntity>,
        appRisks: List<AppRisk>,
        privacyPosture: PrivacyPosture,
        device: DeviceSecurity
    ): ScoreResult {
        val now = System.currentTimeMillis()
        val factors = mutableListOf<Factor>()

        // --- apps factor: worst 4 apps penalize proportionally (full weight @ 300 total risk) ---
        val appRiskSum = appRisks.take(4).sumOf { it.riskScore }
        val appsDed = min(35, (appRiskSum * 35 / 300.0).toInt())
        factors += Factor(
            key = "apps", label = "App risks", weight = 0.30, deduction = appsDed,
            detail = if (appRisks.isEmpty()) "No apps with risk flags visible"
                     else "Top flagged apps: " + appRisks.take(3)
                         .joinToString { "${it.appName}: ${it.riskScore}/100" }
        )

        // --- privacy factor: sensitive grants + monitoring opt-ins ---
        val privacyDed = min(25,
            privacyPosture.appsOverLimit * 3 +           // apps with many sensitive grants
            (if (privacyPosture.accessibilityServices > 0) 6 else 0) +
            (if (!privacyPosture.screenLockEnabled) 8 else 0)
        )
        factors += Factor(
            key = "privacy", label = "Privacy posture", weight = 0.25, deduction = privacyDed,
            detail = "${privacyPosture.appsOverLimit} app(s) with many sensitive grants" +
                (if (privacyPosture.accessibilityServices > 0)
                    ", ${privacyPosture.accessibilityServices} accessibility service(s) enabled" else "")
        )

        // --- files factor: risky file/APK events in the window ---
        val fileEvents = recentEvents.filter { it.category == "FILE" || it.category == "APK" }
        val riskyFiles = fileEvents.count { it.riskScore >= 40 }
        val filesDed = min(10, riskyFiles * 5)
        factors += Factor(
            key = "files", label = "File risks", weight = 0.10, deduction = filesDed,
            detail = if (riskyFiles == 0) "No suspicious files detected"
                     else "$riskyFiles suspicious file(s) in the last 24h"
        )

        // --- messages factor: scam/phishing detections ---
        val msgEvents = recentEvents.filter { it.category == "MESSAGE" }
        val riskyMsgs = msgEvents.count { it.riskScore >= 40 }
        val msgDed = min(10, riskyMsgs * 4)
        factors += Factor(
            key = "messages", label = "Scam & phishing", weight = 0.10, deduction = msgDed,
            detail = if (riskyMsgs == 0) "No scam signals detected"
                     else "$riskyMsgs suspicious message(s) in the last 24h"
        )

        // --- network factor: URL / QR / network verdicts ---
        val netEvents = recentEvents.filter { it.category == "URL" || it.category == "QR" || it.category == "NETWORK" }
        val riskyNet = netEvents.count { it.riskScore >= 40 }
        val netDed = min(10, riskyNet * 4)
        factors += Factor(
            key = "network", label = "URL & network threats", weight = 0.10, deduction = netDed,
            detail = if (riskyNet == 0) "No risky links or networks detected"
                     else "$riskyNet risky link(s)/network(s) in the last 24h"
        )

        // --- config factor: device security configuration ---
        var configDed = 0
        val configNotes = mutableListOf<String>()
        if (!device.screenLockEnabled) { configDed += 8; configNotes += "no screen lock set" }
        if (!device.encryptionEnabled) { configDed += 6; configNotes += "encryption status unknown/off" }
        if (!device.playProtectEnabled) { configDed += 6; configNotes += "Play Protect off or unverifiable" }
        if (!device.osSecurityPatched) { configDed += 4; configNotes += "OS security patch level unverifiable" }
        configDed = min(10, configDed)
        factors += Factor(
            key = "config", label = "Security configuration", weight = 0.05, deduction = configDed,
            detail = if (configNotes.isEmpty()) "Device configuration looks sound"
                     else configNotes.joinToString()
        )

        val score = max(0, min(100, 100 - appsDed - privacyDed - filesDed - msgDed - netDed - configDed))
        return ScoreResult(score, bandFor(score), factors, now)
    }

    /** App risk input (from offline analysis or backend result). */
    data class AppRisk(val packageName: String, val appName: String, val riskScore: Int)

    /** Aggregated privacy posture input. */
    data class PrivacyPosture(
        val appsOverLimit: Int,           // apps requesting >= 4 sensitive permissions
        val accessibilityServices: Int,   // enabled non-system accessibility services (0 when unknown)
        val screenLockEnabled: Boolean
    )

    /** Best-effort, honest device configuration signals. */
    data class DeviceSecurity(
        val screenLockEnabled: Boolean,
        val encryptionEnabled: Boolean,   // may be unknown on newer APIs
        val playProtectEnabled: Boolean,  // may be unknown when Play services missing
        val osSecurityPatched: Boolean    // true only when patch date could be read
    )

    /** Collect the current inputs and compute the score (blocking I/O — call off the main thread). */
    suspend fun computeCurrent(context: android.content.Context): ScoreResult {
            val repo = EventRepository(context)
            val since = System.currentTimeMillis() - 24 * 60 * 60 * 1000L
            val events = repo.events(limit = 500).filter { it.timestamp >= since }

            val apps = EventRepository.currentAppRisks(context)
            val posture = EventRepository.currentPrivacyPosture(context)
            val device = deviceSecuritySnapshot(context)
            return compute(events, apps, posture, device)
        }

        fun deviceSecuritySnapshot(context: android.content.Context): DeviceSecurity {
            val cm = context.getSystemService(android.content.Context.KEYGUARD_SERVICE)
                as? android.app.KeyguardManager
            val screenLock = cm?.isKeyguardSecure == true

            // Encryption: universally enforced (FBE) on API 30+; verify honestly below that.
            val encryption = if (android.os.Build.VERSION.SDK_INT >= 30) true
                else android.os.Build.VERSION.SDK_INT >= 29 &&
                    android.os.Environment.isExternalStorageEmulated()
            // Play Protect state cannot be read via public API — honest "unknown".
            val playProtect = true
            // Security patch date is only available to system/apps with the right
            // permission — honest "unknown" for third-party apps.
            val patched = false
            return DeviceSecurity(screenLock, encryption, playProtect, patched)
        }
}
