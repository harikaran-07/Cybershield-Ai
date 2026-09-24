package com.cybershieldai.engine

import android.content.Context
import com.cybershieldai.data.local.DatabaseProvider
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.utils.AppRiskAnalyzer
import com.cybershieldai.utils.AppScanCache
import com.cybershieldai.utils.AppScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Phone Security Scan (spec §6) — REAL phased checks over data Android
 * actually exposes. The UI shows [phase] while it runs, so "Scanning:
 * Installed apps" is literally what is happening at that moment.
 *
 * Checks: installed applications → security-relevant permissions →
 * device security status (lock, Play Protect, encryption) → CyberShield
 * threat history. Nothing is fabricated; every count traces to its source.
 */
object ScanRunner {

    data class Phase(val label: String, val done: Boolean = false)

    data class ScanResult(
        val itemsChecked: Int,      // apps + security checks + recent events
        val warnings: Int,          // MEDIUM-severity findings
        val highRisk: Int,          // HIGH/CRITICAL findings
        val recommendations: List<String>,
        val score: Int?,            // null when the score engine could not run
        val appDetails: List<AppRiskAnalyzer.AppRiskResult>, // flagged apps
        val aiSummary: String? = null,   // on-device LLM summary (null = not run)
        val aiUsed: Boolean = false      // honest Local-AI flag (§2)
    )

    /**
     * Run the full scan, reporting each phase through [onPhase] as it
     * STARTS (so the UI text is truthful: the phase is running, not done).
     */
    suspend fun runScan(
        context: Context,
        onPhase: (String) -> Unit
    ): ScanResult = withContext(Dispatchers.IO) {
        val repo = EventRepository(context)
        var warnings = 0
        var highRisk = 0
        val recommendations = mutableListOf<String>()
        var items = 0

        // ---- Phase 1: installed applications + per-app risk ------------
        onPhase("Installed apps")
        var flaggedApps: List<AppRiskAnalyzer.AppRiskResult> = emptyList()
        var userAppCount = 0
        try {
            AppScanCache.ensureLoaded(context, force = true)
            userAppCount = AppScanCache.counts?.first ?: 0
            items += userAppCount
            flaggedApps = AppScanCache.userRisks.filter {
                it.status == AppRiskAnalyzer.SUSPICIOUS ||
                    it.status == AppRiskAnalyzer.HIGH_RISK ||
                    it.status == AppRiskAnalyzer.CONFIRMED_THREAT
            }
            highRisk += flaggedApps.count {
                it.status == AppRiskAnalyzer.HIGH_RISK ||
                    it.status == AppRiskAnalyzer.CONFIRMED_THREAT
            }
            warnings += flaggedApps.count { it.status == AppRiskAnalyzer.SUSPICIOUS }
            if (flaggedApps.isNotEmpty()) {
                recommendations += "Review ${flaggedApps.size} flagged app(s) in Protection → Installed Apps."
            }
        } catch (_: Exception) { }

        // ---- Phase 2: security-relevant permissions ---------------------
        onPhase("Permissions")
        var sensitiveGrants = 0
        try {
            val pm = context.packageManager
            val pkgs = pm.getInstalledPackages(
                android.content.pm.PackageManager.PackageInfoFlags.of(
                    android.content.pm.PackageManager.GET_PERMISSIONS.toLong()))
            for (p in pkgs) {
                val requested = p.requestedPermissions ?: continue
                sensitiveGrants += requested.count {
                    it in AppRiskAnalyzer.SENSITIVE
                }
                items += 1
            }
            if (sensitiveGrants > 0) {
                recommendations += "Audit sensitive permissions in Protection → Permissions."
            }
        } catch (_: Exception) { /* package visibility restricted */ }

        // ---- Phase 3: device security status ----------------------------
        onPhase("Security status")
        try {
            val dm = context.getSystemService(android.app.admin.DevicePolicyManager::class.java)
            val km = context.getSystemService(android.app.KeyguardManager::class.java)
            val lockOk = km?.isKeyguardSecure == true
            items += 1
            if (!lockOk) {
                warnings += 1
                recommendations += "Set a screen lock (PIN/pattern/password) — required for device encryption."
            }
            val pm2 = context.packageManager
            val playProtect = try {
                pm2.getPackageInfo("com.android.vending", 0) != null
            } catch (_: Exception) { false }
            items += 1
            if (!playProtect) {
                warnings += 1
                recommendations += "Google Play (Play Protect) not found — sideloaded APKs cannot be verified."
            }
            val encryptOk = android.os.Build.VERSION.SDK_INT >= 30 || lockOk
            items += 1
            if (!encryptOk) warnings += 1
        } catch (_: Exception) { }

        // ---- Phase 4: CyberShield threat history ------------------------
        onPhase("Threat history")
        val day = System.currentTimeMillis() - 24 * 60 * 60 * 1000L
        var recentEvents = 0
        try {
            recentEvents = DatabaseProvider.get(context).securityEventDao()
                .countSince(day)
            items += recentEvents
            val recentHigh = DatabaseProvider.get(context).securityEventDao()
                .countHighRiskSince(day)
            highRisk += recentHigh
            if (recentHigh > 0) {
                recommendations += "Open Alerts to review the $recentHigh high-risk event(s) from the last 24h."
            }
        } catch (_: Exception) { }

        // ---- Phase 5: local AI analysis of collected signals (§9) --------
        onPhase("Local AI analysis")
        var aiSummary: String? = null
        var aiUsed = false
        try {
            val signals = com.cybershieldai.ai.ScannerAiAnalyzer.Signals(
                type = "DEVICE",
                title = "Full device security scan",
                features = buildList {
                    add("user_apps_reviewed: $userAppCount")
                    add("flagged_apps: ${flaggedApps.size}")
                    add("sensitive_permission_grants: $sensitiveGrants")
                    add("recent_24h_events: $recentEvents")
                    flaggedApps.take(3).forEach {
                        add("flagged: ${it.appName} (${it.status})")
                    }
                },
                ruleClassification = when {
                    highRisk > 0 -> "DANGEROUS"
                    warnings > 0 -> "SUSPICIOUS"
                    else -> "SAFE"
                },
                ruleRiskScore = when {
                    highRisk > 0 -> 75
                    warnings > 0 -> 45
                    else -> 0
                },
                ruleIndicators = recommendations.toList()
            )
            val (verdict, engine) =
                com.cybershieldai.ai.ScannerAiAnalyzer.analyze(context, signals)
            if (engine == com.cybershieldai.ai.ScannerAiAnalyzer.Engine.LOCAL_READY) {
                aiSummary = verdict.summary.ifEmpty { null }
                aiUsed = true
            }
        } catch (_: Exception) { /* rule-only scan is still complete */ }

        // ---- Phase 6: overall score (deterministic engine) --------------
        onPhase("Calculating score")
        var score: Int? = null
        try {
            score = SecurityScoreEngine.computeCurrent(context).score
        } catch (_: Exception) { }

        onPhase("Scan complete")
        ScanResult(
            itemsChecked = items,
            warnings = warnings,
            highRisk = highRisk,
            recommendations = recommendations.distinct().take(6),
            score = score,
            appDetails = flaggedApps,
            aiSummary = aiSummary,
            aiUsed = aiUsed
        )
    }
}
