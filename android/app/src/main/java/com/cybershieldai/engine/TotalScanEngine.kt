package com.cybershieldai.engine

import android.content.Context
import com.cybershieldai.data.local.DatabaseProvider
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.utils.AppRiskAnalyzer
import com.cybershieldai.utils.AppScanCache
import com.cybershieldai.utils.WhatChangedStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * DEVICE TOTAL SCAN — the central SCAN → DETECT → CORRELATE → EXPLAIN →
 * RECOMMEND workflow (spec §14).
 *
 * Honesty contract:
 *  - Every module reads only what Android legitimately exposes: package
 *    metadata, granted-permission declarations, device configuration signals,
 *    network capabilities, and CyberShield's OWN recorded scan/call history.
 *  - No other app's private data is accessed; nothing is claimed to be
 *    inspected that Android does not expose.
 *  - The score is computed ONLY by [SecurityScoreEngine] (deterministic).
 *  - The local LLM is the LAST stage: it explains the final result and can
 *    never change it. Unavailable model ⇒ "AI explanation unavailable".
 */
object TotalScanEngine {

    /** One coordinated check's outcome. */
    data class ModuleResult(
        val key: String,          // stable id
        val label: String,        // UI label ("Installed apps")
        val available: Boolean,   // false = unsupported on this device → marked clearly
        val checkedCount: Int,    // items actually examined
        val warnings: Int,        // MEDIUM-severity findings
        val highRisk: Int,        // HIGH/CRITICAL findings
        val summary: String,      // honest one-liner for the result list
        val route: String         // in-app remediation deep link
    )

    /**
     * A correlated pattern (spec §3): transparent rules over REAL recorded
     * evidence — never an assumption that multiple signals are an attack.
     */
    data class CorrelationCase(
        val title: String,
        val severity: String,        // MEDIUM | HIGH
        val evidence: List<String>,  // the actual events that matched
        val route: String
    )

    data class TotalResult(
        val modules: List<ModuleResult>,
        val correlations: List<CorrelationCase>,
        val score: Int?,
        val scoreBand: String?,
        val scoreDeltas: List<String>,  // "+ Safe network configuration" lines
        val actionsRequired: List<String>,
        val durationMs: Long,
        val itemsChecked: Int,
        val warnings: Int,
        val highRisk: Int
    )

    /** Phase labels shown live while each check RUNS (truthful, not retrospective). */
    val PHASES = listOf(
        "Checking installed apps…",
        "Checking app permissions…",
        "Checking security configuration…",
        "Checking network indicators…",
        "Checking URL & QR verdicts…",
        "Checking scam message signals…",
        "Correlating threats…",
        "Calculating security score…",
        "Recording scan history…"
    )

    suspend fun run(context: Context, onPhase: (String) -> Unit): TotalResult =
        withContext(Dispatchers.IO) {
            val started = System.currentTimeMillis()
            val repo = EventRepository(context)
            val modules = mutableListOf<ModuleResult>()

            val day = System.currentTimeMillis() - 24 * 60 * 60 * 1000L
            var recentEvents: List<SecurityEventEntity> = emptyList()
            try {
                recentEvents = DatabaseProvider.get(context).securityEventDao()
                    .recent(300).filter { it.timestamp >= day }
            } catch (_: Exception) { }

            // ---- Module: Installed apps --------------------------------------
            onPhase(PHASES[0])
            var userPackages: List<String> = emptyList()
            runCatching {
                AppScanCache.ensureLoaded(context, force = true)
                val counts = AppScanCache.counts
                val risks = AppScanCache.userRisks
                userPackages = AppScanCache.deviceApps?.userApps?.map { it.packageName }
                    ?: emptyList()
                val flagged = risks.count {
                    it.status == AppRiskAnalyzer.SUSPICIOUS ||
                        it.status == AppRiskAnalyzer.HIGH_RISK ||
                        it.status == AppRiskAnalyzer.CONFIRMED_THREAT
                }
                val high = risks.count {
                    it.status == AppRiskAnalyzer.HIGH_RISK ||
                        it.status == AppRiskAnalyzer.CONFIRMED_THREAT
                }
                modules += ModuleResult(
                    key = "apps", label = "Installed apps",
                    available = counts != null,
                    checkedCount = counts?.first ?: 0,
                    warnings = flagged - high, highRisk = high,
                    summary = when {
                        counts == null -> "Package visibility restricted by Android"
                        flagged == 0 -> "${counts.first} apps checked — no risk flags"
                        else -> "${counts.first} apps checked — $flagged flagged for review"
                    },
                    route = "protection"
                )
            }

            // ---- Module: App permissions --------------------------------------
            onPhase(PHASES[1])
            runCatching {
                val posture = EventRepository.currentPrivacyPosture(context)
                modules += ModuleResult(
                    key = "permissions", label = "App permissions",
                    available = true,
                    checkedCount = AppScanCache.counts?.first ?: 0,
                    warnings = posture.appsOverLimit, highRisk = 0,
                    summary = when {
                        posture.appsOverLimit == 0 ->
                            "No app exceeds the sensitive-permission threshold"
                        else -> "${posture.appsOverLimit} app(s) hold many sensitive permissions"
                    },
                    route = "privacy"
                )
            }

            // ---- Module: Security configuration -------------------------------
            onPhase(PHASES[2])
            runCatching {
                val device = SecurityScoreEngine.deviceSecuritySnapshot(context)
                val issues = buildList {
                    if (!device.screenLockEnabled) add("no screen lock")
                    if (!device.encryptionEnabled) add("encryption unverified")
                    if (!device.playProtectEnabled) add("Play Protect unverified")
                }
                modules += ModuleResult(
                    key = "config", label = "Security configuration",
                    available = true,
                    checkedCount = 4,
                    warnings = issues.size, highRisk = 0,
                    summary = if (issues.isEmpty()) "Screen lock + encryption look sound"
                              else issues.joinToString(),
                    route = "settings"
                )
            }

            // ---- Module: Network indicators (§2F — supported signals only) ----
            onPhase(PHASES[3])
            runCatching {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as? android.net.ConnectivityManager
                val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
                val vpn = caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true
                val metered = caps?.hasCapability(
                    android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == true
                val online = caps != null && caps.hasCapability(
                    android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                val networkEvents = recentEvents.count { it.category == "NETWORK" }
                val netRisk = recentEvents.count { it.category == "NETWORK" && it.riskScore >= 40 }
                modules += ModuleResult(
                    key = "network", label = "Network indicators",
                    available = caps != null,
                    checkedCount = 1 + networkEvents,
                    warnings = netRisk, highRisk = 0,
                    summary = when {
                        caps == null -> "Active network unavailable to inspect"
                        vpn -> "VPN active — encrypted tunnel in use" +
                            (if (netRisk > 0) "; $netRisk network event(s) flagged" else "")
                        online -> "Wi-Fi/Mobile network active" +
                            (if (!metered) "" else "") +
                            (if (netRisk > 0) "; $netRisk network event(s) flagged" else "")
                        else -> "No active network connection"
                    },
                    route = "network"
                )
            }

            // ---- Modules: URL / QR / message / file verdicts (§2C/§2D/§2E/§2B)
            // These read CyberShield's OWN scan history — real results produced
            // by the real scanners. The engine never fabricates new verdicts.
            onPhase(PHASES[4])
            runCatching {
                val urlEvents = recentEvents.filter { it.category == "URL" }
                val qrEvents = recentEvents.filter { it.category == "QR" }
                modules += ModuleResult(
                    key = "urls", label = "URL threats",
                    available = true,
                    checkedCount = urlEvents.size,
                    warnings = urlEvents.count { it.riskScore >= 30 && it.riskScore < 60 },
                    highRisk = urlEvents.count { it.riskScore >= 60 },
                    summary = when {
                        urlEvents.isEmpty() -> "No URLs scanned in the last 24h — run the Link Scanner"
                        else -> "${urlEvents.size} URL scan(s) on record — " +
                            urlEvents.count { it.riskScore >= 30 } + " suspicious+"
                    },
                    route = "scan"
                )
                modules += ModuleResult(
                    key = "qr", label = "QR security",
                    available = true,
                    checkedCount = qrEvents.size,
                    warnings = qrEvents.count { it.riskScore >= 30 && it.riskScore < 60 },
                    highRisk = qrEvents.count { it.riskScore >= 60 },
                    summary = when {
                        qrEvents.isEmpty() -> "No QR codes analyzed in the last 24h"
                        else -> "${qrEvents.size} QR scan(s) on record — " +
                            qrEvents.count { it.riskScore >= 30 } + " risky"
                    },
                    route = "scan"
                )
            }

            onPhase(PHASES[5])
            runCatching {
                val msgEvents = recentEvents.filter { it.category == "MESSAGE" }
                modules += ModuleResult(
                    key = "messages", label = "Scam message signals",
                    available = true,
                    checkedCount = msgEvents.size,
                    warnings = msgEvents.count { it.riskScore >= 30 && it.riskScore < 60 },
                    highRisk = msgEvents.count { it.riskScore >= 60 },
                    summary = when {
                        msgEvents.isEmpty() -> "No messages analyzed in the last 24h — scan one in Scanner"
                        else -> "${msgEvents.size} message scan(s) on record — " +
                            msgEvents.count { it.riskScore >= 30 } + " suspicious+"
                    },
                    route = "scan"
                )
                val fileEvents = recentEvents.filter { it.category == "FILE" || it.category == "APK" }
                modules += ModuleResult(
                    key = "files", label = "User-scanned files & APKs",
                    available = true,
                    checkedCount = fileEvents.size,
                    warnings = fileEvents.count { it.riskScore >= 30 && it.riskScore < 60 },
                    highRisk = fileEvents.count { it.riskScore >= 60 },
                    summary = when {
                        fileEvents.isEmpty() -> "No user-selected files/APKs analyzed yet"
                        else -> "${fileEvents.size} file/APK scan(s) on record — " +
                            fileEvents.count { it.riskScore >= 30 } + " risky"
                    },
                    route = "scan"
                )
            }

            // ---- Threat correlation (§3): transparent rules, real evidence ----
            onPhase(PHASES[6])
            val correlations = correlate(recentEvents)

            // ---- Security score: deterministic engine ONLY (§4) ----------------
            onPhase(PHASES[7])
            var score: Int? = null
            var band: String? = null
            var deltas: List<String> = emptyList()
            runCatching {
                val result = SecurityScoreEngine.computeCurrent(context)
                score = result.score
                band = result.band
                deltas = result.factors.map { f ->
                    if (f.deduction > 0) "- ${f.detail.replaceFirstChar { it.uppercase() }}"
                    else "+ ${f.detail.replaceFirstChar { it.uppercase() }}"
                }
            }

            val totalWarnings = modules.sumOf { it.warnings }
            val totalHigh = modules.sumOf { it.highRisk }
            val totalItems = modules.sumOf { it.checkedCount }

            // ---- Actions required (§6): one honest remediation per finding ----
            val actions = buildList {
                modules.filter { it.highRisk > 0 }.forEach {
                    add("Review ${it.highRisk} high-risk finding(s) — ${it.label}")
                }
                modules.filter { it.warnings > 0 && it.highRisk == 0 }.forEach {
                    add("Review ${it.warnings} warning(s) — ${it.label}")
                }
                correlations.filter { it.severity == "HIGH" }.forEach {
                    add("Investigate correlated pattern: ${it.title}")
                }
            }

            // ---- Scan history snapshot (§8): local Room, diffable -------------
            onPhase(PHASES[8])
            runCatching {
                WhatChangedStore.record(
                    context = context,
                    trigger = "TotalScan",
                    appsChecked = modules.firstOrNull { it.key == "apps" }?.checkedCount ?: 0,
                    threatsFound = totalHigh,
                    privacyChanges = modules.firstOrNull { it.key == "permissions" }?.warnings ?: 0,
                    networkEvents = recentEvents.count { it.category == "NETWORK" },
                    score = score,
                    userPackages = userPackages
                )
                // A SCORE event puts the Total Scan on the Security Timeline
                // (spec §8) with its real score — visible in history forever.
                if (score != null) {
                    repo.recordMonitor(
                        category = "SCORE",
                        classification = when {
                            totalHigh > 0 -> "RISKY"
                            totalWarnings > 0 -> "SUSPICIOUS"
                            else -> "SAFE"
                        },
                        riskScore = (100 - (score ?: 0)).coerceIn(0, 100),
                        indicators = deltas.take(6),
                        summary = "Device Total Scan — $score/100 (${band ?: "?"}) " +
                            "in ${(System.currentTimeMillis() - started) / 1000}s",
                        subject = "TOTAL_SCAN"
                    )
                }
            }

            // §9 notification: only for real high-risk findings, gated by the
            // user's notification prefs inside NotificationHelper.
            if (totalHigh > 0) {
                runCatching {
                    com.cybershieldai.utils.NotificationHelper.notifyThreat(
                        context,
                        title = "🛡 CyberShield AI",
                        body = "⚠ Security issue detected — $totalHigh high-risk indicator(s) " +
                            "require your attention. Open Total Scan details.",
                        enabled = true,
                        severity = "HIGH",
                        channel = com.cybershieldai.utils.NotificationHelper.CHANNEL_HIGH_RISK,
                        deepLinkScreen = "alerts"
                    )
                }
            }

            TotalResult(
                modules = modules.toList(),
                correlations = correlations,
                score = score,
                scoreBand = band,
                scoreDeltas = deltas,
                actionsRequired = actions.distinct().take(6),
                durationMs = System.currentTimeMillis() - started,
                itemsChecked = totalItems,
                warnings = totalWarnings,
                highRisk = totalHigh
            )
        }

    /**
     * Transparent correlation rules (spec §3): each case names the rule and
     * lists the EXACT evidence. Signals are combined only when they genuinely
     * reinforce each other — never assumed to be an attack.
     */
    private fun correlate(events: List<SecurityEventEntity>): List<CorrelationCase> {
        val cases = mutableListOf<CorrelationCase>()
        val riskyUrls = events.filter { it.category == "URL" && it.riskScore >= 40 }
        val riskyMsgs = events.filter { (it.category == "MESSAGE") && it.riskScore >= 40 }
        val riskyFiles = events.filter {
            (it.category == "FILE" || it.category == "APK") && it.riskScore >= 40
        }

        // Rule 1: suspicious messages + risky links in the same window.
        if (riskyMsgs.isNotEmpty() && riskyUrls.isNotEmpty()) {
            cases += CorrelationCase(
                title = "Suspicious messages linked to risky URLs",
                severity = "HIGH",
                evidence = (riskyMsgs.take(2).map { "Message: ${it.summary}" } +
                    riskyUrls.take(2).map { "URL: ${it.summary}" }),
                route = "alerts"
            )
        }
        // Rule 2: risky file/APK together with risky link traffic.
        if (riskyFiles.isNotEmpty() && (riskyUrls.isNotEmpty() || riskyMsgs.isNotEmpty())) {
            cases += CorrelationCase(
                title = "Risky file scan combined with risky link activity",
                severity = "MEDIUM",
                evidence = (riskyFiles.take(2).map { "File: ${it.summary}" } +
                    (riskyUrls + riskyMsgs).take(2).map { "Link/Msg: ${it.summary}" }),
                route = "incidents"
            )
        }
        return cases
    }
}
