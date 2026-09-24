package com.cybershieldai.data.repository

import android.content.Context
import com.cybershieldai.data.local.DailyStatsEntity
import com.cybershieldai.data.local.DatabaseProvider
import com.cybershieldai.data.local.SecurityEventEntity
import com.cybershieldai.engine.LocalRiskEngine
import com.cybershieldai.engine.LocalThreatCorrelator
import com.cybershieldai.engine.SecurityScoreEngine
import com.cybershieldai.utils.ApkAnalyzer
import com.cybershieldai.utils.OfflineAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Analysis outcome shared by all scan paths (local-first; backend optional). */
data class AnalysisOutcome(
    val category: String,
    val classification: String,
    val severity: String,
    val riskScore: Int,
    val confidence: Double,
    val summary: String,
    val indicators: List<String>,
    val methods: List<String>,
    val recommendation: String,
    val eventId: Long? = null
)

/**
 * Single write-path for every security event: local detection → local risk
 * engine → local correlation → Room persistence → (optional) backend mirror.
 * Raw content is never persisted — only labels, hosts and scores.
 */
class EventRepository(private val context: Context) {

    private val dao = DatabaseProvider.get(context).securityEventDao()
    private val statsDao = DatabaseProvider.get(context).dailyStatsDao()

    private fun methodLabel(backendUsed: Boolean) =
        if (backendUsed) listOf("Rules", "ML (backend)") else listOf("Rules", "Offline Rules")

    suspend fun recordManual(
        category: String, classification: String, riskScore: Int,
        indicators: List<String>, summary: String,
        backendUsed: Boolean = false, recommendation: String = ""
    ): AnalysisOutcome {
        val correlation = LocalThreatCorrelator.assess(dao.recentHighRisk(10), riskScore)
        val finalRisk = LocalRiskEngine.combine(riskScore, correlation.boost, indicators.size)
        val sev = LocalRiskEngine.severityFor(finalRisk)
        val conf = LocalRiskEngine.confidenceFor(indicators.size, backendUsed)
        val classification = if (sev == "SAFE" && classification == "SUSPICIOUS") "SUSPICIOUS" else classification

        val entity = SecurityEventEntity(
            timestamp = System.currentTimeMillis(),
            category = category,
            classification = classification,
            severity = sev,
            riskScore = finalRisk,
            confidence = conf,
            summary = summary.take(140),
            indicatorsJson = toJson(indicators),
            methodsJson = toJson(methodLabel(backendUsed)),
            source = "Manual",
            status = "New"
        )
        val id = dao.insert(entity)
        bumpStats(category, sev)
        return AnalysisOutcome(
            category, classification, sev, finalRisk, conf, summary,
            indicators, methodLabel(backendUsed),
            recommendation.ifEmpty { LocalRiskEngine.recommendationFor(category, sev) },
            eventId = id
        )
    }

    suspend fun recordMonitor(
        category: String, classification: String, riskScore: Int,
        indicators: List<String>, summary: String,
        subject: String = ""
    ): AnalysisOutcome {
        val correlation = LocalThreatCorrelator.assess(dao.recentHighRisk(10), riskScore)
        val finalRisk = LocalRiskEngine.combine(riskScore, correlation.boost, indicators.size)
        val sev = LocalRiskEngine.severityFor(finalRisk)
        val conf = LocalRiskEngine.confidenceFor(indicators.size, backendUsed = false)

        val entity = SecurityEventEntity(
            timestamp = System.currentTimeMillis(),
            category = category,
            classification = classification,
            severity = sev,
            riskScore = finalRisk,
            confidence = conf,
            summary = summary.take(140),
            indicatorsJson = toJson(indicators),
            methodsJson = toJson(listOf("Rules", "Correlation")),
            source = "Monitor",
            status = "New",
            subject = subject
        )
        val id = dao.insert(entity)
        bumpStats(category, sev)
        return AnalysisOutcome(
            category, classification, sev, finalRisk, conf, summary,
            indicators, listOf("Rules", "Correlation"),
            LocalRiskEngine.recommendationFor(category, sev), eventId = id
        )
    }

    /** Alert lifecycle (spec §18): New → Reviewed → Resolved. */
    suspend fun setEventStatus(id: Long, status: String) = withContext(Dispatchers.IO) {
        dao.setStatus(id, status)
    }

    suspend fun deleteEvent(id: Long) = withContext(Dispatchers.IO) {
        dao.deleteById(id)
    }

    private suspend fun bumpStats(category: String, severity: String) {
        try {
            val day = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())
            val existing = statsDao.byDay(day) ?: DailyStatsEntity(day = day)
            val isThreat = severity != "SAFE" && severity != "LOW"
            statsDao.upsert(
                existing.copy(
                    scans = existing.scans + 1,
                    threats = existing.threats + if (isThreat) 1 else 0,
                    highRisk = existing.highRisk + if (severity == "HIGH" || severity == "CRITICAL") 1 else 0,
                    urls = existing.urls + if (category == "URL") 1 else 0,
                    messages = existing.messages + if (category == "MESSAGE") 1 else 0,
                    files = existing.files + if (category == "FILE" || category == "APK") 1 else 0,
                    apps = existing.apps + if (category == "APP") 1 else 0
                )
            )
        } catch (_: Exception) {
            // Stats bookkeeping must NEVER break event recording or notifications.
        }
    }

    suspend fun dashboardData(): DashboardData = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val sinceToday = now - 24 * 60 * 60 * 1000L
        val appsCount = countApps()
        DashboardData(
            threatsToday = dao.countSince(sinceToday).let { c ->
                dao.countHighRiskSince(sinceToday) + (c - dao.countCategorySince(sinceToday, "PRIVACY"))
            },
            highRiskToday = dao.countHighRiskSince(sinceToday),
            urlsChecked = dao.countCategorySince(sinceToday, "URL"),
            messagesAnalyzed = dao.countCategorySince(sinceToday, "MESSAGE"),
            filesChecked = dao.countCategorySince(sinceToday, "FILE") + dao.countCategorySince(sinceToday, "APK"),
            appsAnalyzed = appsCount,
            totalEvents = dao.count(),
            byCategory = dao.countByCategory().map { it.category to it.cnt },
            bySeverity = dao.countBySeverity().map { it.severity to it.cnt },
            recent = dao.recent(30),
            lastEventAt = dao.recent(1).firstOrNull()?.timestamp
        )
    }

    private suspend fun countApps(): Int {
        // Count of apps analyzed comes from persisted APP events; honest local figure.
        val day = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())
        val today = statsDao.byDay(day)
        return today?.apps ?: dao.countCategorySince(0L, "APP")
    }

    suspend fun events(
        severity: String? = null, category: String? = null, limit: Int = 200
    ): List<SecurityEventEntity> = withContext(Dispatchers.IO) {
        val list = if (severity != null && category != null) {
            dao.recent(500).filter { it.severity == severity && it.category == category }
        } else if (severity != null) {
            dao.recent(500).filter { it.severity == severity }
        } else if (category != null) {
            dao.recent(500).filter { it.category == category }
        } else dao.recent(limit)
        list.take(limit)
    }

    suspend fun clearAll() = withContext(Dispatchers.IO) {
        dao.clearAll()
    }

    /** One stored event by Room id (local threat-detail view). */
    suspend fun eventById(id: Long): SecurityEventEntity? =
        withContext(Dispatchers.IO) { dao.byId(id) }

    suspend fun applyRetention(retainDays: Int) = withContext(Dispatchers.IO) {
        if (retainDays > 0) {
            dao.deleteOlderThan(System.currentTimeMillis() - retainDays * 24 * 60 * 60 * 1000L)
        }
    }

    private fun toJson(list: List<String>): String {
        val arr = JSONArray()
        list.forEach { arr.put(it) }
        return arr.toString()
    }

    companion object {
        fun fromJsonList(json: String): List<String> {
            val out = mutableListOf<String>()
            try {
                val arr = JSONArray(json)
                for (i in 0 until arr.length()) out.add(arr.optString(i))
            } catch (_: Exception) { }
            return out
        }

        fun analyzeMessageLocal(text: String) = OfflineAnalyzer.analyzeMessage(text)
        fun analyzeUrlLocal(url: String) = OfflineAnalyzer.analyzeUrl(url)
        fun analyzeFileLocal(name: String, size: Int) = OfflineAnalyzer.analyzeFile(name, size)
        fun analyzeApkLocal(name: String, bytes: ByteArray) = ApkAnalyzer.analyze(name, bytes)

        /**
         * Deterministic app-risk inputs for the security score engine.
         * Uses the offline analyzer (PackageManager data only) — no network,
         * no backend requirement. Empty when the platform hides packages.
         */
        fun currentAppRisks(context: android.content.Context): List<SecurityScoreEngine.AppRisk> {
            val apps = com.cybershieldai.utils.AppScanner.collectInstalledApps(context) ?: return emptyList()
            return com.cybershieldai.utils.AppRiskAnalyzer.analyzeAll(context, apps)
                .filter { it.status == com.cybershieldai.utils.AppRiskAnalyzer.SUSPICIOUS ||
                          it.status == com.cybershieldai.utils.AppRiskAnalyzer.HIGH_RISK ||
                          it.status == com.cybershieldai.utils.AppRiskAnalyzer.CONFIRMED_THREAT }
                .sortedByDescending { it.overallScore }
                .take(6)
                .map {
                    com.cybershieldai.engine.SecurityScoreEngine.AppRisk(
                        it.app.packageName, it.appName, it.overallScore)
                }
        }

        /** Aggregated sensitive-permission posture for the score engine. */
        fun currentPrivacyPosture(context: android.content.Context): SecurityScoreEngine.PrivacyPosture {
            val pm = context.packageManager
            var overLimit = 0
            try {
                val pkgs = pm.getInstalledPackages(
                    android.content.pm.PackageManager.PackageInfoFlags.of(
                        android.content.pm.PackageManager.GET_PERMISSIONS.toLong()))
                for (p in pkgs) {
                    val requested = p.requestedPermissions ?: continue
                    val sensitive = requested.count {
                        it in com.cybershieldai.utils.AppRiskAnalyzer.SENSITIVE
                    }
                    if (sensitive >= 4) overLimit++
                }
            } catch (_: Exception) {
                // package visibility restricted — count only what we can see
            }
            val accessibility = try {
                android.provider.Settings.Secure.getString(
                    context.contentResolver,
                    android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
                ?.split(":")?.count { it.isNotBlank() } ?: 0
            } catch (_: Exception) { 0 }
            val keyguard = context.getSystemService(android.content.Context.KEYGUARD_SERVICE)
                as? android.app.KeyguardManager
            return SecurityScoreEngine.PrivacyPosture(
                appsOverLimit = overLimit,
                accessibilityServices = accessibility,
                screenLockEnabled = keyguard?.isKeyguardSecure == true
            )
        }
    }
}

data class DashboardData(
    val threatsToday: Int,
    val highRiskToday: Int,
    val urlsChecked: Int,
    val messagesAnalyzed: Int,
    val filesChecked: Int,
    val appsAnalyzed: Int,
    val totalEvents: Int,
    val byCategory: List<Pair<String, Int>>,
    val bySeverity: List<Pair<String, Int>>,
    val recent: List<SecurityEventEntity>,
    val lastEventAt: Long?
)
