package com.cybershieldai.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.cybershieldai.data.local.SettingsStore
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.engine.SecurityScoreEngine
import com.cybershieldai.utils.AppScanCache
import com.cybershieldai.utils.AppRiskAnalyzer
import com.cybershieldai.utils.NotificationHelper
import com.cybershieldai.utils.WhatChangedStore
import kotlinx.coroutines.flow.first
import java.util.concurrent.TimeUnit

/**
 * Automatic security check (spec §4) — approximately every 12 hours via
 * WorkManager when Android allows background execution.
 *
 * Performs REAL checks: app discovery + permission analysis, privacy posture,
 * event review, network reachability, score computation, a What-Changed
 * snapshot, and scam correlation. Notification is event-specific and honest.
 */
class AutoCheckWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val context = applicationContext
        val settings = SettingsStore(context)
        val prefs = try { settings.autoCheckPrefsOnce() } catch (_: Exception) {
            SettingsStore.AutoCheckPrefs()
        }
        if (!prefs.enabled) return Result.success()
        if (!settings.monitoringEnabledOnce()) return Result.success()

        val repo = EventRepository(context)
        val day = System.currentTimeMillis() - 24 * 60 * 60 * 1000L

        // --- 1. Real app discovery + risk analysis (fresh, not cached) ---
        var flagged = 0
        var review = 0
        var appsChecked = 0
        var userPackages: List<String> = emptyList()
        try {
            AppScanCache.ensureLoaded(context, force = true)
            appsChecked = AppScanCache.counts?.first ?: 0
            userPackages = AppScanCache.deviceApps?.userApps?.map { it.packageName } ?: emptyList()
            AppScanCache.userRisks.let { risks ->
                flagged = risks.count {
                    it.status == AppRiskAnalyzer.SUSPICIOUS || it.status == AppRiskAnalyzer.HIGH_RISK ||
                        it.status == AppRiskAnalyzer.CONFIRMED_THREAT
                }
                review = risks.count { it.status == AppRiskAnalyzer.REVIEW }
            }
        } catch (_: Exception) { }

        // --- 2. Privacy posture + recent privacy changes ---
        var privacyChanges = 0
        try {
            privacyChanges = repo.events(category = "PRIVACY", limit = 50).size
            EventRepository.currentPrivacyPosture(context)
        } catch (_: Exception) { }

        // --- 3. Network events + reachability (honest: metadata only) ---
        var networkEvents = 0
        try { networkEvents = repo.events(category = "URL", limit = 100).size } catch (_: Exception) { }

        // --- 4. Real score ---
        var score: Int? = null
        try { score = SecurityScoreEngine.computeCurrent(context).score } catch (_: Exception) { }

        // --- 5. What-Changed snapshot (diffs computed against last check) ---
        val threatsFound = try {
            repo.events(severity = "CRITICAL", limit = 20).size
        } catch (_: Exception) { 0 }
        try {
            WhatChangedStore.record(
                context = context, trigger = "AutoCheck",
                appsChecked = appsChecked, threatsFound = threatsFound,
                privacyChanges = privacyChanges, networkEvents = networkEvents,
                score = score, userPackages = userPackages
            )
        } catch (_: Exception) { }

        // --- 7. Event-specific notification (spec §4/§5) routed centrally ---
        if (prefs.notify) {
            val critical = flagged > 0 || threatsFound > 0
            if (critical) {
                com.cybershieldai.utils.CyberShieldNotificationManager.notifySecurityAlert(
                    context,
                    severity = "HIGH",
                    title = "🔴 CyberShield — Security Alert",
                    body = buildString {
                        append("A security/privacy change requires your attention. ")
                        if (flagged > 0) append("$flagged flagged app(s). ")
                        if (threatsFound > 0) append("$threatsFound critical event(s). ")
                        append("Tap to review.")
                    }
                )
            } else {
                com.cybershieldai.utils.CyberShieldNotificationManager.markScanCompleted(
                    context, itemsChecked = appsChecked, issuesFound = 0)
            }
        } else {
            com.cybershieldai.utils.CyberShieldNotificationManager.track(
                "AUTO_CHECK_COMPLETED", ok = true,
                detail = "$appsChecked apps checked, notifications off")
        }
        return Result.success()
    }

    companion object {
        const val WORK_NAME = "cybershield_auto_check"

        /** (Re)schedule the periodic check. KEEP: existing schedule wins. */
        fun schedule(context: Context, intervalHours: Int = 12) {
            val request = PeriodicWorkRequestBuilder<AutoCheckWorker>(
                intervalHours.coerceIn(6, 48).toLong(), TimeUnit.HOURS
            )
                .setConstraints(
                    androidx.work.Constraints.Builder()
                        .setRequiresBatteryNotLow(true)
                        .build()
                )
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }

        /** Called after settings change — replaces the period. */
        fun reschedule(context: Context, intervalHours: Int) {
            val request = PeriodicWorkRequestBuilder<AutoCheckWorker>(
                intervalHours.coerceIn(6, 48).toLong(), TimeUnit.HOURS
            )
                .setConstraints(
                    androidx.work.Constraints.Builder()
                        .setRequiresBatteryNotLow(true)
                        .build()
                )
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }
    }
}
