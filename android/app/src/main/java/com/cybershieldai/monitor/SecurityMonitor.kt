package com.cybershieldai.monitor

import android.app.Notification
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.cybershieldai.data.local.SettingsStore
import com.cybershieldai.data.repository.EventRepository
import com.cybershieldai.engine.SecurityScoreEngine
import com.cybershieldai.utils.AppRiskAnalyzer
import com.cybershieldai.utils.AppScanner
import com.cybershieldai.utils.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit
import kotlin.math.min

/**
 * Background monitoring (spec §18) — transparent and user-controlled:
 *  - Master switch: Settings → Monitoring (DataStore key `monitoring_enabled`).
 *    When OFF, no receivers are registered and no workers run.
 *  - Package monitor: new-install and update (permission-diff) checks.
 *  - Notification listener: OPT-IN via Android Settings; analyzes notification
 *    text in memory for scam patterns; never stores raw content.
 *  - Workers: hygiene/retention (6h) and security score refresh (1h).
 * Everything here only uses data Android legitimately exposes.
 */
class ShieldNotificationListener : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val extras = sbn.notification?.extras ?: return
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: return
        if (text.length < 15) return
        if (sbn.packageName == packageName) return // never analyze our own alerts

        val appContext = applicationContext
        CoroutineScope(Dispatchers.Default).launch {
            val monitoring = SettingsStore(appContext).monitoringEnabledOnce()
            if (!monitoring) return@launch

            val result = EventRepository.analyzeMessageLocal(text) ?: return@launch
            if (result.riskScore >= 55) {
                val repo = EventRepository(appContext)
                val outcome = repo.recordMonitor(
                    category = "MESSAGE",
                    classification = result.classification,
                    riskScore = result.riskScore,
                    indicators = result.indicators,
                    summary = "Notification flagged (${sbn.packageName.substringAfterLast('.')})"
                )
                if (outcome.severity == "HIGH" || outcome.severity == "CRITICAL") {
                    NotificationHelper.notifyThreat(
                        appContext,
                        title = "🚨 Potential scam message detected",
                        body = "Risk ${outcome.riskScore}/100 — " +
                            (outcome.indicators.firstOrNull() ?: "review recommended"),
                        enabled = true,
                        severity = outcome.severity,
                        channel = NotificationHelper.CHANNEL_SCAM
                    )
                }
            }
        }
    }
}

/** Package monitor: flags new installs and permission CHANGES on app updates. */
class PackageMonitor : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_PACKAGE_ADDED &&
            intent.action != Intent.ACTION_PACKAGE_REPLACED) return
        val pkg = intent.data?.schemeSpecificPart ?: return
        val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)

        val appContext = context.applicationContext
        val pending = goAsync()
        CoroutineScope(Dispatchers.Default).launch {
            try {
                val monitoring = SettingsStore(appContext).monitoringEnabledOnce()
                if (!monitoring) return@launch

                if (replacing) checkPermissionChange(appContext, pkg)
                else checkNewInstall(appContext, pkg)
            } catch (_: Exception) {
                // monitoring is best-effort; never crash the host process
            } finally {
                pending.finish()
            }
        }
    }

    private suspend fun checkNewInstall(context: Context, pkg: String) {
        val perms = AppScanner.permissionsForPackage(context, pkg) ?: return
        val risky = perms.count { it in com.cybershieldai.utils.ApkAnalyzer.dangerousPermissions }
        if (risky == 0) return
        val score = min(100, risky * 15 + 10)
        val repo = EventRepository(context)
        val outcome = repo.recordMonitor(
            category = "APP",
            classification = if (score >= 60) "RISKY" else "SUSPICIOUS",
            riskScore = score,
            indicators = listOf("Newly installed app requests $risky high-risk permission(s)"),
            summary = "New app installed: ${pkg.substringAfterLast('.')}"
        )
        if (outcome.severity == "HIGH" || outcome.severity == "CRITICAL") {
            NotificationHelper.notifyThreat(
                context,
                title = "⚠ New app with high-risk permissions",
                body = "$pkg — sensitive permission granted — review recommended.",
                enabled = true,
                severity = outcome.severity,
                channel = NotificationHelper.CHANNEL_HIGH_RISK,
                deepLinkScreen = NotificationHelper.SCREEN_APPS
            )
        }
    }

    private suspend fun checkPermissionChange(context: Context, pkg: String) {
        val repo = EventRepository(context)
        val now = AppScanner.permissionsForPackage(context, pkg) ?: return
        val dao = com.cybershieldai.data.local.DatabaseProvider.get(context).securityEventDao()
        // Find the most recent APP event for this package to diff against.
        val label = "New app installed: ${pkg.substringAfterLast('.')}"
        val previous = dao.recent(200).firstOrNull {
            it.category == "APP" && (it.summary == label || it.summary.startsWith(pkg))
        }
        val previousPerms = previous?.indicatorsJson
            ?.let { EventRepository.fromJsonList(it) }
            ?.mapNotNull { PermissionDiff.decode(it) }
            ?.toSet()
        // We cannot read historical permission lists unless a prior APP event
        // recorded them (see AppRiskAnalyzer persistence below). When no prior
        // record exists, record the baseline without alerting.
        if (previous == null || previousPerms == null) {
            recordBaseline(context, repo, pkg, now)
            return
        }
        val watch = SettingsStore(context).permWatchPrefsOnce()
        val added = now.filter { it !in previousPerms &&
            it in com.cybershieldai.utils.ApkAnalyzer.dangerousPermissions &&
            watch.watches(it) }
        val removed = previousPerms.filter { it !in now.toSet() && watch.watches(it) }
        if (added.isEmpty() && removed.isEmpty()) return

        val indicators = mutableListOf<String>()
        if (added.isNotEmpty()) {
            indicators += "${added.size} sensitive permission(s) newly granted: " +
                added.take(3).joinToString { it.substringAfterLast('.') }
        }
        if (removed.isNotEmpty()) {
            indicators += "${removed.size} permission(s) revoked"
        }
        val score = min(100, added.size * 25 + 20)
        val outcome = repo.recordMonitor(
            category = "PRIVACY",
            classification = "PERMISSION_CHANGE",
            riskScore = score,
            indicators = indicators,
            summary = "Permissions changed: ${pkg.substringAfterLast('.')}"
        )
        // Record the new baseline so the next diff works (indicator encoding).
        recordBaseline(context, repo, pkg, now)
        NotificationHelper.notifyThreat(
            context,
            title = "🔐 Privacy permission changed",
            body = "${pkg.substringAfterLast('.')}: ${indicators.firstOrNull()}",
            enabled = true,
            severity = outcome.severity,
            channel = NotificationHelper.CHANNEL_PRIVACY,
            deepLinkScreen = NotificationHelper.SCREEN_PRIVACY
        )
    }

    /** Persist the current permission set as the diff baseline (metadata only). */
    private suspend fun recordBaseline(context: Context, repo: EventRepository, pkg: String, perms: List<String>) {
        try {
            repo.recordManual(
                category = "APP",
                classification = "PERMISSION_BASELINE",
                riskScore = 0,
                indicators = perms.map { PermissionDiff.encode(it) },
                summary = "Permission baseline: ${pkg.substringAfterLast('.')}",
                backendUsed = false
            )
        } catch (_: Exception) { }
    }
}

/** Encoder for permission strings stored inside the indicators JSON array. */
object PermissionDiff {
    private const val PREFIX = "perm:"
    fun encode(perm: String) = PREFIX + perm
    fun decode(s: String): String? = if (s.startsWith(PREFIX)) s.removePrefix(PREFIX) else null
}

/** Hourly security score refresh — raises a Security Updates alert on change (spec §11). */
class ScoreCheckWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val context = applicationContext
        if (!SettingsStore(context).monitoringEnabledOnce()) return Result.success()

        val dao = com.cybershieldai.data.local.DatabaseProvider.get(context).securityEventDao()
        val previous = try { dao.lastScoreSnapshot() } catch (_: Exception) { null }
        // (Snapshot is re-computed fresh below; the DAO read is only the prior value.)

        val result = SecurityScoreEngine.computeCurrent(context)

        // Persist snapshot as a local INFO event (also visible in the timeline).
        EventRepository(context).recordManual(
            category = "SCORE",
            classification = "INFO",
            riskScore = 100 - result.score, // convention: stored event shows risk
            indicators = listOf("Score ${result.score}/100 (${result.band})"),
            summary = "Security score: ${result.score}/100 — ${result.band}",
            backendUsed = false
        )

        // Snapshot events store risk = 100 - score (see recordManual above).
        val prevScore = previous?.let { 100 - it.riskScore }
        if (prevScore != null && prevScore != result.score) {
            val dir = if (result.score < prevScore) "dropped" else "improved"
            NotificationHelper.notifyThreat(
                context,
                title = "📊 Security score changed",
                body = "Previous: $prevScore · Current: ${result.score}. " +
                    "The score $dir — open the report for the reasons.",
                enabled = true,
                severity = if (result.score < prevScore) "MEDIUM" else "LOW",
                channel = NotificationHelper.CHANNEL_UPDATES,
                deepLinkScreen = NotificationHelper.SCREEN_INCIDENTS
            )
        }
        return Result.success()
    }

    companion object {
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<ScoreCheckWorker>(1, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "cybershield_score_check",
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork("cybershield_score_check")
        }
    }
}

/** Periodic hygiene: enforce local retention, keep stats tidy. */
class HygieneWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val repo = EventRepository(applicationContext)
        repo.applyRetention(30) // 30-day local retention default
        return Result.success()
    }

    companion object {
        const val WORK_NAME = "cybershield_hygiene"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<HygieneWorker>(6, TimeUnit.HOURS)
                .setConstraints(
                    Constraints.Builder().setRequiresBatteryNotLow(true).build()
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
    }
}

object MonitorController {

    @Volatile private var packageMonitor: PackageMonitor? = null

    /** Apply the stored monitoring switch: registers/unregisters everything. */
    fun start(context: Context) {
        val appContext = context.applicationContext
        val enabled = kotlinx.coroutines.runBlocking {
            try { SettingsStore(appContext).monitoringEnabledOnce() } catch (_: Exception) { true }
        }
        if (enabled) enable(appContext) else disable(appContext)
    }

    fun enable(appContext: Context) {
        if (packageMonitor == null) {
            val monitor = PackageMonitor()
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }
            ContextCompat.registerReceiver(
                appContext, monitor, filter, ContextCompat.RECEIVER_NOT_EXPORTED
            )
            packageMonitor = monitor
        }
        HygieneWorker.schedule(appContext)
        ScoreCheckWorker.schedule(appContext)
        NotificationHelper.startPocketSensing(appContext)
    }

    fun disable(appContext: Context) {
        packageMonitor?.let { appContext.unregisterReceiver(it) }
        packageMonitor = null
        HygieneWorker.cancel(appContext)
        ScoreCheckWorker.cancel(appContext)
        NotificationHelper.stopPocketSensing()
    }
}
