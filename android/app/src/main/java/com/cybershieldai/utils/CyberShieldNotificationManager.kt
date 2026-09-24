package com.cybershieldai.utils

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import com.cybershieldai.MainActivity
import com.cybershieldai.data.local.SettingsStore

/**
 * CyberShieldNotificationManager (spec §6) — the ONE path every security
 * alert takes to the Android notification bar.
 *
 * Three user-visible channels:
 *   CYBERSHIELD_CRITICAL → "CyberShield Critical"   (scam-risk, critical)
 *   CYBERSHIELD_SECURITY → "CyberShield Security"   (warnings needing review)
 *   CYBERSHIELD_SCAN     → "CyberShield Scan"       (scan/auto-check results)
 *
 * Routing is by detection severity; content is generated from ACTUAL results
 * by the caller. Every attempt (posted or blocked) is tracked so the
 * Notification Diagnostics screen shows the REAL state of the pipeline.
 */
object CyberShieldNotificationManager {

    const val CH_CRITICAL = "cybershield_critical"
    const val CH_SECURITY = "cybershield_security"
    const val CH_SCAN = "cybershield_scan"

    /** Last 20 pipeline events, newest first (in-memory diagnostics trail). */
    data class TrackEntry(val time: Long, val stage: String, val ok: Boolean, val detail: String)
    private val trail = ArrayDeque<TrackEntry>()
    private const val TRAIL_MAX = 20

    @Volatile var lastNotificationAt: Long = 0L
        private set
    @Volatile var lastDetectionAt: Long = 0L
        private set
    @Volatile var lastError: String? = null
        private set

    /** Internal: record a successful post (called by NotificationHelper). */
    fun markNotificationPosted() { lastNotificationAt = System.currentTimeMillis() }

    /** Internal: record a delivery failure (called by NotificationHelper). */
    fun markDeliveryError(why: String) { lastError = why }

    fun track(stage: String, ok: Boolean, detail: String = "") {
        synchronized(trail) {
            trail.addFirst(TrackEntry(System.currentTimeMillis(), stage, ok, detail))
            while (trail.size > TRAIL_MAX) trail.removeLast()
        }
    }

    fun markDetection() { lastDetectionAt = System.currentTimeMillis() }

    /** Diagnostics trail snapshot (newest first). */
    fun recentTrail(): List<TrackEntry> = synchronized(trail) { trail.toList() }

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        fun ch(id: String, name: String, importance: Int, desc: String) =
            NotificationChannel(id, name, importance).apply { description = desc }
        manager.createNotificationChannel(ch(
            CH_CRITICAL, "CyberShield Critical", NotificationManager.IMPORTANCE_HIGH,
            "Possible scam indicators and critical security events"))
        manager.createNotificationChannel(ch(
            CH_SECURITY, "CyberShield Security", NotificationManager.IMPORTANCE_DEFAULT,
            "Suspicious activity that needs review"))
        manager.createNotificationChannel(ch(
            CH_SCAN, "CyberShield Scan", NotificationManager.IMPORTANCE_LOW,
            "Security scan and periodic check results"))
    }

    /** Channel state for the diagnostics screen: ENABLED / DISABLED / UNAVAILABLE. */
    fun channelState(context: Context, channelId: String): String {
        if (Build.VERSION.SDK_INT < 26) return "READY"
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return "ERROR"
        return try {
            val ch = nm.getNotificationChannel(channelId) ?: return "READY"
            if (ch.importance == NotificationManager.IMPORTANCE_NONE) "DISABLED" else "ENABLED"
        } catch (e: Exception) { "ERROR: ${e.javaClass.simpleName}" }
    }

    /**
     * Post an alert through the central pipeline. Returns true when the
     * notification actually reached NotificationManager.notify().
     *
     * @param severity detection severity: SAFE | LOW | MEDIUM | HIGH | CRITICAL
     * @param deepLinkScreen in-app screen to open on tap
     */
    fun notifySecurityAlert(
        context: Context,
        severity: String,
        title: String,
        body: String,
        deepLinkScreen: String = NotificationHelper.SCREEN_ALERTS,
        eventId: Long = -1L
    ): Boolean {
        ensureChannels(context)
        val channel = when (severity) {
            "CRITICAL", "HIGH" -> CH_CRITICAL
            "MEDIUM", "LOW" -> CH_SECURITY
            else -> CH_SCAN
        }
        val link = if (eventId > 0) "threat:$eventId" else deepLinkScreen
        track("NOTIFICATION_REQUESTED", ok = true, detail = "$severity → $channel")

        val posted = NotificationHelper.notifyAlert(
            context,
            NotificationHelper.Alert(
                channel = channel,
                severity = severity,
                title = title,
                body = body,
                deepLinkScreen = link
            )
        )
        if (posted) {
            markNotificationPosted()
            track("NOTIFICATION_POSTED", ok = true, detail = title.take(40))
        } else {
            val why = diagnoseBlock(context)
            markDeliveryError(why)
            track("NOTIFICATION_POSTED", ok = false, detail = why)
        }
        return posted
    }

    /** Human-readable reason the last delivery was blocked (diagnostics). */
    fun diagnoseBlock(context: Context): String = when {
        !NotificationHelper.notificationsAllowed(context) ->
            "POST_NOTIFICATIONS permission not granted (Android 13+)"
        else -> {
            val st = try {
                kotlinx.coroutines.runBlocking { SettingsStore(context).notificationPrefsOnce() }
            } catch (_: Exception) { null }
            when {
                st != null && !st.enabled -> "Master notifications switch is OFF in CyberShield"
                else -> "Blocked by user notification rules (severity threshold, quiet hours or rate limit)"
            }
        }
    }

    /**
     * Diagnostics test (spec §7): a REAL notification through the REAL
     * pipeline — explicitly labelled as a test, not a fake detection.
     */
    fun sendTestNotification(context: Context): Boolean {
        ensureChannels(context)
        // forceDeliver: the user explicitly asked for this (spec §7) — the only
        // gate that still applies is Android's POST_NOTIFICATIONS permission.
        val ok = NotificationHelper.notifyAlert(
            context,
            NotificationHelper.Alert(
                channel = CH_SECURITY,
                severity = "LOW",
                title = "CyberShield Test Alert",
                body = "CyberShield notification system is working correctly.",
                deepLinkScreen = NotificationHelper.SCREEN_ALERTS,
                forceDeliver = true
            )
        )
        if (ok) {
            markNotificationPosted()
            track("TEST_NOTIFICATION", ok = true, detail = "posted")
        } else {
            val why = diagnoseBlock(context)
            markDeliveryError(why)
            track("TEST_NOTIFICATION", ok = false, detail = why)
        }
        return ok
    }

    // -- WorkManager/jobs report completion here for the diagnostics screen --
    fun markScanCompleted(context: Context, itemsChecked: Int, issuesFound: Int) {
        markDetection()
        track("SCAN_COMPLETED", ok = true, detail = "$itemsChecked items, $issuesFound issues")
        val prefs = try {
            kotlinx.coroutines.runBlocking { SettingsStore(context).notificationPrefsOnce() }
        } catch (_: Exception) { null }
        // Scan summaries always attempt the SCAN channel (LOW severity bypasses
        // the generic gate for that channel inside NotificationHelper gates).
        NotificationHelper.notifyAlert(
            context,
            NotificationHelper.Alert(
                channel = CH_SCAN,
                severity = "LOW",
                title = "🟢 CyberShield — Scan Complete",
                body = if (issuesFound == 0) "No major security issues detected. $itemsChecked items checked."
                       else "Scan finished: $issuesFound issue(s) found across $itemsChecked items. Review in Alerts.",
                deepLinkScreen = NotificationHelper.SCREEN_ALERTS
            )
        )
    }
}
