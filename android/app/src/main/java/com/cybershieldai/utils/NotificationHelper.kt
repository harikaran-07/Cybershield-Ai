package com.cybershieldai.utils

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.cybershieldai.MainActivity
import com.cybershieldai.R
import com.cybershieldai.data.local.NotificationPrefs
import com.cybershieldai.data.local.SettingsStore

/**
 * Real-time security notifications (spec §11/§12).
 *
 * Five Android notification channels map 1:1 to the product spec. Delivery is
 * gated by, in order:
 *   1. Android 13+ POST_NOTIFICATIONS runtime permission,
 *   2. the user's master notifications switch,
 *   3. the user's per-category switches,
 *   4. the user's minimum severity threshold,
 *   5. quiet hours (with a pocket/darkness sensor override for CRITICAL),
 *   6. a frequency limiter so the user is never spammed.
 */
object NotificationHelper {

    const val CHANNEL_CRITICAL = "critical_security"
    const val CHANNEL_HIGH_RISK = "high_risk"
    const val CHANNEL_PRIVACY = "privacy"
    const val CHANNEL_SCAM = "scam_phishing"
    const val CHANNEL_UPDATES = "security_updates"

    private const val MAX_PER_HOUR = 6

    /** Deep-link target screens. */
    const val SCREEN_ALERTS = "alerts"
    const val SCREEN_INCIDENTS = "incidents"
    const val SCREEN_PRIVACY = "privacy"
    const val SCREEN_APPS = "apps"
    const val SCREEN_THREAT = "threat"
    const val SCREEN_REPORT = "report"

    fun ensureChannels(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        fun channel(id: String, name: String, importance: Int, desc: String) =
            NotificationChannel(id, name, importance).apply { this.description = desc }
        manager.createNotificationChannel(channel(
            CHANNEL_CRITICAL, "Critical Security", NotificationManager.IMPORTANCE_HIGH,
            "Immediate threats needing urgent review"))
        manager.createNotificationChannel(channel(
            CHANNEL_HIGH_RISK, "High Risk", NotificationManager.IMPORTANCE_HIGH,
            "High-risk security events"))
        manager.createNotificationChannel(channel(
            CHANNEL_PRIVACY, "Privacy", NotificationManager.IMPORTANCE_DEFAULT,
            "Sensitive permission and privacy changes"))
        manager.createNotificationChannel(channel(
            CHANNEL_SCAM, "Scam & Phishing", NotificationManager.IMPORTANCE_DEFAULT,
            "Potential scam and phishing detections"))
        manager.createNotificationChannel(channel(
            CHANNEL_UPDATES, "Security Updates", NotificationManager.IMPORTANCE_LOW,
            "Score changes and periodic security summaries"))
    }

    /** Convenience for callers that only need channel creation. */
    fun ensureChannel(context: Context) = ensureChannels(context)

    data class Alert(
        val channel: String,
        val severity: String,          // SAFE | LOW | MEDIUM | HIGH | CRITICAL
        val title: String,
        val body: String,
        val deepLinkScreen: String = SCREEN_ALERTS,
        val actions: List<Pair<String, String>> = emptyList(), // label to screen
        val critical: Boolean = false,
        /** TRUE only for notifications the user explicitly requested (e.g. the
         *  diagnostics test) — skips user pref gates but NEVER the Android
         *  POST_NOTIFICATIONS permission check. */
        val forceDeliver: Boolean = false
    )

    /** Shared PocketManager-style sensor check: dark + face-down suggests pocket. */
    private class PocketSensorListener(context: Context) : SensorEventListener {
        private val manager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        private val light = manager?.getDefaultSensor(Sensor.TYPE_LIGHT)
        private val proximity = manager?.getDefaultSensor(Sensor.TYPE_PROXIMITY)
        @Volatile var dark: Boolean = true
            private set
        @Volatile var close: Boolean = false
            private set
        private val maxProximity = proximity?.maximumRange ?: 5f

        fun start() {
            val listener = this
            light?.let { manager?.registerListener(listener, it, SensorManager.SENSOR_DELAY_NORMAL) }
            proximity?.let { manager?.registerListener(listener, it, SensorManager.SENSOR_DELAY_NORMAL) }
        }
        fun stop() { manager?.unregisterListener(this) }
        override fun onSensorChanged(event: SensorEvent) {
            when (event.sensor.type) {
                Sensor.TYPE_LIGHT -> dark = event.values.firstOrNull() ?: 0f < 10f
                Sensor.TYPE_PROXIMITY -> close = (event.values.firstOrNull() ?: 0f) < maxProximity * 0.5f
            }
        }
        override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) { }
    }

    private var pocketListener: PocketSensorListener? = null

    fun inQuietHours(nowMillis: Long = System.currentTimeMillis(), startHour: Int, endHour: Int): Boolean {
        val cal = java.util.Calendar.getInstance().apply { timeInMillis = nowMillis }
        val hour = cal.get(java.util.Calendar.HOUR_OF_DAY)
        return if (startHour == endHour) false
        else if (startHour < endHour) hour in startHour until endHour
        else hour >= startHour || hour < endHour
    }

    /**
     * Full delivery pipeline. Returns false when any gate blocked the alert.
     * Gating order documented in the class KDoc.
     */
    fun notifyAlert(context: Context, alert: Alert): Boolean {
        val stored = kotlinx.coroutines.runBlocking {
            SettingsStore(context).notificationPrefsOnce()
        }
        return deliver(context, alert, stored)
    }

    /** Diagnostics: why would delivery be blocked right now? (spec §7) */
    fun deliveryBlockReason(context: Context): String? {
        if (!notificationsAllowed(context))
            return "POST_NOTIFICATIONS permission not granted"
        val prefs = try {
            kotlinx.coroutines.runBlocking { SettingsStore(context).notificationPrefsOnce() }
        } catch (_: Exception) { return null }
        return when {
            !prefs.enabled -> "Master notifications switch is OFF"
            prefs.quietHoursEnabled && inQuietHours(
                startHour = prefs.quietStartHour, endHour = prefs.quietEndHour) ->
                "Quiet hours active (critical alerts still break through)"
            else -> null
        }
    }

    private fun deliver(context: Context, alert: Alert, prefs: NotificationPrefs): Boolean {
        // User-requested notifications (diagnostics test) bypass pref gates —
        // the Android runtime permission check below ALWAYS applies.
        if (!alert.forceDeliver) {
            if (!prefs.enabled) return false
            if (!prefs.categoryEnabled(alert.channel)) return false

            // Severity threshold: CRITICAL and the SCAN channel bypass it (scan
            // summaries must always deliver); all other channels require severity
            // >= the user's threshold.
            val sevRank = severityRank(alert.severity)
            val minRank = severityRank(prefs.minSeverity)
            if (alert.channel != CHANNEL_CRITICAL &&
                alert.channel != CyberShieldNotificationManager.CH_SCAN &&
                sevRank < minRank) return false
        }

        if (!alert.forceDeliver &&
            prefs.quietHoursEnabled && inQuietHours(startHour = prefs.quietStartHour, endHour = prefs.quietEndHour)) {
            // Only truly critical alerts break through quiet hours, and only when
            // the device is NOT pocketed (dark + covered) — never wake the user for a buzz in a pocket.
            val pocketed = pocketListener?.let { it.dark && it.close } ?: false
            if (!alert.critical || pocketed) return false
        }

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) return false // Never nag; user controls notifications in Android Settings

        // Rate limiting applies to general channels.
        if (!alert.forceDeliver && !rateLimitAllows(context)) return false

        ensureChannels(context)
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("screen", alert.deepLinkScreen)
        }
        val pending = PendingIntent.getActivity(
            context, alert.deepLinkScreen.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(context, alert.channel)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(alert.title)
            .setContentText(alert.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(alert.body))
            .setPriority(if (alert.critical) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pending)

        // Up to three action buttons (spec: [View Security Details] /
        // [Report Scam] — SECURITY actions only, never call controls).
        alert.actions.take(3).forEach { (label, screen) ->
            val actionIntent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("screen", screen)
            }
            val actionPending = PendingIntent.getActivity(
                context, (screen.hashCode() + label.hashCode()), actionIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(0, label, actionPending)
        }

        return try {
            NotificationManagerCompat.from(context)
                .notify((alert.channel + alert.body).hashCode(), builder.build())
            CyberShieldNotificationManager.markNotificationPosted()
            CyberShieldNotificationManager.track(
                "NOTIFICATION_POSTED", ok = true, detail = "${alert.channel} · ${alert.severity}")
            true
        } catch (e: SecurityException) {
            CyberShieldNotificationManager.markDeliveryError("POST_NOTIFICATIONS denied (SecurityException)")
            CyberShieldNotificationManager.track(
                "NOTIFICATION_POSTED", ok = false, detail = "POST_NOTIFICATIONS denied (SecurityException)")
            false
        }
    }

    private fun severityRank(s: String): Int = when (s) {
        "CRITICAL" -> 4
        "HIGH" -> 3
        "MEDIUM" -> 2
        "LOW" -> 1
        else -> 0
    }

    private fun rateLimitAllows(context: Context): Boolean {
        val prefs = context.getSharedPreferences("notif_rate", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val hourAgo = now - 60 * 60 * 1000L
        val stamps = prefs.getStringSet("sent", emptySet())!!
            .mapNotNull { it.toLongOrNull() }.filter { it > hourAgo }.toMutableSet()
        if (stamps.size >= MAX_PER_HOUR) return false
        stamps.add(now)
        prefs.edit().putStringSet("sent", stamps.map { it.toString() }.toSet()).apply()
        return true
    }

    /** Register/unregister the pocket sensor (used for quiet-hours override decisions). */
    fun startPocketSensing(context: Context) {
        if (pocketListener == null) {
            pocketListener = PocketSensorListener(context.applicationContext).also { it.start() }
        }
    }

    fun stopPocketSensing() {
        pocketListener?.stop()
        pocketListener = null
    }

    /** Can this app post notifications at all (Android 13+ runtime gate)? */
    fun notificationsAllowed(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 33) return true
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    // -------------------------------------------------------------------------
    // Back-compat simple API used by existing call sites (ScanViewModel, monitor).
    // Applies stored gating rules automatically.
    // -------------------------------------------------------------------------
    fun notifyThreat(context: Context, title: String, body: String, enabled: Boolean,
                     severity: String = "HIGH", channel: String = CHANNEL_HIGH_RISK,
                     deepLinkScreen: String = SCREEN_ALERTS) {
        if (!enabled) return
        val stored = kotlinx.coroutines.runBlocking {
            SettingsStore(context).notificationPrefsOnce()
        }
        deliver(
            context,
            Alert(
                channel = channel, severity = severity, title = title, body = body,
                deepLinkScreen = deepLinkScreen,
                actions = listOf("View" to deepLinkScreen)
            ),
            stored
        )
    }
}
