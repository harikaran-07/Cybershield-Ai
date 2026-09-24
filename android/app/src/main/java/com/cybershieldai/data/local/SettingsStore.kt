package com.cybershieldai.data.local

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.cybershieldai.utils.NotificationHelper
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "settings")

/** Notification preferences (spec §12) persisted with DataStore. */
data class NotificationPrefs(
    val enabled: Boolean = true,
    val minSeverity: String = "HIGH",   // MEDIUM | HIGH | CRITICAL
    val quietHoursEnabled: Boolean = false,
    val quietStartHour: Int = 22,       // 0-23 local
    val quietEndHour: Int = 7,
    val minIntervalMinutes: Int = 30,
    val catCritical: Boolean = true,
    val catHighRisk: Boolean = true,
    val catPrivacy: Boolean = true,
    val catScam: Boolean = true,
    val catUpdates: Boolean = true
) {
    fun categoryEnabled(channel: String): Boolean = when (channel) {
        NotificationHelper.CHANNEL_CRITICAL -> catCritical
        NotificationHelper.CHANNEL_HIGH_RISK -> catHighRisk
        NotificationHelper.CHANNEL_PRIVACY -> catPrivacy
        NotificationHelper.CHANNEL_SCAM -> catScam
        NotificationHelper.CHANNEL_UPDATES -> catUpdates
        else -> true
    }
}

/** User settings persisted with DataStore (privacy: local-only). */
class SettingsStore(private val context: Context) {

    private object Keys {
        val NOTIFICATIONS = booleanPreferencesKey("notifications_enabled")
        val AUTO_SCAN_SHARES = booleanPreferencesKey("auto_scan_shared_text")
        val BACKEND_URL = stringPreferencesKey("backend_url")
        val STORE_HISTORY = booleanPreferencesKey("store_history")
        // Monitoring (spec §18) — user-visible ON/OFF for all background behavior
        val MONITORING_ENABLED = booleanPreferencesKey("monitoring_enabled")
        // Notification rules (spec §12)
        val MIN_SEVERITY = stringPreferencesKey("notif_min_severity")
        val QUIET_HOURS_ENABLED = booleanPreferencesKey("notif_quiet_enabled")
        val QUIET_START = intPreferencesKey("notif_quiet_start")
        val QUIET_END = intPreferencesKey("notif_quiet_end")
        val MIN_INTERVAL_MIN = intPreferencesKey("notif_min_interval_min")
        val CAT_CRITICAL = booleanPreferencesKey("notif_cat_critical")
        val CAT_HIGH_RISK = booleanPreferencesKey("notif_cat_high")
        val CAT_PRIVACY = booleanPreferencesKey("notif_cat_privacy")
        val CAT_SCAM = booleanPreferencesKey("notif_cat_scam")
        val CAT_UPDATES = booleanPreferencesKey("notif_cat_updates")
        // Automatic 12-hour security check (product spec: auto check ON/OFF + notifications)
        val AUTO_CHECK_ENABLED = booleanPreferencesKey("auto_check_enabled")
        val AUTO_CHECK_HOURS = intPreferencesKey("auto_check_hours")
        val AUTO_CHECK_NOTIFY = booleanPreferencesKey("auto_check_notify")
        // Per-category permission monitoring (App Protection screen toggles).
        // ON = CyberShield watches permission changes in that category.
        val MON_PERM_CAMERA = booleanPreferencesKey("mon_perm_camera")
        val MON_PERM_MICROPHONE = booleanPreferencesKey("mon_perm_microphone")
        val MON_PERM_LOCATION = booleanPreferencesKey("mon_perm_location")
        val MON_PERM_CONTACTS = booleanPreferencesKey("mon_perm_contacts")
        val MON_PERM_SMS = booleanPreferencesKey("mon_perm_sms")
        val MON_PERM_FILES = booleanPreferencesKey("mon_perm_files")
        // Local AI model (spec §20) — install state, reported size, explain toggle
        val AI_MODEL_INSTALLED = booleanPreferencesKey("ai_model_installed")
        val AI_MODEL_SIZE_BYTES = longPreferencesKey("ai_model_size_bytes")
        val AI_EXPLAIN_ENABLED = booleanPreferencesKey("ai_explain_enabled")
        // Crash watchdog: consecutive process deaths during scanner LLM use.
        // Survives process restarts so a native-crashing model can never
        // crash the scanner twice in a row (scanner falls back to rules).
        val SCANNER_LLM_CRASHES = intPreferencesKey("scanner_llm_crashes")
        // UI design concept (UI/UX redesign): which of the five design skins
        // the app renders with. Visual only — no functional impact.
        val UI_CONCEPT = stringPreferencesKey("ui_concept")
    }

    /** Permission categories watchable from the App Protection screen. */
    data class PermWatchPrefs(
        val camera: Boolean = true,
        val microphone: Boolean = true,
        val location: Boolean = true,
        val contacts: Boolean = true,
        val sms: Boolean = true,
        val files: Boolean = true
    ) {
        /** Is the given Android permission string watched? */
        fun watches(permission: String): Boolean = when (permission) {
            android.Manifest.permission.CAMERA, "android.permission-group.CAMERA" -> camera
            android.Manifest.permission.RECORD_AUDIO -> microphone
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.ACCESS_COARSE_LOCATION,
            android.Manifest.permission.ACCESS_BACKGROUND_LOCATION -> location
            android.Manifest.permission.READ_CONTACTS,
            android.Manifest.permission.WRITE_CONTACTS -> contacts
            android.Manifest.permission.RECEIVE_SMS,
            android.Manifest.permission.READ_SMS,
            android.Manifest.permission.SEND_SMS -> sms
            android.Manifest.permission.READ_EXTERNAL_STORAGE,
            android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
            android.Manifest.permission.READ_MEDIA_IMAGES,
            android.Manifest.permission.READ_MEDIA_VIDEO,
            android.Manifest.permission.READ_MEDIA_AUDIO -> files
            else -> false
        }
    }

    val permWatchPrefs: Flow<PermWatchPrefs> = context.dataStore.data.map { p ->
        PermWatchPrefs(
            camera = p[Keys.MON_PERM_CAMERA] ?: true,
            microphone = p[Keys.MON_PERM_MICROPHONE] ?: true,
            location = p[Keys.MON_PERM_LOCATION] ?: true,
            contacts = p[Keys.MON_PERM_CONTACTS] ?: true,
            sms = p[Keys.MON_PERM_SMS] ?: true,
            files = p[Keys.MON_PERM_FILES] ?: true
        )
    }

    suspend fun permWatchPrefsOnce(): PermWatchPrefs =
        permWatchPrefs.firstOrNull() ?: PermWatchPrefs()

    suspend fun setPermWatch(update: (PermWatchPrefs) -> PermWatchPrefs) {
        context.dataStore.edit { p ->
            val current = PermWatchPrefs(
                camera = p[Keys.MON_PERM_CAMERA] ?: true,
                microphone = p[Keys.MON_PERM_MICROPHONE] ?: true,
                location = p[Keys.MON_PERM_LOCATION] ?: true,
                contacts = p[Keys.MON_PERM_CONTACTS] ?: true,
                sms = p[Keys.MON_PERM_SMS] ?: true,
                files = p[Keys.MON_PERM_FILES] ?: true
            )
            val next = update(current)
            p[Keys.MON_PERM_CAMERA] = next.camera
            p[Keys.MON_PERM_MICROPHONE] = next.microphone
            p[Keys.MON_PERM_LOCATION] = next.location
            p[Keys.MON_PERM_CONTACTS] = next.contacts
            p[Keys.MON_PERM_SMS] = next.sms
            p[Keys.MON_PERM_FILES] = next.files
        }
    }

    /** How often the automatic security check runs (hours). */
    data class AutoCheckPrefs(
        val enabled: Boolean = true,
        val intervalHours: Int = 12,
        val notify: Boolean = true
    )

    val notificationsEnabled: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.NOTIFICATIONS] ?: true }
    val autoScanShares: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.AUTO_SCAN_SHARES] ?: true }
    val storeHistory: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.STORE_HISTORY] ?: true }
    val backendUrl: Flow<String> =
        context.dataStore.data.map { it[Keys.BACKEND_URL] ?: "" }

    /** Master monitoring switch: OFF disables package/worker/notification monitoring. */
    val monitoringEnabled: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.MONITORING_ENABLED] ?: true }

    val autoCheckPrefs: Flow<AutoCheckPrefs> = context.dataStore.data.map { p ->
        AutoCheckPrefs(
            enabled = p[Keys.AUTO_CHECK_ENABLED] ?: true,
            intervalHours = p[Keys.AUTO_CHECK_HOURS] ?: 12,
            notify = p[Keys.AUTO_CHECK_NOTIFY] ?: true
        )
    }

    suspend fun autoCheckPrefsOnce(): AutoCheckPrefs =
        autoCheckPrefs.firstOrNull() ?: AutoCheckPrefs()

    suspend fun setAutoCheckEnabled(value: Boolean) =
        context.dataStore.edit { it[Keys.AUTO_CHECK_ENABLED] = value }

    suspend fun setAutoCheckHours(value: Int) =
        context.dataStore.edit { it[Keys.AUTO_CHECK_HOURS] = value.coerceIn(6, 48) }

    suspend fun setAutoCheckNotify(value: Boolean) =
        context.dataStore.edit { it[Keys.AUTO_CHECK_NOTIFY] = value }

    /** One-shot read for synchronous callers (workers, receivers, listener). */
    suspend fun monitoringEnabledOnce(): Boolean = monitoringEnabled.firstOrDefault(true)

    val notificationPrefs: Flow<NotificationPrefs> = context.dataStore.data.map { p ->
        NotificationPrefs(
            enabled = p[Keys.NOTIFICATIONS] ?: true,
            minSeverity = p[Keys.MIN_SEVERITY] ?: "HIGH",
            quietHoursEnabled = p[Keys.QUIET_HOURS_ENABLED] ?: false,
            quietStartHour = p[Keys.QUIET_START] ?: 22,
            quietEndHour = p[Keys.QUIET_END] ?: 7,
            minIntervalMinutes = p[Keys.MIN_INTERVAL_MIN] ?: 30,
            catCritical = p[Keys.CAT_CRITICAL] ?: true,
            catHighRisk = p[Keys.CAT_HIGH_RISK] ?: true,
            catPrivacy = p[Keys.CAT_PRIVACY] ?: true,
            catScam = p[Keys.CAT_SCAM] ?: true,
            catUpdates = p[Keys.CAT_UPDATES] ?: true
        )
    }

    /** One-shot read for synchronous callers (workers, receivers). */
    suspend fun notificationPrefsOnce(): NotificationPrefs = notificationPrefs.firstOrDefault(NotificationPrefs())

    suspend fun setNotificationsEnabled(value: Boolean) =
        context.dataStore.edit { it[Keys.NOTIFICATIONS] = value }

    suspend fun setAutoScanShares(value: Boolean) =
        context.dataStore.edit { it[Keys.AUTO_SCAN_SHARES] = value }

    suspend fun setStoreHistory(value: Boolean) =
        context.dataStore.edit { it[Keys.STORE_HISTORY] = value }

    suspend fun setBackendUrl(value: String) =
        context.dataStore.edit { it[Keys.BACKEND_URL] = value }

    suspend fun setMonitoringEnabled(value: Boolean) =
        context.dataStore.edit { it[Keys.MONITORING_ENABLED] = value }

    suspend fun updateNotificationPrefs(update: (NotificationPrefs) -> NotificationPrefs) {
        context.dataStore.edit { p ->
            val current = NotificationPrefs(
                enabled = p[Keys.NOTIFICATIONS] ?: true,
                minSeverity = p[Keys.MIN_SEVERITY] ?: "HIGH",
                quietHoursEnabled = p[Keys.QUIET_HOURS_ENABLED] ?: false,
                quietStartHour = p[Keys.QUIET_START] ?: 22,
                quietEndHour = p[Keys.QUIET_END] ?: 7,
                minIntervalMinutes = p[Keys.MIN_INTERVAL_MIN] ?: 30,
                catCritical = p[Keys.CAT_CRITICAL] ?: true,
                catHighRisk = p[Keys.CAT_HIGH_RISK] ?: true,
                catPrivacy = p[Keys.CAT_PRIVACY] ?: true,
                catScam = p[Keys.CAT_SCAM] ?: true,
                catUpdates = p[Keys.CAT_UPDATES] ?: true
            )
            val next = update(current)
            p[Keys.NOTIFICATIONS] = next.enabled
            p[Keys.MIN_SEVERITY] = next.minSeverity
            p[Keys.QUIET_HOURS_ENABLED] = next.quietHoursEnabled
            p[Keys.QUIET_START] = next.quietStartHour
            p[Keys.QUIET_END] = next.quietEndHour
            p[Keys.MIN_INTERVAL_MIN] = next.minIntervalMinutes
            p[Keys.CAT_CRITICAL] = next.catCritical
            p[Keys.CAT_HIGH_RISK] = next.catHighRisk
            p[Keys.CAT_PRIVACY] = next.catPrivacy
            p[Keys.CAT_SCAM] = next.catScam
            p[Keys.CAT_UPDATES] = next.catUpdates
        }
    }

    /** Delete all local app data (privacy control). */
    suspend fun clearAll() {
        context.dataStore.edit { it.clear() }
    }

    // ---- Local AI model (spec §20) ----

    val aiModelInstalled: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.AI_MODEL_INSTALLED] ?: false }
    val aiModelSizeBytes: Flow<Long> =
        context.dataStore.data.map { it[Keys.AI_MODEL_SIZE_BYTES] ?: 0L }
    val aiExplainEnabled: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.AI_EXPLAIN_ENABLED] ?: true }

    suspend fun setAiModelInstalled(installed: Boolean) =
        context.dataStore.edit { it[Keys.AI_MODEL_INSTALLED] = installed }

    suspend fun setAiModelSize(sizeBytes: Long) =
        context.dataStore.edit { it[Keys.AI_MODEL_SIZE_BYTES] = sizeBytes }

    suspend fun setAiExplainEnabled(enabled: Boolean) =
        context.dataStore.edit { it[Keys.AI_EXPLAIN_ENABLED] = enabled }

    /** Consecutive native crashes during scanner LLM use (0 = healthy). */
    val scannerLlmCrashes: Flow<Int> =
        context.dataStore.data.map { it[Keys.SCANNER_LLM_CRASHES] ?: 0 }

    suspend fun scannerLlmCrashesOnce(): Int =
        context.dataStore.data.firstOrNull()?.get(Keys.SCANNER_LLM_CRASHES) ?: 0

    suspend fun setScannerLlmCrashes(count: Int) =
        context.dataStore.edit { it[Keys.SCANNER_LLM_CRASHES] = count.coerceAtLeast(0) }

    // ---- UI design concept (visual only) ----

    val uiConcept: Flow<String> =
        context.dataStore.data.map { it[Keys.UI_CONCEPT] ?: "" }

    suspend fun setUiConcept(id: String) =
        context.dataStore.edit { it[Keys.UI_CONCEPT] = id }

    private suspend fun <T> Flow<T>.firstOrDefault(default: T): T =
        firstOrNull() ?: default
}
