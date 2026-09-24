package com.cybershieldai.utils

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext

/**
 * Cached app-scan results (spec §33 — performance).
 *
 * PackageManager discovery + per-app risk analysis is expensive (hundreds of
 * packages, permission checks). Screens must read from this cache instead of
 * re-scanning during recomposition. Refresh happens only when:
 *  - the cache is empty, or
 *  - the caller explicitly forces a refresh (SCAN NOW), or
 *  - the cache is older than [TTL_MS] (5 minutes) AND the screen was reopened.
 */
object AppScanCache {

    private const val TTL_MS = 5 * 60 * 1000L

    @Volatile var deviceApps: AppScanner.DeviceApps? = null; private set
    @Volatile var userRisks: List<AppRiskAnalyzer.AppRiskResult> = emptyList(); private set
    @Volatile var systemRisks: List<AppRiskAnalyzer.AppRiskResult> = emptyList(); private set
    @Volatile var cachedAt: Long = 0; private set
    @Volatile var visibilityRestricted: Boolean = false; private set

    /** Bumped after every (re)load so Compose can observe cache changes. */
    private val _revision = MutableStateFlow(0L)
    val revision: StateFlow<Long> = _revision

    val isExpired: Boolean get() = System.currentTimeMillis() - cachedAt > TTL_MS
    val hasData: Boolean get() = deviceApps != null

    /** User-app counts for Home cards: (userCount, flagged, review). */
    val counts: Triple<Int, Int, Int>?
        get() = deviceApps?.let { d ->
            Triple(
                d.userApps.size,
                userRisks.count {
                    it.status == AppRiskAnalyzer.SUSPICIOUS ||
                        it.status == AppRiskAnalyzer.HIGH_RISK ||
                        it.status == AppRiskAnalyzer.CONFIRMED_THREAT
                },
                userRisks.count { it.status == AppRiskAnalyzer.REVIEW }
            )
        }

    /**
     * Load from cache when fresh; otherwise (re)analyze. Force=true re-runs
     * everything (SCAN NOW). Returns true when data is available.
     */
    suspend fun ensureLoaded(context: Context, force: Boolean = false): Boolean =
        withContext(Dispatchers.Default) {
            if (hasData && !force && !isExpired) return@withContext true
            val apps = AppScanner.collectDeviceApps(context)
            if (apps == null) {
                visibilityRestricted = true
                deviceApps = null
                return@withContext false
            }
            visibilityRestricted = false
            deviceApps = apps
            userRisks = AppRiskAnalyzer.analyzeAll(context, apps.userApps)
            systemRisks = AppRiskAnalyzer.analyzeAll(context, apps.systemAndOem)
            cachedAt = System.currentTimeMillis()
            _revision.value = _revision.value + 1
            true
        }
}
