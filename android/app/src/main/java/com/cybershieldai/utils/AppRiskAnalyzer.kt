package com.cybershieldai.utils

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.cybershieldai.data.model.AppInfo

/**
 * Offline per-app risk analysis using only PackageManager data that Android
 * legitimately exposes (requested permissions, install source, target SDK).
 *
 * Honesty rules (product spec §6/§7):
 *  - A sensitive permission is an INDICATOR, not proof of malware. A powerful
 *    system component must never be classified as malware.
 *  - Three orthogonal axes: privacy risk, security risk, malware evidence.
 *  - Five overall statuses: SAFE → REVIEW → SUSPICIOUS → HIGH RISK →
 *    CONFIRMED THREAT (the last only with actual detection-system evidence).
 *  - No claim of active camera/microphone use is ever made: Android exposes
 *    no reliable, always-available API for that to third-party apps.
 */
object AppRiskAnalyzer {

    // Overall statuses in escalating order.
    const val SAFE = "SAFE"
    const val REVIEW = "REVIEW"
    const val SUSPICIOUS = "SUSPICIOUS"
    const val HIGH_RISK = "HIGH RISK"
    const val CONFIRMED_THREAT = "CONFIRMED THREAT"

    data class AppRiskResult(
        val app: AppInfo,
        val appName: String,
        val versionName: String?,
        val installSource: String?,          // Play Store / sideload / unknown
        val permissions: List<String>,
        val grantedSensitive: List<String>,  // dangerous permissions actually granted
        val privacyScore: Int,               // 0-100 — how much private data it can touch
        val securityScore: Int,              // 0-100 — abuse-pattern / posture signals
        val malwareEvidence: Int,            // 0-100 — only concrete detection-system evidence
        val overallScore: Int,               // 0-100 — composite for sorting
        val status: String,                  // one of the five bands above
        val findings: List<String>
    )

    // Sensitive permission groups (camera/mic/loc/contacts/SMS/files).
    // Public: reused by the privacy posture collector and the Privacy Center.
    val SENSITIVE = mapOf(
        "android.permission.CAMERA" to "Camera",
        "android.permission.RECORD_AUDIO" to "Microphone",
        "android.permission.ACCESS_FINE_LOCATION" to "Precise location",
        "android.permission.ACCESS_COARSE_LOCATION" to "Approximate location",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Background location",
        "android.permission.READ_CONTACTS" to "Contacts",
        "android.permission.WRITE_CONTACTS" to "Contacts (write)",
        "android.permission.READ_SMS" to "Read SMS",
        "android.permission.RECEIVE_SMS" to "Receive SMS",
        "android.permission.SEND_SMS" to "Send SMS",
        "android.permission.READ_CALL_LOG" to "Call log",
        "android.permission.CALL_PHONE" to "Direct dialing",
        "android.permission.READ_EXTERNAL_STORAGE" to "Files & media",
        "android.permission.WRITE_EXTERNAL_STORAGE" to "Files & media (write)",
        "android.permission.READ_MEDIA_IMAGES" to "Photos",
        "android.permission.READ_MEDIA_VIDEO" to "Videos",
        "android.permission.READ_MEDIA_AUDIO" to "Audio files",
        "android.permission.SYSTEM_ALERT_WINDOW" to "Draw over other apps",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Install other apps",
        "android.permission.BODY_SENSORS" to "Body sensors",
        "android.permission.READ_PHONE_STATE" to "Phone state"
    )

    /** Permissions in ApkAnalyzer.dangerousPermissions weigh more (classic abuse vectors). */
    private val HIGH_WEIGHT = ApkAnalyzer.dangerousPermissions

    fun analyze(context: Context, app: AppInfo): AppRiskResult {
        val pm = context.packageManager
        val appName = app.appName ?: app.packageName.substringAfterLast('.')

        var versionName: String? = null
        var requested: List<String> = app.permissions
        try {
            val info = pm.getPackageInfo(
                app.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            versionName = info.versionName
            info.requestedPermissions?.let { requested = it.toList() }
        } catch (_: Throwable) {
            // Includes NoSuchMethodError on platforms lacking the flags-based API
        }

        // getInstallSourceInfo requires API 30+; catch Throwable so older
        // devices degrade to "unknown" instead of crashing.
        val installSource = if (android.os.Build.VERSION.SDK_INT >= 30) try {
            when (pm.getInstallSourceInfo(app.packageName).installingPackageName) {
                "com.android.vending" -> "Google Play"
                null -> "Sideloaded / unknown source"
                else -> "Third-party store"
            }
        } catch (_: Throwable) { null } else null

        // Which sensitive permissions are actually GRANTED (runtime dangerous ones)?
        val grantedSensitive = requested.filter { perm ->
            perm in SENSITIVE && try {
                pm.checkPermission(perm, app.packageName) == PackageManager.PERMISSION_GRANTED
            } catch (_: Exception) { false }
        }

        val findings = mutableListOf<String>()

        // ---------------- PRIVACY AXIS ----------------
        // What private data can this app reach right now? An indicator only.
        var privacy = 0
        val highGranted = grantedSensitive.filter { it in HIGH_WEIGHT }
        if (highGranted.isNotEmpty()) {
            privacy += min(55, highGranted.size * 12)
            findings += "${highGranted.size} high-impact permission(s) granted (" +
                highGranted.take(3).joinToString { SENSITIVE[it] ?: it.substringAfterLast('.') } + ")"
        }
        val otherGranted = grantedSensitive.size - highGranted.size
        if (otherGranted > 0) privacy += min(20, otherGranted * 5)
        if (app.isSystemApp) privacy = (privacy * 3 / 4).coerceAtMost(100) // platform components: expected power

        // ---------------- SECURITY AXIS ----------------
        // Posture / combination signals that historically correlate with abuse.
        var security = 0
        if (app.fromUnknownSource == true) {
            security += 25
            findings += "Installed from outside the Play Store — verify you trust the source"
        }
        if (requested.any { it == "android.permission.REQUEST_INSTALL_PACKAGES" } && !app.isSystemApp) {
            security += 20
            findings += "Can install other apps — uncommon for most app categories"
        }
        val overlaySmsCombo =
            requested.any { it == "android.permission.SYSTEM_ALERT_WINDOW" } &&
            requested.any { it.endsWith("READ_SMS") || it.endsWith("RECEIVE_SMS") }
        if (overlaySmsCombo) {
            security += 30
            findings += "Overlay + SMS combination — classic credential-capture pattern"
        }
        val targetSdk = app.targetSdk ?: 0
        if (targetSdk in 1 until 26) {
            security += 10
            findings += "Targets a very old Android version (targetSdk $targetSdk) — may skip modern privacy controls"
        }

        // ---------------- MALWARE-EVIDENCE AXIS ----------------
        // Starts at zero. Only concrete evidence from a detection system moves
        // it. Today there is no runtime scanner wired to it; when one exists
        // (hash match, confirmed C2 verdict) it feeds HERE, not the others.
        var malwareEvidence = 0

        val privacyScore = privacy.coerceIn(0, 100)
        val securityScore = security.coerceIn(0, 100)

        // Composite for sorting/review ordering — never presented as "malware %".
        val overall = min(100, (privacyScore * 55 + securityScore * 45) / 100)

        // Status bands: permission posture caps out at REVIEW; only
        // security-pattern evidence crosses into SUSPICIOUS, and only
        // detection-system evidence can produce HIGH RISK / CONFIRMED THREAT.
        val status = when {
            malwareEvidence >= 60 -> CONFIRMED_THREAT
            malwareEvidence >= 30 || securityScore >= 70 -> HIGH_RISK
            securityScore >= 40 || privacyScore >= 60 -> SUSPICIOUS
            privacyScore >= 20 || securityScore >= 15 -> REVIEW
            else -> SAFE
        }

        if (findings.isEmpty()) {
            findings += if (app.isSystemApp)
                "Platform component — powerful permissions are expected; not user malware"
            else "No elevated permission risk indicators found"
        }

        return AppRiskResult(
            app = app, appName = appName, versionName = versionName,
            installSource = installSource, permissions = requested,
            grantedSensitive = grantedSensitive,
            privacyScore = privacyScore, securityScore = securityScore,
            malwareEvidence = malwareEvidence, overallScore = overall,
            status = status, findings = findings
        )
    }

    fun analyzeAll(context: Context, apps: List<AppInfo>): List<AppRiskResult> =
        apps.map { analyze(context, it) }

    /** Display color key for a status (maps onto the severity palette). */
    fun statusColorKey(status: String): String = when (status) {
        CONFIRMED_THREAT -> "CRITICAL"
        HIGH_RISK -> "HIGH"
        SUSPICIOUS -> "MEDIUM"
        REVIEW -> "LOW"
        else -> "SAFE"
    }

    private fun min(a: Int, b: Int) = if (a < b) a else b
}
