package com.cybershieldai.utils

import com.cybershieldai.data.model.AppInfo
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

/**
 * Safe static APK analysis. NEVER executes, installs, or extracts to disk.
 * Reads the ZIP central directory and the binary AndroidManifest for
 * permission strings, then applies the same permission-risk rules as
 * app-security analysis.
 */
object ApkAnalyzer {

    /** Publicly reusable set for the package monitor. */
    val dangerousPermissions: Set<String> = setOf(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS", "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA", "android.permission.READ_CONTACTS",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.READ_CALL_LOG", "android.permission.CALL_PHONE",
        "android.permission.BODY_SENSORS"
    )
    private val OVERLAY_PERMS = setOf(
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"
    )

    data class ApkResult(
        val fileName: String,
        val sha256: String,
        val sizeBytes: Int,
        val packageName: String?,
        val permissions: List<String>,
        val indicators: List<String>,
        val riskScore: Int,
        val severity: String,
        val classification: String,
        val entryCount: Int
    )

    fun analyze(fileName: String, bytes: ByteArray): ApkResult {
        val indicators = mutableListOf<String>()
        val sha = sha256(bytes)

        // --- ZIP structure ---
        var entryCount = 0
        var manifestBytes: ByteArray? = null
        var dexCount = 0
        var hasNativeLibs = false
        try {
            ZipInputStream(ByteArrayInputStream(bytes)).use { zis ->
                val buffer = ByteArray(64 * 1024)
                while (entryCount < 2000) {
                    val entry = zis.nextEntry ?: break
                    entryCount++
                    when {
                        entry.name == "AndroidManifest.xml" && manifestBytes == null -> {
                            val out = java.io.ByteArrayOutputStream()
                            var n: Int
                            while (zis.read(buffer).also { n = it } > 0) out.write(buffer, 0, n)
                            manifestBytes = out.toByteArray()
                        }
                        entry.name.endsWith(".dex") -> dexCount++
                        entry.name.startsWith("lib/") -> hasNativeLibs = true
                    }
                    if (entry.name.contains("..")) indicators.add("ZIP entry path traversal pattern: ${entry.name}")
                    zis.closeEntry()
                }
            }
        } catch (e: Exception) {
            indicators.add("Archive structure is unreadable — possibly corrupted or not a valid APK")
        }

        // --- Manifest permissions (binary XML string pool extraction) ---
        val permissions = manifestBytes?.let { extractPermissions(it) } ?: emptyList()
        if (manifestBytes == null) indicators.add("AndroidManifest.xml not found or unreadable")

        val dangerous = permissions.filter { it in dangerousPermissions }
        if (dangerous.isNotEmpty()) {
            indicators.add("${dangerous.size} high-risk permission(s) requested: " +
                dangerous.take(4).joinToString(", ") { it.substringAfterLast(".") })
        }
        // Classic overlay+accessibility or overlay+SMS combo is a strong risk signal
        val permSet = permissions.toSet()
        if (permSet.any { it in OVERLAY_PERMS } && (permSet.any { it.endsWith("READ_SMS") } || permSet.any { it.endsWith("RECEIVE_SMS") })) {
            indicators.add("Overlay/accessibility combined with SMS access — classic credential-capture pattern")
        }
        if (dexCount > 3) indicators.add("Multiple DEX files ($dexCount) — dynamic loading common")
        if (hasNativeLibs) indicators.add("Contains native libraries")

        // --- Risk scoring (mirrors backend app_security rules) ---
        var score = min(100, dangerous.size * 15 + indicators.size * 8)
        val severity = OfflineAnalyzer.severityFor(score)
        val classification = when {
            score >= 60 -> "RISKY"
            score >= 30 -> "SUSPICIOUS"
            else -> "SAFE"
        }

        return ApkResult(
            fileName = fileName,
            sha256 = sha,
            sizeBytes = bytes.size,
            packageName = null, // binary manifest parsing of package attr is heuristic-only; skip honest gap
            permissions = permissions,
            indicators = indicators.ifEmpty { listOf("No suspicious static indicators found") },
            riskScore = score,
            severity = severity,
            classification = classification,
            entryCount = entryCount
        )
    }

    /**
     * Extract permission strings from a binary AndroidManifest.xml by scanning
     * its UTF-16 string pool. This is a read-only heuristic that works for most
     * APKs without full binary-XML parsing.
     */
    private fun extractPermissions(manifest: ByteArray): List<String> {
        val perms = mutableListOf<String>()
        try {
            // Binary XML stores strings as UTF-16LE; scan for known permission prefixes
            val text = String(manifest, Charsets.UTF_16LE)
            val regex = Regex("android\\.permission\\.[A-Z_]+")
            regex.findAll(text).forEach { m ->
                val p = m.value
                if (p !in perms) perms.add(p)
            }
        } catch (_: Exception) { }
        return perms
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun min(a: Int, b: Int): Int = if (a < b) a else b
}
