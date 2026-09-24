package com.cybershieldai.utils

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.cybershieldai.data.model.AppInfo

/**
 * Collects installed-app metadata via legitimate PackageManager APIs.
 *
 * Classification contract (product spec §4):
 *  - USER apps: installed by the user (not part of the system image), plus
 *    updated system apps (the user/store replaced their copy → user-owned).
 *  - SYSTEM apps: part of the system image (AOSP/platform).
 *  - OEM/VENDOR: system packages from the device maker / SoC vendor
 *    (OnePlus, Oppo, Realme, Qualcomm, MediaTek, …) where identifiable.
 *
 * Returns null when the platform restricts visibility (Android 11+ package
 * visibility) — the UI then explains this honestly instead of pretending.
 */
object AppScanner {

    /** OEM / SoC-vendor package prefixes (device-maker bloatware & engines). */
    private val OEM_PREFIXES = listOf(
        "com.oplus.", "com.oneplus.", "com.coloros.", "com.realme.", "com.heytap.",
        "com.oppo.", "com.color.", "com.samsung.", "com.sec.android.", "com.miui.",
        "com.xiaomi.", "com.huawei.", "com.hihonor.", "com.vivo.", "com.bbkl.",
        "com.asus.", "com.zte.", "com.lenovo.", "com.lge.", "com.sony.",
        "org.codeaurora.", "org.qualcomm.", "org.chromium.",
        "com.qualcomm.", "com.qti.", "vendor.", "com.mediatek.",
        "com.android.settings.", "com.android.stk.", "com.android.hotword."
    )

    /** Packages that ARE the Android platform itself (never user apps). */
    private val PLATFORM_EXACT = setOf(
        "android", "com.android.shell", "com.android.launcher3", "com.android.systemui"
    )

    data class DeviceApps(
        val userApps: List<AppInfo>,
        val systemApps: List<AppInfo>,
        val oemApps: List<AppInfo>,
        val visibleCount: Int,      // packages we could inspect at all
        val totalPackages: Int      // everything the OS reports (when accessible)
    ) {
        val systemAndOem: List<AppInfo> get() = systemApps + oemApps
    }

    /**
     * Full device inventory, split into user / system / OEM buckets.
     * Only packages that request at least one permission are returned —
     * permission-less packages have nothing security-relevant to review.
     */
    fun collectDeviceApps(context: Context): DeviceApps? {
        val pm = context.packageManager
        return try {
            val flags = PackageManager.GET_PERMISSIONS
            val packages: List<PackageInfo> =
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))

            val user = mutableListOf<AppInfo>()
            val system = mutableListOf<AppInfo>()
            val oem = mutableListOf<AppInfo>()

            for (info in packages) {
                if (info.requestedPermissions == null) continue
                val app = info.applicationInfo ?: continue
                val entry = toAppInfo(context, pm, info, app)
                val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                val isOem = isOemPackage(info.packageName)

                when {
                    // Updated system apps carry user/store-installed updates → user-owned
                    !isSystem || isUpdatedSystem -> user.add(entry)
                    isOem -> oem.add(entry)
                    else -> system.add(entry)
                }
            }

            DeviceApps(
                userApps = user.sortedBy { (it.appName ?: it.packageName).lowercase() },
                systemApps = system.sortedBy { (it.appName ?: it.packageName).lowercase() },
                oemApps = oem.sortedBy { (it.appName ?: it.packageName).lowercase() },
                visibleCount = packages.size,
                totalPackages = packages.size
            )
        } catch (e: SecurityException) {
            null // package visibility restricted
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Back-compat helper: user-facing apps only (user-installed + updated
     * system apps). This is the set the backend analyzes — the default view.
     */
    fun collectInstalledApps(context: Context): List<AppInfo>? =
        collectDeviceApps(context)?.userApps

    private fun toAppInfo(
        context: Context, pm: PackageManager, info: PackageInfo, app: ApplicationInfo
    ): AppInfo = AppInfo(
        packageName = info.packageName,
        appName = app.loadLabel(pm)?.toString(),
        // Stock packages (e.g. com.android.shell) declare 900+ permissions;
        // cap per app so batch requests stay lean and server limits never
        // reject the whole device scan.
        permissions = (info.requestedPermissions?.toList() ?: emptyList()).take(200),
        isSystemApp = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
        fromUnknownSource =
            (app.flags and ApplicationInfo.FLAG_SYSTEM) == 0 &&
            (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0 &&
            !isFromPlayStore(context, info.packageName),
        accessibilityEnabled = null,
        targetSdk = app.targetSdkVersion
    )

    fun isOemPackage(packageName: String): Boolean {
        if (packageName in PLATFORM_EXACT) return false
        return OEM_PREFIXES.any { packageName.startsWith(it) }
    }

    private fun isFromPlayStore(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getInstallerPackageName(packageName) == "com.android.vending"
        } catch (e: Exception) {
            false
        }
    }

    /** Does this package open from the launcher? (user-visible app signal) */
    fun hasLauncherEntry(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getLaunchIntentForPackage(packageName) != null
        } catch (_: Exception) {
            false
        }
    }

    /** Permission list for one package (used by the package monitor). */
    fun permissionsForPackage(context: Context, packageName: String): List<String>? {
        return try {
            val pm = context.packageManager
            val info = pm.getPackageInfo(
                packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
            )
            info.requestedPermissions?.toList() ?: emptyList()
        } catch (e: Exception) {
            null
        }
    }
}
