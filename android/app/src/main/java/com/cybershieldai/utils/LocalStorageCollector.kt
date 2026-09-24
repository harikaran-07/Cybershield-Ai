package com.cybershieldai.utils

import android.app.usage.StorageStatsManager
import android.content.Context
import android.os.Environment
import android.os.storage.StorageManager
import java.util.UUID

/**
 * Real device storage figures via StorageStatsManager / StorageManager.
 * No hardcoded values — falls back honestly (null) when the OS refuses.
 */
object LocalStorageCollector {

    data class StorageSnapshot(
        val totalGb: Long,
        val usedGb: Long,
        val freeGb: Long
    )

    fun snapshot(): StorageSnapshot? = try {
        val sm = ContextHolder.appContext?.getSystemService(Context.STORAGE_SERVICE) as? StorageManager
        val ssm = ContextHolder.appContext?.getSystemService(Context.STORAGE_STATS_SERVICE) as? StorageStatsManager
        if (sm == null || ssm == null) null else {
            val storageVolumes = sm.storageVolumes
            val internal = storageVolumes.firstOrNull { it.isPrimary } ?: storageVolumes.firstOrNull()
            val uuid: UUID = internal?.uuid?.let {
                try { UUID.fromString(it) } catch (_: Exception) { StorageManager.UUID_DEFAULT }
            } ?: StorageManager.UUID_DEFAULT

            val totalBytes = ssm.getTotalBytes(uuid)
            val freeBytes = ssm.getFreeBytes(uuid)
            if (totalBytes <= 0) null
            else StorageSnapshot(
                totalGb = totalBytes / (1024L * 1024L * 1024L),
                freeGb = freeBytes / (1024L * 1024L * 1024L),
                usedGb = (totalBytes - freeBytes) / (1024L * 1024L * 1024L)
            )
        }
    } catch (_: Exception) {
        // Some OEM builds restrict StorageStats — degrade to Environment estimate
        try {
            val dir = Environment.getDataDirectory()
            val total = dir.totalSpace
            val free = dir.usableSpace
            if (total <= 0) null
            else StorageSnapshot(
                totalGb = total / (1024L * 1024L * 1024L),
                freeGb = free / (1024L * 1024L * 1024L),
                usedGb = (total - free) / (1024L * 1024L * 1024L)
            )
        } catch (_: Exception) { null }
    }
}

/** Application-context holder so non-Activity collectors can reach services. */
object ContextHolder {
    @Volatile
    var appContext: android.content.Context? = null
}
