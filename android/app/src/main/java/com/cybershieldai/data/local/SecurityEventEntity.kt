package com.cybershieldai.data.local

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.ColumnInfo
import androidx.room.Index
import androidx.room.RoomDatabase

/**
 * Local-first security event store. History works fully offline; sync to the
 * backend is optional. Raw sensitive content is NEVER stored — only metadata
 * (labels, hosts, scores). Retention is user-controlled.
 */
@Entity(tableName = "security_events")
data class SecurityEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val category: String,      // URL | MESSAGE | FILE | APK | QR | APP | PRIVACY | NETWORK | SCORE
    val classification: String,// SAFE | SPAM | SCAM | PHISHING | SUSPICIOUS | RISKY | INFO
    val severity: String,      // SAFE | LOW | MEDIUM | HIGH | CRITICAL
    val riskScore: Int,
    val confidence: Double,    // 0..1 (LOW/MEDIUM/HIGH)
    val summary: String,       // short human-readable label (no raw content)
    val indicatorsJson: String,// JSON array of strings
    val methodsJson: String,   // JSON array e.g. ["Rules","NLP(fallback)"]
    val source: String,        // Manual | Monitor | Worker
    @ColumnInfo(defaultValue = "New") val status: String = "New", // New | Reviewed | Resolved
    /** Subject of the analysis when applicable: caller number (E.164-ish), URL, app package. */
    @ColumnInfo(defaultValue = "") val subject: String = ""
)

@Entity(tableName = "daily_stats")
data class DailyStatsEntity(
    @PrimaryKey val day: String,   // yyyy-MM-dd (local)
    val scans: Int = 0,
    val threats: Int = 0,
    val highRisk: Int = 0,
    val urls: Int = 0,
    val messages: Int = 0,
    val files: Int = 0,
    val apps: Int = 0
)

/**
 * Snapshot of one completed security check (manual scan or automatic 12h
 * check). Powers "What Changed?" and "Last Security Check" honestly: every
 * number comes from the diff at completion time.
 */
@Entity(tableName = "check_snapshots")
data class CheckSnapshotEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val completedAt: Long,
    val trigger: String,        // Manual | AutoCheck
    val appsChecked: Int,
    val threatsFound: Int,
    val privacyChanges: Int,
    val networkEvents: Int,
    val score: Int?,            // null when the score engine could not run
    val packagesJson: String,   // JSON array of user-app package names
    val changesJson: String     // JSON array: "+2 new apps" style lines
)

@Dao
interface SecurityEventDao {
    @Insert
    suspend fun insert(event: SecurityEventEntity): Long

    @Query("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT :limit")
    suspend fun recent(limit: Int = 100): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events WHERE severity IN ('HIGH','CRITICAL') ORDER BY timestamp DESC LIMIT :limit")
    suspend fun recentHighRisk(limit: Int = 20): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events WHERE id = :id")
    suspend fun byId(id: Long): SecurityEventEntity?

    /** Most recent prior scan of the same URL host+summary prefix (URL tab §8). */
    @Query("SELECT * FROM security_events WHERE category = 'URL' AND summary = :label ORDER BY timestamp DESC LIMIT 1")
    suspend fun latestByUrlLabel(label: String): SecurityEventEntity?

    @Query("DELETE FROM security_events")
    suspend fun clearAll()

    @Query("DELETE FROM security_events WHERE timestamp < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)

    @Query("DELETE FROM security_events WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("UPDATE security_events SET status = :status WHERE id = :id")
    suspend fun setStatus(id: Long, status: String)

    @Query("SELECT COUNT(*) FROM security_events")
    suspend fun count(): Int

    @Query("SELECT COUNT(*) FROM security_events WHERE timestamp >= :since")
    suspend fun countSince(since: Long): Int

    @Query("SELECT COUNT(*) FROM security_events WHERE timestamp >= :since AND severity IN ('HIGH','CRITICAL')")
    suspend fun countHighRiskSince(since: Long): Int

    @Query("SELECT COUNT(*) FROM security_events WHERE timestamp >= :since AND category = :category")
    suspend fun countCategorySince(since: Long, category: String): Int

    @Query("SELECT COUNT(*) FROM security_events WHERE timestamp >= :since AND category = :category AND riskScore >= :minRisk")
    suspend fun countCategorySinceMinRisk(since: Long, category: String, minRisk: Int): Int

    @Query("SELECT category, COUNT(*) as cnt FROM security_events GROUP BY category")
    suspend fun countByCategory(): List<CategoryCount>

    @Query("SELECT * FROM security_events WHERE category = 'SCORE' ORDER BY timestamp DESC LIMIT 1")
    suspend fun lastScoreSnapshot(): SecurityEventEntity?

    @Query("SELECT severity, COUNT(*) as cnt FROM security_events GROUP BY severity")
    suspend fun countBySeverity(): List<SeverityCount>
}

data class CategoryCount(val category: String, val cnt: Int)
data class SeverityCount(val severity: String, val cnt: Int)

@Dao
interface DailyStatsDao {
    @Query("SELECT * FROM daily_stats ORDER BY day DESC LIMIT :days")
    suspend fun recent(days: Int = 14): List<DailyStatsEntity>

    @Query("SELECT * FROM daily_stats WHERE day = :day")
    suspend fun byDay(day: String): DailyStatsEntity?

    /** True upsert: REPLACE avoids the UNIQUE(day) crash when today's row
     *  already exists (this constraint failure previously aborted event
     *  recording and silently killed call-screening notifications). */
    @Insert(onConflict = androidx.room.OnConflictStrategy.REPLACE)
    suspend fun upsert(stats: DailyStatsEntity)
}

/**
 * Community report (spec §25): a user-filed report of a scam/suspicious
 * number, SMS or URL. LOCAL ONLY — nothing leaves the device. Feeds the
 * Call Risk Engine's caller-reputation signal (spec §5) and marks future
 * calls from reported numbers.
 */
@Entity(tableName = "community_reports")
data class CommunityReportEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val createdAt: Long,
    val kind: String,           // NUMBER | SMS | URL | APP | OTHER
    val value: String,          // number (E.164-ish), URL, app package, or summary
    val reportType: String,     // SCAM | PHISHING | SPAM | FRAUDULENT_PAYMENT | FRAUD_ATTEMPT
    val note: String,           // optional user note (may be empty)
    @ColumnInfo(defaultValue = "New") val status: String = "New"  // New | Reviewed
)

@Dao
interface CommunityReportDao {
    @Insert
    suspend fun insert(report: CommunityReportEntity): Long

    @Query("SELECT * FROM community_reports WHERE kind = 'NUMBER' AND value = :number LIMIT 1")
    suspend fun numberReport(number: String): CommunityReportEntity?

    @Query("SELECT COUNT(*) FROM community_reports WHERE kind = 'NUMBER' AND value = :number")
    suspend fun countNumberReports(number: String): Int

    @Query("SELECT * FROM community_reports ORDER BY createdAt DESC LIMIT :limit")
    suspend fun recent(limit: Int = 100): List<CommunityReportEntity>

    @Query("SELECT COUNT(*) FROM community_reports")
    suspend fun count(): Int

    @Query("UPDATE community_reports SET status = :status WHERE id = :id")
    suspend fun setStatus(id: Long, status: String)

    @Query("DELETE FROM community_reports WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM community_reports")
    suspend fun clearAll()
}

@Dao
interface CheckSnapshotDao {
    @Insert
    suspend fun insert(snapshot: CheckSnapshotEntity): Long

    @Query("SELECT * FROM check_snapshots ORDER BY completedAt DESC LIMIT 1")
    suspend fun latest(): CheckSnapshotEntity?

    @Query("SELECT COUNT(*) FROM check_snapshots")
    suspend fun count(): Int
}

@Database(
    entities = [
        SecurityEventEntity::class,
        DailyStatsEntity::class,
        CheckSnapshotEntity::class,
        CommunityReportEntity::class
    ],
    version = 7,
    exportSchema = false
)
abstract class CyberShieldDatabase : RoomDatabase() {
    abstract fun securityEventDao(): SecurityEventDao
    abstract fun dailyStatsDao(): DailyStatsDao
    abstract fun checkSnapshotDao(): CheckSnapshotDao
    abstract fun communityReportDao(): CommunityReportDao
}

