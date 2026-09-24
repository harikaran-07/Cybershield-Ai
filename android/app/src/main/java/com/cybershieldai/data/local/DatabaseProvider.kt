package com.cybershieldai.data.local

import android.content.Context
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/** Singleton Room database provider. All history is local-first. */
object DatabaseProvider {
    @Volatile private var instance: CyberShieldDatabase? = null

    /** v3→v4: community_reports gains the lifecycle `status` column. */
    private val MIGRATION_3_4 = object : Migration(3, 4) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "ALTER TABLE community_reports ADD COLUMN status TEXT NOT NULL DEFAULT 'New'")
        }
    }

    /** v4→v5: security_events.subject column. v5→v6: caller_identities
     *  dropped (call screening removed from the product). Existing rows in
     *  the dropped table are simply abandoned; no data is carried over. */
    private val MIGRATION_4_5 = object : Migration(4, 5) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "ALTER TABLE security_events ADD COLUMN subject TEXT NOT NULL DEFAULT ''")
        }
    }

    /** v5→v6: remove the caller_identities table (call screening removed).
     *  v6→v7: remove the scam_incidents table (Scam Protection removed). */
    private val MIGRATION_5_6 = object : Migration(5, 6) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("DROP TABLE IF EXISTS caller_identities")
        }
    }

    private val MIGRATION_6_7 = object : Migration(6, 7) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("DROP TABLE IF EXISTS scam_incidents")
        }
    }

    fun get(context: Context): CyberShieldDatabase =
        instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                context.applicationContext,
                CyberShieldDatabase::class.java,
                "cybershield.db"
            )
                .addMigrations(MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7)
                .fallbackToDestructiveMigration()
                .build().also { instance = it }
        }
}
