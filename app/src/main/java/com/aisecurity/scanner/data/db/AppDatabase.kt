package com.aisecurity.scanner.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.aisecurity.scanner.data.db.dao.*
import com.aisecurity.scanner.data.db.entities.*

@Database(
    entities = [
        ScanResultEntity::class,
        VulnerabilityEntity::class,
        RemediationLogEntity::class,
        CVECacheEntity::class,
        AppAuditEntryEntity::class
    ],
    version = 3,
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanResultDao(): ScanResultDao
    abstract fun vulnerabilityDao(): VulnerabilityDao
    abstract fun cveCache(): CVECacheDao
    abstract fun appAuditDao(): AppAuditDao
    abstract fun remediationLogDao(): RemediationLogDao

    companion object {
        // Migration von Version 1 auf 2 – fügt affectedAppsJson zur vulnerabilities-Tabelle hinzu.
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `vulnerabilities` ADD COLUMN `affectedAppsJson` TEXT NOT NULL DEFAULT ''"
                )
            }
        }

        // Migration von Version 2 auf 3 – keine strukturellen Schema-Änderungen,
        // daher ist dies eine No-Op-Migration (reine Versions-Inkrementierung).
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Keine Schema-Änderungen erforderlich.
            }
        }
    }
}
