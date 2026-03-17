package com.aisecurity.scanner.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
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
    version = 2,
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanResultDao(): ScanResultDao
    abstract fun vulnerabilityDao(): VulnerabilityDao
    abstract fun cveCache(): CVECacheDao
    abstract fun appAuditDao(): AppAuditDao
}
