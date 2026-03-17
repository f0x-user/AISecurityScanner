package com.aisecurity.scanner.data.db.dao

import androidx.room.*
import com.aisecurity.scanner.data.db.entities.ScanResultEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanResultDao {

    @Query("SELECT * FROM scan_results ORDER BY timestamp DESC")
    fun getAllScans(): Flow<List<ScanResultEntity>>

    @Query("SELECT * FROM scan_results WHERE id = :id LIMIT 1")
    suspend fun getScanById(id: String): ScanResultEntity?

    @Query("SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLatestScan(): ScanResultEntity?

    @Query("SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentScans(limit: Int): List<ScanResultEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(scan: ScanResultEntity)

    @Delete
    suspend fun deleteScan(scan: ScanResultEntity)

    @Query("DELETE FROM scan_results WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("SELECT COUNT(*) FROM scan_results")
    suspend fun getScanCount(): Int
}
