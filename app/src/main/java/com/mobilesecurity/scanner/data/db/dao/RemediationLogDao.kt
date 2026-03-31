package com.mobilesecurity.scanner.data.db.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.mobilesecurity.scanner.data.db.entities.RemediationLogEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface RemediationLogDao {

    @Insert
    suspend fun insert(log: RemediationLogEntity): Long

    @Query("SELECT * FROM remediation_logs WHERE vulnId = :vulnId ORDER BY timestamp DESC")
    fun getLogsForVuln(vulnId: String): Flow<List<RemediationLogEntity>>

    @Query("SELECT * FROM remediation_logs ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentLogs(limit: Int = 50): List<RemediationLogEntity>

    @Query("DELETE FROM remediation_logs WHERE timestamp < :olderThanMs")
    suspend fun deleteOlderThan(olderThanMs: Long)
}
