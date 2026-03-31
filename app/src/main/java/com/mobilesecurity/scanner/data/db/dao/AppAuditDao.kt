package com.mobilesecurity.scanner.data.db.dao

import androidx.room.*
import com.mobilesecurity.scanner.data.db.entities.AppAuditEntryEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface AppAuditDao {

    @Query("SELECT * FROM app_audit_entries WHERE scanId = :scanId ORDER BY riskScore DESC")
    fun getAuditsForScan(scanId: String): Flow<List<AppAuditEntryEntity>>

    @Query("SELECT * FROM app_audit_entries WHERE scanId = :scanId ORDER BY riskScore DESC")
    suspend fun getAuditsForScanOnce(scanId: String): List<AppAuditEntryEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAudits(audits: List<AppAuditEntryEntity>)

    @Query("DELETE FROM app_audit_entries WHERE scanId = :scanId")
    suspend fun deleteAuditsForScan(scanId: String)
}
