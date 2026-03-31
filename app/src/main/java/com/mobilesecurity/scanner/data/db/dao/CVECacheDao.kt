package com.mobilesecurity.scanner.data.db.dao

import androidx.room.*
import com.mobilesecurity.scanner.data.db.entities.CVECacheEntity

@Dao
interface CVECacheDao {

    @Query("SELECT * FROM cve_cache WHERE cveId = :cveId AND expiresAt > :now LIMIT 1")
    suspend fun getCachedCVE(cveId: String, now: Long = System.currentTimeMillis()): CVECacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrReplace(entry: CVECacheEntity)

    @Query("DELETE FROM cve_cache WHERE expiresAt < :now")
    suspend fun deleteExpired(now: Long = System.currentTimeMillis())

    @Query("DELETE FROM cve_cache")
    suspend fun clearAll()

    @Query("SELECT COUNT(*) FROM cve_cache WHERE expiresAt > :now")
    suspend fun getValidCacheCount(now: Long = System.currentTimeMillis()): Int

    @Query("SELECT * FROM cve_cache WHERE expiresAt > :now")
    suspend fun getValidEntries(now: Long = System.currentTimeMillis()): List<CVECacheEntity>
}
