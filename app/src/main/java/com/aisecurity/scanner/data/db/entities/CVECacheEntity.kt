package com.aisecurity.scanner.data.db.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "cve_cache")
data class CVECacheEntity(
    @PrimaryKey val cveId: String,
    val dataJson: String,
    val cachedAt: Long,
    val expiresAt: Long,        // cachedAt + 24h TTL
    val source: String
)
