package com.aisecurity.scanner.data.db.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_results")
data class ScanResultEntity(
    @PrimaryKey val id: String,
    val timestamp: Long,
    val overallScore: Int,
    val scanDepth: String,
    val durationMs: Long,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val zeroDayCount: Int,
    val activelyExploitedCount: Int
)
