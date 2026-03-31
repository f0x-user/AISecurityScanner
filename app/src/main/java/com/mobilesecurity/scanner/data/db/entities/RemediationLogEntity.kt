package com.mobilesecurity.scanner.data.db.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "remediation_logs",
    foreignKeys = [
        ForeignKey(
            entity = VulnerabilityEntity::class,
            parentColumns = ["id"],
            childColumns = ["vulnId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index("vulnId")]
)
data class RemediationLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val vulnId: String,
    val action: String,
    val timestamp: Long,
    val success: Boolean,
    val notes: String = ""
)
