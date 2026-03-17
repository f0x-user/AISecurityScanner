package com.aisecurity.scanner.data.db.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "app_audit_entries",
    foreignKeys = [
        ForeignKey(
            entity = ScanResultEntity::class,
            parentColumns = ["id"],
            childColumns = ["scanId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index("scanId"), Index("packageName")]
)
data class AppAuditEntryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scanId: String,
    val packageName: String,
    val appName: String,
    val versionName: String,
    val targetSdkVersion: Int,
    val installSource: String?,
    val isSideloaded: Boolean,
    val isDebugBuild: Boolean,
    val dangerousPermissionsJson: String,   // JSON
    val hasOverlayPermission: Boolean,
    val hasAccessibilityPermission: Boolean,
    val hasDeviceAdminRights: Boolean,
    val riskScore: Int,
    val riskFlagsJson: String               // JSON
)
