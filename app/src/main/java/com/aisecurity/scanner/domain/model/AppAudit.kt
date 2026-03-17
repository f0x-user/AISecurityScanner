package com.aisecurity.scanner.domain.model

data class AppAudit(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val targetSdkVersion: Int,
    val installSource: String?,
    val isSideloaded: Boolean,
    val isDebugBuild: Boolean,
    val dangerousPermissions: List<String>,
    val hasOverlayPermission: Boolean,
    val hasAccessibilityPermission: Boolean,
    val hasDeviceAdminRights: Boolean,
    val riskScore: Int,             // 0–100
    val riskFlags: List<String>     // Klartextbeschreibungen der Risiken
)
