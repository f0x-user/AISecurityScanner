package com.aisecurity.scanner.data.repository

import com.aisecurity.scanner.data.db.dao.AppAuditDao
import com.aisecurity.scanner.data.db.dao.ScanResultDao
import com.aisecurity.scanner.data.db.dao.VulnerabilityDao
import com.aisecurity.scanner.data.db.entities.*
import com.aisecurity.scanner.domain.model.*
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanRepository @Inject constructor(
    private val scanResultDao: ScanResultDao,
    private val vulnerabilityDao: VulnerabilityDao,
    private val appAuditDao: AppAuditDao,
    private val moshi: Moshi
) {
    private val stringListAdapter = moshi.adapter<List<String>>(
        Types.newParameterizedType(List::class.java, String::class.java)
    )

    fun getAllScans(): Flow<List<ScanResult>> =
        scanResultDao.getAllScans().map { entities ->
            entities.map { entity ->
                ScanResult(
                    id = entity.id,
                    timestamp = Instant.ofEpochMilli(entity.timestamp),
                    overallScore = entity.overallScore,
                    scanDepth = entity.scanDepth,
                    durationMs = entity.durationMs,
                    vulnerabilities = emptyList(), // Lazy – Details werden separat geladen
                    storedCritical = entity.criticalCount,
                    storedHigh = entity.highCount,
                    storedMedium = entity.mediumCount,
                    storedLow = entity.lowCount,
                    storedZeroDay = entity.zeroDayCount,
                    storedActivelyExploited = entity.activelyExploitedCount,
                )
            }
        }

    suspend fun getScanWithDetails(scanId: String): ScanResult? = withContext(Dispatchers.IO) {
        val entity = scanResultDao.getScanById(scanId) ?: return@withContext null
        val vulnEntities = vulnerabilityDao.getVulnerabilitiesForScanOnce(scanId)
        val auditEntities = appAuditDao.getAuditsForScanOnce(scanId)

        ScanResult(
            id = entity.id,
            timestamp = Instant.ofEpochMilli(entity.timestamp),
            overallScore = entity.overallScore,
            scanDepth = entity.scanDepth,
            durationMs = entity.durationMs,
            vulnerabilities = vulnEntities.map { it.toDomain() },
            appAudits = auditEntities.map { it.toDomain() }
        )
    }

    suspend fun getAllScansOnce(): List<ScanResult> = withContext(Dispatchers.IO) {
        scanResultDao.getAllScansOnce().map { entity ->
            ScanResult(
                id = entity.id,
                timestamp = Instant.ofEpochMilli(entity.timestamp),
                overallScore = entity.overallScore,
                scanDepth = entity.scanDepth,
                durationMs = entity.durationMs,
                vulnerabilities = emptyList(),
                storedCritical = entity.criticalCount,
                storedHigh = entity.highCount,
                storedMedium = entity.mediumCount,
                storedLow = entity.lowCount,
                storedZeroDay = entity.zeroDayCount,
                storedActivelyExploited = entity.activelyExploitedCount,
            )
        }
    }

    suspend fun getLatestScan(): ScanResult? = withContext(Dispatchers.IO) {
        val entity = scanResultDao.getLatestScan() ?: return@withContext null
        getScanWithDetails(entity.id)
    }

    suspend fun saveScan(scanResult: ScanResult) = withContext(Dispatchers.IO) {
        scanResultDao.insertScan(
            ScanResultEntity(
                id = scanResult.id,
                timestamp = scanResult.timestamp.toEpochMilli(),
                overallScore = scanResult.overallScore,
                scanDepth = scanResult.scanDepth,
                durationMs = scanResult.durationMs,
                criticalCount = scanResult.criticalCount,
                highCount = scanResult.highCount,
                mediumCount = scanResult.mediumCount,
                lowCount = scanResult.lowCount,
                zeroDayCount = scanResult.zeroDayCount,
                activelyExploitedCount = scanResult.activelyExploitedCount
            )
        )
        vulnerabilityDao.insertVulnerabilities(
            scanResult.vulnerabilities.map { it.toEntity(scanResult.id) }
        )
        appAuditDao.insertAudits(
            scanResult.appAudits.map { it.toEntity(scanResult.id) }
        )
    }

    suspend fun deleteScan(scanId: String) = withContext(Dispatchers.IO) {
        val entity = scanResultDao.getScanById(scanId) ?: return@withContext
        scanResultDao.deleteScan(entity)
    }

    suspend fun deleteOldScans(retentionDays: Int) = withContext(Dispatchers.IO) {
        val cutoff = System.currentTimeMillis() - retentionDays * 24 * 60 * 60 * 1000L
        scanResultDao.deleteOlderThan(cutoff)
    }

    // Mapping-Extensions
    private fun VulnerabilityEntity.toDomain(): VulnerabilityEntry = VulnerabilityEntry(
        id = id,
        title = title,
        severity = Severity.valueOf(severity),
        cvssScore = cvssScore,
        cvssVector = cvssVector,
        isZeroDay = isZeroDay,
        isActivelyExploited = isActivelyExploited,
        affectedComponent = affectedComponent,
        description = description,
        impact = impact,
        remediation = RemediationSteps(
            priority = Priority.valueOf(remediationPriority),
            steps = stringListAdapter.fromJson(remediationStepsJson) ?: emptyList(),
            automatable = automatable,
            deepLinkSettings = deepLinkSettings,
            officialDocUrl = officialDocUrl,
            estimatedTime = estimatedTime
        ),
        cveLinks = stringListAdapter.fromJson(cveLinksJson) ?: emptyList(),
        patchAvailable = patchAvailable,
        patchEta = patchEta,
        detectedAt = Instant.ofEpochMilli(detectedAt),
        source = source,
        affectedApps = stringListAdapter.fromJson(affectedAppsJson) ?: emptyList()
    )

    private fun VulnerabilityEntry.toEntity(scanId: String): VulnerabilityEntity =
        VulnerabilityEntity(
            id = id,
            scanId = scanId,
            cveId = cveLinks.firstOrNull()?.substringAfterLast("/") ?: id,
            title = title,
            severity = severity.name,
            cvssScore = cvssScore,
            cvssVector = cvssVector,
            isZeroDay = isZeroDay,
            isActivelyExploited = isActivelyExploited,
            affectedComponent = affectedComponent,
            description = description,
            impact = impact,
            remediationPriority = remediation.priority.name,
            remediationStepsJson = stringListAdapter.toJson(remediation.steps),
            automatable = remediation.automatable,
            deepLinkSettings = remediation.deepLinkSettings,
            officialDocUrl = remediation.officialDocUrl,
            estimatedTime = remediation.estimatedTime,
            cveLinksJson = stringListAdapter.toJson(cveLinks),
            patchAvailable = patchAvailable,
            patchEta = patchEta,
            detectedAt = detectedAt.toEpochMilli(),
            source = source,
            affectedAppsJson = stringListAdapter.toJson(affectedApps)
        )

    private fun AppAuditEntryEntity.toDomain(): AppAudit = AppAudit(
        packageName = packageName,
        appName = appName,
        versionName = versionName,
        targetSdkVersion = targetSdkVersion,
        installSource = installSource,
        isSideloaded = isSideloaded,
        isDebugBuild = isDebugBuild,
        dangerousPermissions = stringListAdapter.fromJson(dangerousPermissionsJson) ?: emptyList(),
        hasOverlayPermission = hasOverlayPermission,
        hasAccessibilityPermission = hasAccessibilityPermission,
        hasDeviceAdminRights = hasDeviceAdminRights,
        riskScore = riskScore,
        riskFlags = stringListAdapter.fromJson(riskFlagsJson) ?: emptyList()
    )

    private fun AppAudit.toEntity(scanId: String): AppAuditEntryEntity = AppAuditEntryEntity(
        scanId = scanId,
        packageName = packageName,
        appName = appName,
        versionName = versionName,
        targetSdkVersion = targetSdkVersion,
        installSource = installSource,
        isSideloaded = isSideloaded,
        isDebugBuild = isDebugBuild,
        dangerousPermissionsJson = stringListAdapter.toJson(dangerousPermissions),
        hasOverlayPermission = hasOverlayPermission,
        hasAccessibilityPermission = hasAccessibilityPermission,
        hasDeviceAdminRights = hasDeviceAdminRights,
        riskScore = riskScore,
        riskFlagsJson = stringListAdapter.toJson(riskFlags)
    )
}
