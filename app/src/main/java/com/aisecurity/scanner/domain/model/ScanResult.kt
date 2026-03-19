package com.aisecurity.scanner.domain.model

import java.time.Instant

data class ScanResult(
    val id: String,
    val timestamp: Instant,
    val overallScore: Int,           // 0–100 (100 = sicher)
    val scanDepth: String = ScanDepth.FULL,
    val durationMs: Long,
    val vulnerabilities: List<VulnerabilityEntry>,
    val appAudits: List<AppAudit> = emptyList(),
    // Vorberechnete Zähler aus der DB – gesetzt wenn vulnerabilities lazy geladen werden
    private val storedCritical: Int = -1,
    private val storedHigh: Int = -1,
    private val storedMedium: Int = -1,
    private val storedLow: Int = -1,
    private val storedZeroDay: Int = -1,
    private val storedActivelyExploited: Int = -1,
) {
    val criticalCount: Int
        get() = if (storedCritical >= 0) storedCritical else vulnerabilities.count { it.severity == Severity.CRITICAL }
    val highCount: Int
        get() = if (storedHigh >= 0) storedHigh else vulnerabilities.count { it.severity == Severity.HIGH }
    val mediumCount: Int
        get() = if (storedMedium >= 0) storedMedium else vulnerabilities.count { it.severity == Severity.MEDIUM }
    val lowCount: Int
        get() = if (storedLow >= 0) storedLow else vulnerabilities.count { it.severity == Severity.LOW }
    val zeroDayCount: Int
        get() = if (storedZeroDay >= 0) storedZeroDay else vulnerabilities.count { it.isZeroDay }
    val activelyExploitedCount: Int
        get() = if (storedActivelyExploited >= 0) storedActivelyExploited else vulnerabilities.count { it.isActivelyExploited }
}

data class ScanDelta(
    val scoreDelta: Int,
    val newFindings: List<VulnerabilityEntry>,
    val resolvedFindings: List<VulnerabilityEntry>,
    val persistentFindings: List<VulnerabilityEntry>
)

fun ScanResult.compareTo(previous: ScanResult): ScanDelta {
    val currentIds = vulnerabilities.map { it.id }.toSet()
    val previousIds = previous.vulnerabilities.map { it.id }.toSet()
    return ScanDelta(
        scoreDelta = overallScore - previous.overallScore,
        newFindings = vulnerabilities.filter { it.id !in previousIds },
        resolvedFindings = previous.vulnerabilities.filter { it.id !in currentIds },
        persistentFindings = vulnerabilities.filter { it.id in previousIds }
    )
}

enum class ScanStatus {
    IDLE, RUNNING, COMPLETED, FAILED, CANCELLED
}

data class ScanProgress(
    val status: ScanStatus = ScanStatus.IDLE,
    val currentModule: String = "",
    val progressPercent: Int = 0,
    val logLines: List<String> = emptyList(),
    val error: String? = null
)
