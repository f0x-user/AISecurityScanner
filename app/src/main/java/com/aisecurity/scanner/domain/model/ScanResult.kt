package com.aisecurity.scanner.domain.model

import java.time.Instant

data class ScanResult(
    val id: String,
    val timestamp: Instant,
    val overallScore: Int,           // 0–100 (100 = sicher)
    val scanDepth: ScanDepth,
    val durationMs: Long,
    val vulnerabilities: List<VulnerabilityEntry>,
    val appAudits: List<AppAudit> = emptyList()
) {
    val criticalCount get() = vulnerabilities.count { it.severity == Severity.CRITICAL }
    val highCount get() = vulnerabilities.count { it.severity == Severity.HIGH }
    val mediumCount get() = vulnerabilities.count { it.severity == Severity.MEDIUM }
    val lowCount get() = vulnerabilities.count { it.severity == Severity.LOW }
    val zeroDayCount get() = vulnerabilities.count { it.isZeroDay }
    val activelyExploitedCount get() = vulnerabilities.count { it.isActivelyExploited }
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
