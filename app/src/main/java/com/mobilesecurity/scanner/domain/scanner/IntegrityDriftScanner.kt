package com.mobilesecurity.scanner.domain.scanner

import com.mobilesecurity.scanner.domain.integrity.ChangeKind
import com.mobilesecurity.scanner.domain.integrity.IntegrityBaselineManager
import com.mobilesecurity.scanner.domain.integrity.IntegrityChange
import com.mobilesecurity.scanner.domain.model.*
import javax.inject.Inject

/**
 * Feeds Ist-vs-Soll integrity drift into the regular security scan as findings.
 *
 * On the very first run no trusted baseline exists yet, so this module captures
 * one and reports an informational note. On every subsequent run it reports each
 * deviation from that baseline as a finding.
 */
class IntegrityDriftScanner @Inject constructor(
    private val baselineManager: IntegrityBaselineManager
) {
    suspend fun scan(): List<VulnerabilityEntry> {
        if (!baselineManager.hasBaseline()) {
            baselineManager.captureAndStoreBaseline()
            return listOf(baselineEstablishedInfo())
        }

        val diff = baselineManager.compareWithBaseline()
        if (diff.changes.isEmpty()) return emptyList()

        return diff.changes.mapIndexed { index, change ->
            change.toVulnerability(index)
        }
    }

    private fun baselineEstablishedInfo(): VulnerabilityEntry = VulnerabilityEntry(
        id = "DRIFT-000",
        title = "Integrity baseline established",
        severity = Severity.INFO,
        cvssScore = 0.0f,
        affectedComponent = "Device integrity baseline",
        description = "A trusted snapshot of your device's security state (patch level, verified boot, " +
            "device admins, accessibility services, notification listeners and installed apps) was saved. " +
            "From now on every scan compares the current state against this baseline and flags any change.",
        impact = "No issue. This is the reference point used to detect future tampering.",
        remediation = RemediationSteps(
            priority = Priority.LOW,
            steps = listOf(
                "Do nothing – the baseline is now active.",
                "Re-capture the baseline in the 'Integrity' screen after a legitimate system update."
            ),
            automatable = false,
            estimatedTime = "-"
        ),
        source = "IntegrityDriftScanner"
    )

    private fun IntegrityChange.toVulnerability(index: Int): VulnerabilityEntry {
        val kindLabel = when (kind) {
            ChangeKind.ADDED -> "new"
            ChangeKind.REMOVED -> "removed"
            ChangeKind.CHANGED -> "changed"
        }
        val cvss = when (severity) {
            Severity.CRITICAL -> 9.3f
            Severity.HIGH -> 7.8f
            Severity.MEDIUM -> 5.5f
            Severity.LOW -> 3.0f
            Severity.INFO -> 0.0f
        }
        return VulnerabilityEntry(
            id = "DRIFT-%03d".format(index + 1),
            title = "Integrity drift: $category ($kindLabel)",
            severity = severity,
            cvssScore = cvss,
            affectedComponent = category,
            affectedApps = if (kind == ChangeKind.ADDED) listOf(detail) else emptyList(),
            description = "Change vs. trusted baseline in \"$category\": $detail.",
            impact = advice,
            remediation = RemediationSteps(
                priority = when (severity) {
                    Severity.CRITICAL -> Priority.IMMEDIATE
                    Severity.HIGH -> Priority.HIGH
                    else -> Priority.NORMAL
                },
                steps = listOf(
                    advice,
                    "If this change was caused by something you did knowingly, re-capture the baseline " +
                        "in the 'Integrity' screen to clear it."
                ),
                automatable = false,
                estimatedTime = "~5 min"
            ),
            source = "IntegrityDriftScanner"
        )
    }
}
