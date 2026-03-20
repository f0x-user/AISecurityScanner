package com.aisecurity.scanner.domain.remediation

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import com.aisecurity.scanner.data.db.dao.RemediationLogDao
import com.aisecurity.scanner.data.db.entities.RemediationLogEntity
import com.aisecurity.scanner.domain.model.VulnerabilityEntry
import com.aisecurity.scanner.domain.snapshot.SnapshotManager
import com.aisecurity.scanner.domain.snapshot.SnapshotResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Auto-Remediation Engine
 *
 * Versucht erkannte Schwachstellen automatisch zu beheben oder leitet den
 * Nutzer zur korrekten Einstellungsseite weiter.
 *
 * Sicherheitsprinzipien:
 * - Vor jeder Schreiboperation wird ein Snapshot via SnapshotManager erstellt
 * - Root-Kommandos werden nur ausgeführt, wenn Root verifiziert vorhanden ist
 * - Alle Aktionen werden in der RemediationLog-Datenbank gespeichert
 * - Keine destruktiven Aktionen ohne explizite Nutzerbestätigung
 * - Wirkt AUSSCHLIESSLICH auf dem Ziel-Android-Gerät, nie auf dem Host-System
 */
@Singleton
class RemediationEngine @Inject constructor(
    private val context: Context,
    private val remediationLogDao: RemediationLogDao,
    private val snapshotManager: SnapshotManager
) {
    /**
     * Verarbeitet eine Liste von Schwachstellen und versucht automatable=true
     * Einträge zu beheben.
     *
     * @return Liste der Ergebnisse pro Schwachstelle
     */
    suspend fun remediateAll(
        vulnerabilities: List<VulnerabilityEntry>
    ): List<RemediationResult> = withContext(Dispatchers.IO) {
        val automatable = vulnerabilities.filter { it.remediation.automatable }
        automatable.map { vuln -> remediate(vuln) }
    }

    /**
     * Versucht eine einzelne Schwachstelle zu beheben.
     * Erstellt immer zuerst einen Snapshot, bevor eine Aktion ausgeführt wird.
     */
    suspend fun remediate(vuln: VulnerabilityEntry): RemediationResult =
        withContext(Dispatchers.IO) {
            val action = buildAction(vuln)

            // Snapshot vor der Aktion
            val snapshot: SnapshotResult = snapshotManager.createSnapshot(
                targetPath = action.settingsDeepLink ?: action.shellCommand ?: vuln.affectedComponent,
                reason = "Pre-Remediation: ${vuln.id} – ${vuln.title}"
            )

            val result = executeAction(action, snapshot)

            // Ergebnis in die Datenbank schreiben
            logToDatabase(result, snapshot.snapshotId)
            result
        }

    // -------------------------------------------------------------------------
    // Aktionsplanung
    // -------------------------------------------------------------------------

    private fun buildAction(vuln: VulnerabilityEntry): RemediationAction {
        val deepLink = vuln.remediation.deepLinkSettings

        return when {
            // Settings-DeepLink vorhanden → Nutzer zur richtigen Einstellungsseite leiten
            deepLink != null -> RemediationAction(
                vulnId = vuln.id,
                actionType = RemediationActionType.OPEN_SETTINGS,
                description = "Öffne Einstellungen: $deepLink",
                settingsDeepLink = deepLink,
                requiresRoot = false
            )

            // Kernel-Parameter via sysctl (Root erforderlich)
            vuln.id.startsWith("KRN-") -> buildKernelAction(vuln)

            // File-Permission-Probleme (Root erforderlich)
            vuln.id.startsWith("STR-") || vuln.id.startsWith("SYS-") ->
                buildFilePermissionAction(vuln)

            // Kein automatierbarer Ansatz gefunden
            else -> RemediationAction(
                vulnId = vuln.id,
                actionType = RemediationActionType.VIRTUAL_ONLY,
                description = "Keine automatische Behebung verfügbar – manuelle Korrektur erforderlich",
                requiresRoot = false
            )
        }
    }

    private fun buildKernelAction(vuln: VulnerabilityEntry): RemediationAction {
        // Abbildung bekannter KRN-IDs auf sichere Kernel-Parameter
        val sysctlCommand = when (vuln.id) {
            "KRN-002" -> "sysctl -w kernel.randomize_va_space=2"
            "KRN-003" -> "sysctl -w kernel.kptr_restrict=1"
            "KRN-004" -> "sysctl -w kernel.dmesg_restrict=1"
            "KRN-005" -> "sysctl -w kernel.perf_event_paranoid=2"
            "KRN-006" -> "sysctl -w kernel.sysrq=0"
            else -> null
        }

        return if (sysctlCommand != null) {
            RemediationAction(
                vulnId = vuln.id,
                actionType = RemediationActionType.SHELL_COMMAND,
                description = "Kernel-Parameter setzen: $sysctlCommand",
                shellCommand = sysctlCommand,
                requiresRoot = true
            )
        } else {
            RemediationAction(
                vulnId = vuln.id,
                actionType = RemediationActionType.VIRTUAL_ONLY,
                description = "Kernel-Hardening erfordert manuelle Eingriff – siehe Remediation-Schritte",
                requiresRoot = false
            )
        }
    }

    private fun buildFilePermissionAction(vuln: VulnerabilityEntry): RemediationAction {
        // Typische unsichere Dateiberechtigungen korrigieren
        val affectedPath = extractPathFromDescription(vuln.description)

        return if (affectedPath != null && isPathSafeToChmod(affectedPath)) {
            RemediationAction(
                vulnId = vuln.id,
                actionType = RemediationActionType.SHELL_COMMAND,
                description = "Dateiberechtigung sichern: chmod 600 $affectedPath",
                shellCommand = "chmod 600 $affectedPath",
                requiresRoot = true
            )
        } else {
            RemediationAction(
                vulnId = vuln.id,
                actionType = RemediationActionType.VIRTUAL_ONLY,
                description = "Manuelle Korrektur der Dateiberechtigungen erforderlich",
                requiresRoot = false
            )
        }
    }

    // -------------------------------------------------------------------------
    // Ausführung
    // -------------------------------------------------------------------------

    private fun executeAction(
        action: RemediationAction,
        snapshot: SnapshotResult
    ): RemediationResult {
        return when (action.actionType) {
            RemediationActionType.OPEN_SETTINGS -> {
                val launched = tryOpenSettings(action.settingsDeepLink!!)
                RemediationResult(
                    vulnId = action.vulnId,
                    success = launched,
                    actionDescription = action.description,
                    requiresManualIntervention = true,
                    errorMessage = if (!launched) "Settings-Intent konnte nicht gestartet werden" else null
                )
            }

            RemediationActionType.SHELL_COMMAND -> {
                if (!action.requiresRoot || isRootAvailable()) {
                    val shellResult = executeShellCommand(action.shellCommand!!)
                    RemediationResult(
                        vulnId = action.vulnId,
                        success = shellResult.isSuccess,
                        actionDescription = "${action.description} [Snapshot: ${snapshot.snapshotId}]",
                        errorMessage = if (!shellResult.isSuccess) shellResult.output else null
                    )
                } else {
                    RemediationResult(
                        vulnId = action.vulnId,
                        success = false,
                        actionDescription = action.description,
                        requiresManualIntervention = true,
                        errorMessage = "Root-Zugriff nicht verfügbar – manuelle Ausführung erforderlich"
                    )
                }
            }

            RemediationActionType.VIRTUAL_ONLY -> RemediationResult(
                vulnId = action.vulnId,
                success = false,
                actionDescription = action.description,
                requiresManualIntervention = true
            )
        }
    }

    private fun tryOpenSettings(deepLink: String): Boolean {
        return try {
            val intent = when {
                deepLink.startsWith("android.settings.") -> {
                    Intent(deepLink).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                }
                deepLink.startsWith("package:") -> {
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.parse(deepLink)
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                }
                else -> Intent(Settings.ACTION_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }
            context.startActivity(intent)
            true
        } catch (_: Exception) {
            false
        }
    }

    // -------------------------------------------------------------------------
    // Datenbank-Logging
    // -------------------------------------------------------------------------

    private suspend fun logToDatabase(result: RemediationResult, snapshotId: String) {
        try {
            remediationLogDao.insert(
                RemediationLogEntity(
                    vulnId = result.vulnId,
                    action = result.actionDescription,
                    timestamp = System.currentTimeMillis(),
                    success = result.success,
                    notes = buildNotes(result, snapshotId)
                )
            )
        } catch (_: Exception) {
            // Logging-Fehler sind nicht kritisch – Remediation-Ergebnis bleibt gültig
        }
    }

    private fun buildNotes(result: RemediationResult, snapshotId: String): String {
        return buildString {
            append("snapshotId=$snapshotId")
            if (result.requiresManualIntervention) append(" | manualRequired=true")
            result.errorMessage?.let { append(" | error=$it") }
        }
    }

    // -------------------------------------------------------------------------
    // Hilfsfunktionen
    // -------------------------------------------------------------------------

    private fun isRootAvailable(): Boolean = try {
        val result = executeShellCommand("id")
        result.isSuccess && result.output.contains("uid=0")
    } catch (_: Exception) {
        false
    }

    private fun executeShellCommand(command: String): ShellResult {
        return try {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            ShellResult(exitCode == 0, output.trim())
        } catch (e: Exception) {
            ShellResult(false, e.message ?: "Prozess konnte nicht gestartet werden")
        }
    }

    /**
     * Extrahiert einen Dateipfad aus der Schwachstellen-Beschreibung.
     * Sucht nach typischen Linux-Pfadmustern (beginnt mit /).
     */
    private fun extractPathFromDescription(description: String): String? {
        val pathRegex = Regex("""/[a-zA-Z0-9/_\-\.]+""")
        return pathRegex.find(description)?.value
    }

    /**
     * Sicherheitsprüfung: Verhindert chmod auf gefährliche Systempfade.
     * Nur explizit erlaubte Pfad-Präfixe werden akzeptiert.
     */
    private fun isPathSafeToChmod(path: String): Boolean {
        val safePrefixes = listOf(
            "/sdcard/",
            "/storage/",
            "/data/user/",
            "/data/data/${context.packageName}/"
        )
        val dangerousPrefixes = listOf(
            "/system/", "/proc/", "/sys/", "/dev/",
            "/bin/", "/sbin/", "/lib/", "/etc/"
        )
        val normalizedPath = File(path).canonicalPath
        if (dangerousPrefixes.any { normalizedPath.startsWith(it) }) return false
        return safePrefixes.any { normalizedPath.startsWith(it) }
    }

    private data class ShellResult(val isSuccess: Boolean, val output: String)
}
