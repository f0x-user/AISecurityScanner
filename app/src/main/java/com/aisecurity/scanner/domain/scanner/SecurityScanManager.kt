package com.aisecurity.scanner.domain.scanner

import com.aisecurity.scanner.domain.model.*
import com.aisecurity.scanner.util.DebugLogger
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.Instant
import java.util.UUID
import javax.inject.Inject
import kotlin.math.max

class SecurityScanManager @Inject constructor(
    private val systemInfoScanner: SystemInfoScanner,
    private val appPermissionAuditor: AppPermissionAuditor,
    private val networkSecurityScanner: NetworkSecurityScanner,
    private val deviceHardeningChecker: DeviceHardeningChecker,
    private val storageSecurityScanner: StorageSecurityScanner,
    private val zeroDayCorrelator: ZeroDayCorrelator,
    private val malwareIndicatorScanner: MalwareIndicatorScanner,
    private val privacyHardwareScanner: PrivacyHardwareScanner,
    private val debugLogger: DebugLogger
) {
    private val _progress = MutableStateFlow(ScanProgress())
    val progress: StateFlow<ScanProgress> = _progress.asStateFlow()

    private var scanJob: Job? = null

    suspend fun startScan(): ScanResult = coroutineScope {
        val startTime = System.currentTimeMillis()
        val scanId = UUID.randomUUID().toString()
        val allVulnerabilities = mutableListOf<VulnerabilityEntry>()
        var allAudits = listOf<AppAudit>()
        val logLines = mutableListOf<String>()

        fun log(message: String) {
            logLines += "[${java.time.LocalTime.now().toString().take(8)}] $message"
            _progress.value = _progress.value.copy(logLines = logLines.toList())
        }

        fun updateProgress(module: String, percent: Int) {
            _progress.value = ScanProgress(
                status = ScanStatus.RUNNING,
                currentModule = module,
                progressPercent = percent,
                logLines = logLines.toList()
            )
        }

        _progress.value = ScanProgress(status = ScanStatus.RUNNING, progressPercent = 0)
        log("Vollständiger Sicherheitsscan gestartet")
        debugLogger.logSection("SCAN START | ID: $scanId")

        try {
            // Modul 1: Systeminfo
            updateProgress("Systeminfo wird analysiert...", 5)
            log("Modul 1/8: SystemInfoScanner")
            debugLogger.logSection("Modul 1/8: SystemInfoScanner")
            val m1Start = System.currentTimeMillis()
            val systemFindings = systemInfoScanner.scan(ScanDepth.FORENSIC)
            allVulnerabilities += systemFindings
            debugLogger.logTiming("SystemInfoScanner", "Dauer", System.currentTimeMillis() - m1Start)
            debugLogger.log("SystemInfoScanner", "${systemFindings.size} Befunde")
            systemFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${systemFindings.size} Befunde")
            updateProgress("Systeminfo abgeschlossen", 14)

            // Modul 2: App-Berechtigungen
            updateProgress("App-Berechtigungen werden geprueft...", 15)
            log("Modul 2/8: AppPermissionAuditor")
            debugLogger.logSection("Modul 2/8: AppPermissionAuditor")
            val m2Start = System.currentTimeMillis()
            val (appFindings, audits) = appPermissionAuditor.scan()
            allVulnerabilities += appFindings
            allAudits = audits
            debugLogger.logTiming("AppPermissionAuditor", "Dauer", System.currentTimeMillis() - m2Start)
            debugLogger.log("AppPermissionAuditor", "${appFindings.size} Befunde | ${audits.size} Apps analysiert")
            appFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${appFindings.size} Befunde, ${audits.size} Apps analysiert")
            updateProgress("App-Analyse abgeschlossen", 28)

            // Modul 3: Netzwerksicherheit
            updateProgress("Netzwerksicherheit wird analysiert...", 29)
            log("Modul 3/8: NetworkSecurityScanner")
            debugLogger.logSection("Modul 3/8: NetworkSecurityScanner")
            val m3Start = System.currentTimeMillis()
            val networkFindings = networkSecurityScanner.scan(ScanDepth.FORENSIC)
            allVulnerabilities += networkFindings
            debugLogger.logTiming("NetworkSecurityScanner", "Dauer", System.currentTimeMillis() - m3Start)
            debugLogger.log("NetworkSecurityScanner", "${networkFindings.size} Befunde")
            networkFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${networkFindings.size} Befunde")
            updateProgress("Netzwerkanalyse abgeschlossen", 42)

            // Modul 4: Geraetehärtung
            updateProgress("Geraetesicherheit wird geprueft...", 43)
            log("Modul 4/8: DeviceHardeningChecker")
            debugLogger.logSection("Modul 4/8: DeviceHardeningChecker")
            val m4Start = System.currentTimeMillis()
            val hardeningFindings = deviceHardeningChecker.scan(ScanDepth.FORENSIC)
            allVulnerabilities += hardeningFindings
            debugLogger.logTiming("DeviceHardeningChecker", "Dauer", System.currentTimeMillis() - m4Start)
            debugLogger.log("DeviceHardeningChecker", "${hardeningFindings.size} Befunde")
            hardeningFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${hardeningFindings.size} Befunde")
            updateProgress("Geraetehärtung abgeschlossen", 56)

            // Modul 5: Speichersicherheit
            updateProgress("Speicher wird analysiert...", 57)
            log("Modul 5/8: StorageSecurityScanner")
            debugLogger.logSection("Modul 5/8: StorageSecurityScanner")
            val m5Start = System.currentTimeMillis()
            val storageFindings = storageSecurityScanner.scan(ScanDepth.FORENSIC)
            allVulnerabilities += storageFindings
            debugLogger.logTiming("StorageSecurityScanner", "Dauer", System.currentTimeMillis() - m5Start)
            debugLogger.log("StorageSecurityScanner", "${storageFindings.size} Befunde")
            storageFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${storageFindings.size} Befunde")
            updateProgress("Speicheranalyse abgeschlossen", 70)

            // Modul 6: Zero-Day-Korrelation (alle CVEs)
            updateProgress("Zero-Day-Korrelation mit Online-Datenbanken...", 71)
            log("Modul 6/8: ZeroDayCorrelator")
            debugLogger.logSection("Modul 6/8: ZeroDayCorrelator (alle CVEs)")
            val m6Start = System.currentTimeMillis()
            val zeroDayFindings = zeroDayCorrelator.correlate(ScanDepth.FORENSIC)
            allVulnerabilities += zeroDayFindings
            debugLogger.logTiming("ZeroDayCorrelator", "Dauer", System.currentTimeMillis() - m6Start)
            debugLogger.log("ZeroDayCorrelator", "${zeroDayFindings.size} CVEs korreliert")
            zeroDayFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${zeroDayFindings.size} CVEs korreliert")
            updateProgress("Zero-Day-Korrelation abgeschlossen", 85)

            // Modul 7: Malware-Indikatoren
            updateProgress("Malware-Indikatoren werden gesucht...", 86)
            log("Modul 7/8: MalwareIndicatorScanner")
            debugLogger.logSection("Modul 7/8: MalwareIndicatorScanner")
            val m7Start = System.currentTimeMillis()
            val malwareFindings = malwareIndicatorScanner.scan(ScanDepth.FORENSIC)
            allVulnerabilities += malwareFindings
            debugLogger.logTiming("MalwareIndicatorScanner", "Dauer", System.currentTimeMillis() - m7Start)
            debugLogger.log("MalwareIndicatorScanner", "${malwareFindings.size} Indikatoren")
            malwareFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${malwareFindings.size} Indikatoren gefunden")
            updateProgress("Malware-Scan abgeschlossen", 90)

            // Modul 8: Privatsphaere & Hardware-Sicherheit
            updateProgress("Kamera, Mikrofon, Root, Frida, Logcat werden geprueft...", 91)
            log("Modul 8/8: PrivacyHardwareScanner")
            debugLogger.logSection("Modul 8/8: PrivacyHardwareScanner + Forensik")
            val m8Start = System.currentTimeMillis()
            val privacyFindings = privacyHardwareScanner.scan(ScanDepth.FORENSIC)
            allVulnerabilities += privacyFindings
            debugLogger.logTiming("PrivacyHardwareScanner", "Dauer", System.currentTimeMillis() - m8Start)
            debugLogger.log("PrivacyHardwareScanner", "${privacyFindings.size} Befunde")
            privacyFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${privacyFindings.size} Befunde")
            updateProgress("Scan abgeschlossen", 100)

            val durationMs = System.currentTimeMillis() - startTime
            val score = calculateSecurityScore(allVulnerabilities)

            log("Scan abgeschlossen in ${durationMs / 1000}s - Score: $score/100")
            debugLogger.logSection("SCAN ABGESCHLOSSEN")
            debugLogger.log("SecurityScanManager", "Gesamtdauer  : ${durationMs}ms")
            debugLogger.log("SecurityScanManager", "Sicherheits-Score: $score/100")
            debugLogger.log("SecurityScanManager", "Gesamt-Befunde   : ${allVulnerabilities.size}")
            debugLogger.log("SecurityScanManager", "  KRITISCH : ${allVulnerabilities.count { it.severity.name == "CRITICAL" }}")
            debugLogger.log("SecurityScanManager", "  HOCH     : ${allVulnerabilities.count { it.severity.name == "HIGH" }}")
            debugLogger.log("SecurityScanManager", "  MITTEL   : ${allVulnerabilities.count { it.severity.name == "MEDIUM" }}")
            debugLogger.log("SecurityScanManager", "  NIEDRIG  : ${allVulnerabilities.count { it.severity.name == "LOW" }}")

            val result = ScanResult(
                id = scanId,
                timestamp = Instant.now(),
                overallScore = score,
                scanDepth = ScanDepth.FORENSIC,
                durationMs = durationMs,
                vulnerabilities = allVulnerabilities.sortedWith(
                    compareBy({ it.severity.order }, { -it.cvssScore })
                ),
                appAudits = allAudits
            )

            _progress.value = ScanProgress(
                status = ScanStatus.COMPLETED,
                progressPercent = 100,
                logLines = logLines.toList()
            )
            result

        } catch (e: CancellationException) {
            debugLogger.logWarn("SecurityScanManager", "Scan abgebrochen vom Benutzer")
            _progress.value = ScanProgress(
                status = ScanStatus.CANCELLED,
                logLines = logLines.toList()
            )
            throw e
        } catch (e: Exception) {
            log("Fehler: ${e.message}")
            debugLogger.logError("SecurityScanManager", "Scan fehlgeschlagen: ${e.message}", e)
            _progress.value = ScanProgress(
                status = ScanStatus.FAILED,
                logLines = logLines.toList(),
                error = e.message
            )
            throw e
        }
    }

    fun cancelScan() {
        scanJob?.cancel()
        _progress.value = ScanProgress(status = ScanStatus.CANCELLED)
    }

    /**
     * Sicherheits-Score: 100 = perfekt, 0 = kritisch
     * Gewichtung nach CVSS-Score-Schweregrad
     */
    private fun calculateSecurityScore(vulnerabilities: List<VulnerabilityEntry>): Int {
        if (vulnerabilities.isEmpty()) return 100

        val penalty = vulnerabilities.sumOf { vuln ->
            val basePenalty = when (vuln.severity) {
                Severity.CRITICAL -> 25
                Severity.HIGH -> 15
                Severity.MEDIUM -> 7
                Severity.LOW -> 3
                Severity.INFO -> 0
            }
            val exploitMultiplier = if (vuln.isActivelyExploited) 1.5 else 1.0
            val zeroDayMultiplier = if (vuln.isZeroDay) 1.3 else 1.0
            (basePenalty * exploitMultiplier * zeroDayMultiplier).toInt()
        }

        return max(0, 100 - penalty)
    }
}
