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

    suspend fun startScan(depth: ScanDepth): ScanResult = coroutineScope {
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
        log("Scan gestartet (Modus: ${depth.label})")
        debugLogger.logSection("SCAN START  Modus: ${depth.label} | ID: $scanId")
        debugLogger.log("SecurityScanManager", "Scan-Tiefe: ${depth.label} (${depth.durationMinutes} min)")

        try {
            // Modul 1: Systeminfo
            updateProgress("Systeminfo wird analysiert...", 5)
            log("Modul 1/8: SystemInfoScanner [Tiefe: ${depth.label}]")
            debugLogger.logSection("Modul 1/8: SystemInfoScanner")
            val m1Start = System.currentTimeMillis()
            val systemFindings = systemInfoScanner.scan(depth)
            allVulnerabilities += systemFindings
            debugLogger.logTiming("SystemInfoScanner", "Dauer", System.currentTimeMillis() - m1Start)
            debugLogger.log("SystemInfoScanner", "${systemFindings.size} Befunde")
            systemFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${systemFindings.size} Befunde")
            updateProgress("Systeminfo abgeschlossen", 14)

            // Modul 2: App-Berechtigungen
            updateProgress("App-Berechtigungen werden geprueft...", 15)
            log("Modul 2/8: AppPermissionAuditor [Tiefe: ${depth.label}]")
            debugLogger.logSection("Modul 2/8: AppPermissionAuditor")
            val m2Start = System.currentTimeMillis()
            val (appFindings, audits) = appPermissionAuditor.scan(depth)
            allVulnerabilities += appFindings
            allAudits = audits
            debugLogger.logTiming("AppPermissionAuditor", "Dauer", System.currentTimeMillis() - m2Start)
            debugLogger.log("AppPermissionAuditor", "${appFindings.size} Befunde | ${audits.size} Apps analysiert")
            appFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${appFindings.size} Befunde, ${audits.size} Apps analysiert")
            updateProgress("App-Analyse abgeschlossen", 28)

            // Modul 3: Netzwerksicherheit
            updateProgress("Netzwerksicherheit wird analysiert...", 29)
            log("Modul 3/8: NetworkSecurityScanner [Tiefe: ${depth.label}]")
            debugLogger.logSection("Modul 3/8: NetworkSecurityScanner")
            val m3Start = System.currentTimeMillis()
            val networkFindings = networkSecurityScanner.scan(depth)
            allVulnerabilities += networkFindings
            debugLogger.logTiming("NetworkSecurityScanner", "Dauer", System.currentTimeMillis() - m3Start)
            debugLogger.log("NetworkSecurityScanner", "${networkFindings.size} Befunde")
            networkFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${networkFindings.size} Befunde")
            updateProgress("Netzwerkanalyse abgeschlossen", 42)

            // Modul 4: Geraetehärtung
            updateProgress("Geraetesicherheit wird geprueft...", 43)
            log("Modul 4/8: DeviceHardeningChecker [Tiefe: ${depth.label}]")
            debugLogger.logSection("Modul 4/8: DeviceHardeningChecker")
            val m4Start = System.currentTimeMillis()
            val hardeningFindings = deviceHardeningChecker.scan(depth)
            allVulnerabilities += hardeningFindings
            debugLogger.logTiming("DeviceHardeningChecker", "Dauer", System.currentTimeMillis() - m4Start)
            debugLogger.log("DeviceHardeningChecker", "${hardeningFindings.size} Befunde")
            hardeningFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${hardeningFindings.size} Befunde")
            updateProgress("Geraetehärtung abgeschlossen", 56)

            // Modul 5: Speichersicherheit
            updateProgress("Speicher wird analysiert...", 57)
            log("Modul 5/8: StorageSecurityScanner [Tiefe: ${depth.label}]")
            debugLogger.logSection("Modul 5/8: StorageSecurityScanner")
            val m5Start = System.currentTimeMillis()
            val storageFindings = storageSecurityScanner.scan(depth)
            allVulnerabilities += storageFindings
            debugLogger.logTiming("StorageSecurityScanner", "Dauer", System.currentTimeMillis() - m5Start)
            debugLogger.log("StorageSecurityScanner", "${storageFindings.size} Befunde")
            storageFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${storageFindings.size} Befunde")
            updateProgress("Speicheranalyse abgeschlossen", 70)

            // Modul 6: Zero-Day-Korrelation
            if (depth != ScanDepth.QUICK) {
                val minCvss = when (depth) { ScanDepth.STANDARD -> "7.0"; ScanDepth.DEEP -> "4.0"; else -> "0.1" }
                updateProgress("Zero-Day-Korrelation mit Online-Datenbanken...", 71)
                log("Modul 6/8: ZeroDayCorrelator [Tiefe: ${depth.label}, min. CVSS: $minCvss]")
                debugLogger.logSection("Modul 6/8: ZeroDayCorrelator (CVSS>=$minCvss)")
                val m6Start = System.currentTimeMillis()
                val zeroDayFindings = zeroDayCorrelator.correlate(depth)
                allVulnerabilities += zeroDayFindings
                debugLogger.logTiming("ZeroDayCorrelator", "Dauer", System.currentTimeMillis() - m6Start)
                debugLogger.log("ZeroDayCorrelator", "${zeroDayFindings.size} CVEs korreliert")
                zeroDayFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
                log("  ${zeroDayFindings.size} CVEs korreliert")
                updateProgress("Zero-Day-Korrelation abgeschlossen", 85)
            } else {
                log("Modul 6/8: ZeroDayCorrelator (uebersprungen - Quick Scan)")
                debugLogger.log("ZeroDayCorrelator", "Uebersprungen (Quick-Scan)")
                updateProgress("Zero-Day-Korrelation uebersprungen", 85)
            }

            // Modul 7: Malware-Indikatoren
            updateProgress("Malware-Indikatoren werden gesucht...", 86)
            log("Modul 7/8: MalwareIndicatorScanner [Tiefe: ${depth.label}]")
            debugLogger.logSection("Modul 7/8: MalwareIndicatorScanner")
            val m7Start = System.currentTimeMillis()
            val malwareFindings = malwareIndicatorScanner.scan(depth)
            allVulnerabilities += malwareFindings
            debugLogger.logTiming("MalwareIndicatorScanner", "Dauer", System.currentTimeMillis() - m7Start)
            debugLogger.log("MalwareIndicatorScanner", "${malwareFindings.size} Indikatoren")
            malwareFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
            log("  ${malwareFindings.size} Indikatoren gefunden")
            updateProgress("Malware-Scan abgeschlossen", 90)

            // Modul 8: Privatsphaere & Hardware-Sicherheit
            if (depth == ScanDepth.DEEP || depth == ScanDepth.FORENSIC) {
                val forensicSuffix = if (depth == ScanDepth.FORENSIC) ", Frida, Logcat" else ""
                updateProgress("Kamera, Mikrofon, Root$forensicSuffix werden geprueft...", 91)
                log("Modul 8/8: PrivacyHardwareScanner [Tiefe: ${depth.label}]")
                debugLogger.logSection("Modul 8/8: PrivacyHardwareScanner${if (depth == ScanDepth.FORENSIC) " + Forensik" else ""}")
                val m8Start = System.currentTimeMillis()
                val privacyFindings = privacyHardwareScanner.scan(depth)
                allVulnerabilities += privacyFindings
                debugLogger.logTiming("PrivacyHardwareScanner", "Dauer", System.currentTimeMillis() - m8Start)
                debugLogger.log("PrivacyHardwareScanner", "${privacyFindings.size} Befunde")
                privacyFindings.forEach { debugLogger.logFinding(it.id, it.severity.label, it.cvssScore, it.title) }
                log("  ${privacyFindings.size} Befunde")
                updateProgress("Privatsphaere-Scan abgeschlossen", 100)
            } else {
                log("Modul 8/8: PrivacyHardwareScanner (uebersprungen - ${depth.label} Scan)")
                debugLogger.log("PrivacyHardwareScanner", "Uebersprungen (${depth.label}-Scan)")
                updateProgress("Privatsphaere-Scan uebersprungen", 100)
            }

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
                scanDepth = depth,
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
