package com.mobilesecurity.scanner.domain.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.mobilesecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

/**
 * Modul 12: Backdoor-, Fernzugriff- und offene-Port-Erkennung.
 * Prueft das Geraet auf potenzielle Hintertüren, Remote-Access-Tools,
 * offene TCP-Ports und verdaechtige Fernzugriff-Indikatoren.
 */
class BackdoorScanner @Inject constructor(private val context: Context) {

    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()
        findings += checkOpenTcpPorts()
        findings += checkAdbOverTcp()
        findings += checkRemoteAccessApps()
        findings += checkSshServerIndicators()
        findings += checkReverseShellIndicators()
        findings += checkSuspiciousListeningSockets()
        findings.filterNotNull()
    }

    private fun readListenPorts(): Set<Int> {
        val listenPorts = mutableSetOf<Int>()
        for (procFile in listOf("/proc/net/tcp", "/proc/net/tcp6")) {
            try {
                File(procFile).bufferedReader().useLines { lines ->
                    lines.drop(1).forEach { line ->
                        val parts = line.trim().split("\\s+".toRegex())
                        if (parts.size >= 4 && parts[3] == "0A") {
                            val portHex = parts[1].substringAfterLast(":")
                            portHex.toIntOrNull(16)?.let { listenPorts.add(it) }
                        }
                    }
                }
            } catch (_: Exception) {}
        }
        return listenPorts
    }

    private fun checkOpenTcpPorts(): List<VulnerabilityEntry> {
        val findings = mutableListOf<VulnerabilityEntry>()
        val listenPorts = readListenPorts()

        val criticalPorts = mapOf(
            22 to "SSH-Server", 23 to "Telnet-Server",
            4444 to "Metasploit/Reverse-Shell", 5554 to "ADB Console",
            5556 to "ADB Console", 9999 to "Backdoor/Debug-Port",
            31337 to "Backdoor (Elite-Port)", 1337 to "Backdoor/Hacker-Port"
        )
        val highRiskPorts = mapOf(
            8080 to "HTTP-Proxy/Server", 8888 to "HTTP-Dev-Server",
            3333 to "Debug-Server", 6666 to "IRC/Backdoor", 7777 to "Remote-Debug-Port"
        )

        val foundCritical = listenPorts.filter { it in criticalPorts }
        val foundHighRisk = listenPorts.filter { it in highRiskPorts }

        if (foundCritical.isNotEmpty()) {
            val portDesc = foundCritical.joinToString { "$it (${criticalPorts[it]})" }
            findings += VulnerabilityEntry(
                id = "BACKDOOR-001",
                title = "Kritische Backdoor-Ports offen",
                severity = Severity.CRITICAL,
                cvssScore = 9.8f,
                affectedComponent = "Netzwerk/Sockets",
                description = "Kritische Ports mit Backdoor-Potential aktiv: $portDesc. " +
                    "Diese Ports koennen fuer unautorisierten Fernzugriff missbraucht werden.",
                impact = "Vollstaendiger Remote-Zugriff moeglich. Kapern von Bankdaten, PayPal, Passwoertern.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = listOf(
                        "Geraet sofort vom Netzwerk trennen",
                        "Vollstaendigen Scan auf Schadsoftware starten",
                        "Verdaechtige Apps deinstallieren",
                        "Alle Passwoerter von sicherem Geraet aendern"
                    ),
                    automatable = false, estimatedTime = "Sofortige Massnahme erforderlich"
                ),
                source = "BackdoorScanner", patchAvailable = false
            )
        }

        if (foundHighRisk.isNotEmpty()) {
            val portDesc = foundHighRisk.joinToString { "$it (${highRiskPorts[it]})" }
            findings += VulnerabilityEntry(
                id = "BACKDOOR-002",
                title = "Verdaechtige Netzwerkports aktiv",
                severity = Severity.HIGH,
                cvssScore = 7.5f,
                affectedComponent = "Netzwerk/Sockets",
                description = "Ungewoehnliche Netzwerkdienste lauschen auf Verbindungen: $portDesc.",
                impact = "Potenzielle Angriffsflaeche fuer Netzwerkangriffe und unbefugten Zugriff.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Server-Apps ueberpruefen und deinstallieren",
                        "Entwickleroptionen: ADB deaktivieren",
                        "Vollstaendigen Sicherheitsscan durchfuehren"
                    ),
                    automatable = false, estimatedTime = "30-60 Minuten"
                ),
                source = "BackdoorScanner"
            )
        }

        val systemPorts = setOf(53, 631, 5353)
        val allSuspicious = listenPorts.filter { it !in systemPorts }
        if (allSuspicious.size > 5) {
            findings += VulnerabilityEntry(
                id = "BACKDOOR-003",
                title = "Ungewoehnlich viele offene Ports",
                severity = Severity.MEDIUM,
                cvssScore = 5.3f,
                affectedComponent = "Netzwerk/Sockets",
                description = "${allSuspicious.size} TCP-Ports aktiv: ${allSuspicious.take(10).joinToString()}.",
                impact = "Erhoehtes Risiko fuer Netzwerkangriffe.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Nicht benoetigte Netzwerkdienste deinstallieren",
                        "Firewall-App installieren (z.B. NetGuard)"
                    ),
                    automatable = false, estimatedTime = "1-2 Stunden"
                ),
                source = "BackdoorScanner"
            )
        }

        return findings
    }

    private fun checkAdbOverTcp(): VulnerabilityEntry? {
        if (5555 !in readListenPorts()) return null
        return VulnerabilityEntry(
            id = "BACKDOOR-004",
            title = "ADB over TCP aktiv (Port 5555)",
            severity = Severity.CRITICAL,
            cvssScore = 9.1f,
            isActivelyExploited = true,
            affectedComponent = "Android Debug Bridge",
            description = "ADB ist ueber TCP/IP auf Port 5555 aktiv. Jeder im gleichen Netzwerk " +
                "kann ohne Authentifizierung vollen Shell-Zugriff erlangen.",
            impact = "Vollstaendiger Fernzugriff auf Geraet, alle Daten und Konten. " +
                "Banking-Apps und PayPal koennen kompromittiert werden.",
            remediation = RemediationSteps(
                priority = Priority.IMMEDIATE,
                steps = listOf(
                    "Einstellungen > Entwickleroptionen > WLAN-Debugging deaktivieren",
                    "Einstellungen > Entwickleroptionen > USB-Debugging deaktivieren",
                    "Geraet sofort vom WLAN trennen",
                    "Alle Passwoerter und 2FA-Codes erneuern"
                ),
                automatable = true,
                deepLinkSettings = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                estimatedTime = "Sofortige Massnahme erforderlich"
            ),
            source = "BackdoorScanner", patchAvailable = true
        )
    }

    private fun checkRemoteAccessApps(): VulnerabilityEntry? {
        val pm = context.packageManager
        val remoteAccessPackages = mapOf(
            "com.teamviewer.teamviewer" to "TeamViewer",
            "com.teamviewer.host" to "TeamViewer Host",
            "com.anydesk.anydeskandroid" to "AnyDesk",
            "com.realvnc.viewer.android" to "VNC Viewer",
            "net.christianbeier.droidvnc_ng" to "DroidVNC-NG Server",
            "com.airdroid.main" to "AirDroid",
            "com.airdroid" to "AirDroid",
            "com.mobizen.mobizen" to "Mobizen Screen Share",
            "com.rsupport.rckit" to "RemoteCall",
            "com.splashtop.remote.phone" to "Splashtop Remote",
            "org.connectbot" to "ConnectBot SSH",
            "com.lamerman.sshclient" to "SSH Client"
        )

        val installed = mutableListOf<String>()
        for ((pkg, name) in remoteAccessPackages) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0L))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(pkg, 0)
                }
                installed.add(name)
            } catch (_: PackageManager.NameNotFoundException) {}
        }
        if (installed.isEmpty()) return null

        return VulnerabilityEntry(
            id = "BACKDOOR-005",
            title = "Fernzugriff-Apps installiert",
            severity = Severity.HIGH,
            cvssScore = 7.8f,
            affectedComponent = "Installierte Apps / Remote-Access",
            description = "Fernzugriff-Apps gefunden: ${installed.joinToString()}. " +
                "Diese Apps ermoeglichen Dritten, das Geraet remote zu steuern.",
            impact = "Vollstaendiger Fernzugriff auf Geraet, Apps und gespeicherte Zugangsdaten.",
            remediation = RemediationSteps(
                priority = Priority.HIGH,
                steps = listOf(
                    "Ueberpruefen ob diese Apps bewusst installiert wurden",
                    "Nicht benoetigte Remote-Access-Apps deinstallieren",
                    "Berechtigungen der verbleibenden Apps einschraenken"
                ),
                automatable = false,
                deepLinkSettings = "android.settings.APPLICATION_SETTINGS",
                estimatedTime = "15-30 Minuten"
            ),
            affectedApps = installed,
            source = "BackdoorScanner"
        )
    }

    private fun checkSshServerIndicators(): VulnerabilityEntry? {
        val indicators = mutableListOf<String>()
        listOf(
            "/system/bin/sshd", "/system/xbin/sshd",
            "/system/bin/dropbear", "/system/xbin/dropbear",
            "/data/local/tmp/dropbear"
        ).filter { File(it).exists() }.forEach { indicators.add(it.substringAfterLast("/")) }
        listOf("/data/ssh/sshd_config", "/etc/ssh/sshd_config")
            .filter { File(it).exists() }.forEach { indicators.add("config:${it.substringAfterLast("/")}") }
        if (indicators.isEmpty()) return null

        return VulnerabilityEntry(
            id = "BACKDOOR-006",
            title = "SSH-Server auf Geraet gefunden",
            severity = Severity.CRITICAL,
            cvssScore = 9.0f,
            affectedComponent = "SSH / Fernzugriff-Dienste",
            description = "SSH-Server gefunden: ${indicators.joinToString()}. " +
                "SSH-Server auf Android sind ein Indikator fuer Root-Zugriff und unautorisierten Fernzugriff.",
            impact = "Vollstaendige Geraeteubernahme und Datenzugriff moeglich.",
            remediation = RemediationSteps(
                priority = Priority.IMMEDIATE,
                steps = listOf(
                    "SSH-Server-App sofort deinstallieren",
                    "Root-Zugriff ueberpruefen und widerrufen",
                    "Geraet auf Werkseinstellungen zuruecksetzen empfohlen"
                ),
                automatable = false, estimatedTime = "Sofortige Massnahme erforderlich"
            ),
            source = "BackdoorScanner", patchAvailable = false
        )
    }

    private fun checkReverseShellIndicators(): VulnerabilityEntry? {
        val indicators = mutableListOf<String>()
        listOf(
            "/system/bin/nc", "/system/xbin/nc",
            "/system/bin/netcat", "/system/xbin/netcat",
            "/system/bin/socat", "/system/xbin/socat",
            "/data/local/tmp/nc", "/data/local/tmp/socat"
        ).filter { File(it).exists() }.forEach { indicators.add(it.substringAfterLast("/")) }
        if (indicators.isEmpty()) return null

        return VulnerabilityEntry(
            id = "BACKDOOR-007",
            title = "Reverse-Shell-Tools gefunden",
            severity = Severity.HIGH,
            cvssScore = 8.1f,
            affectedComponent = "System-Binaries / Shell-Tools",
            description = "Tools fuer Reverse Shells gefunden: ${indicators.joinToString()}. " +
                "Werden haeufig fuer unautorisierten Fernzugriff missbraucht.",
            impact = "Angreifer koennen eine Verbindung zu einem externen Server aufbauen und das Geraet fernsteuern.",
            remediation = RemediationSteps(
                priority = Priority.HIGH,
                steps = listOf(
                    "Ueberpruefen ob durch Root-Manager installiert",
                    "Unnoetige Tools entfernen",
                    "Laufende Netzwerkverbindungen mit einem Monitor pruefen"
                ),
                automatable = false, estimatedTime = "30-60 Minuten"
            ),
            source = "BackdoorScanner"
        )
    }

    private fun checkSuspiciousListeningSockets(): VulnerabilityEntry? {
        val suspiciousSockets = mutableListOf<String>()
        try {
            File("/proc/net/unix").bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size >= 8) {
                        val state = parts[5]
                        val path = parts.getOrNull(7) ?: ""
                        if (state == "01" && path.isNotEmpty() && !path.startsWith("@")) {
                            if (path.contains("frida") || path.contains("inject") ||
                                path.contains("backdoor") || path.contains("shell") ||
                                path.contains("remote") || path.contains("debug")) {
                                suspiciousSockets.add(path)
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {}
        if (suspiciousSockets.isEmpty()) return null

        return VulnerabilityEntry(
            id = "BACKDOOR-008",
            title = "Verdaechtige UNIX-Sockets gefunden",
            severity = Severity.HIGH,
            cvssScore = 7.2f,
            affectedComponent = "Unix-Domain-Sockets",
            description = "Verdaechtige lauschende Unix-Sockets: ${suspiciousSockets.joinToString()}. " +
                "Koennen auf Instrumentation-Tools oder Backdoors hinweisen.",
            impact = "Moegliche Geraete-Instrumentierung durch externe Tools (Frida, Xposed).",
            remediation = RemediationSteps(
                priority = Priority.HIGH,
                steps = listOf(
                    "Prozesse identifizieren und beenden",
                    "Zugehoerige Apps deinstallieren",
                    "Vollstaendigen Malware-Scan durchfuehren"
                ),
                automatable = false, estimatedTime = "30 Minuten"
            ),
            source = "BackdoorScanner"
        )
    }
}
