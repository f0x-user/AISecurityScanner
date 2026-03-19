package com.aisecurity.scanner.domain.scanner

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import com.aisecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import javax.inject.Inject

class NetworkSecurityScanner @Inject constructor(private val context: Context) {

    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()

        val portsToScan = listOf(21, 22, 23, 25, 80, 443, 3306, 5555, 8080, 8443, 9090, 27017)

        findings += checkWifiSecurity()
        findings += checkOpenPorts(portsToScan)
        findings += checkVpnStatus()
        findings += checkDnsOverHttps()
        findings += checkProxyConfiguration()
        findings += checkInsecureTlsSettings()
        findings += checkCaptivePortalDetection()

        findings.filterNotNull()
    }

    private fun checkWifiSecurity(): VulnerabilityEntry? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(network) ?: return null

        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null

        // SSID ermitteln: auf API 29+ über NetworkCapabilities.transportInfo (kein Standort nötig)
        val ssid: String = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val wifiInfo = caps.transportInfo as? android.net.wifi.WifiInfo
            val raw = wifiInfo?.ssid?.replace("\"", "") ?: return null
            if (raw == "<unknown ssid>" || raw.isBlank()) return null
            raw
        } else {
            val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            val raw = wifiManager.connectionInfo?.ssid?.replace("\"", "") ?: return null
            if (raw == "<unknown ssid>" || raw.isBlank()) return null
            raw
        }

        // Verschlüsselungstyp ermitteln
        // API 31+: WifiInfo.currentSecurityType (präzise, kein Scan nötig)
        // API 26–30: ScanResults (können leer sein → null → kein Befund)
        val capabilities: String? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val wifiInfo = caps.transportInfo as? android.net.wifi.WifiInfo
            // SECURITY_TYPE_OPEN=0, WEP=1, PSK=2(WPA2), EAP=3, SAE=4(WPA3), ...
            when (wifiInfo?.currentSecurityType) {
                0 -> ""            // offen
                1 -> "[WEP]"       // WEP
                2, 3 -> "[WPA2]"   // PSK / EAP (WPA2)
                else -> "[WPA3]"   // SAE und neuere = sicher
            }
        } else {
            val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
            try {
                // getScanResults benötigt ACCESS_FINE_LOCATION; ohne Berechtigung → leere Liste
                // Wir behandeln null/leer korrekt durch Rückgabe von null weiter unten.
                @SuppressLint("MissingPermission")
                @Suppress("DEPRECATION")
                wifiManager.scanResults?.firstOrNull { it.SSID == ssid }?.capabilities
            } catch (_: Exception) { null }
        }

        // Wenn Verschlüsselungstyp nicht bestimmbar → kein Befund (verhindert Falsch-Positive)
        if (capabilities == null) return null

        return when {
            capabilities.isEmpty() || (!capabilities.contains("WPA") && !capabilities.contains("WEP")) -> {
                VulnerabilityEntry(
                    id = "NET-001",
                    title = "Verbunden mit offenem WLAN ($ssid)",
                    severity = Severity.HIGH,
                    cvssScore = 8.1f,
                    cvssVector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    affectedComponent = "WLAN-Verbindung",
                    description = "Das aktive WLAN '$ssid' ist unverschlüsselt. " +
                            "Jeder im gleichen Netz kann den Datenverkehr mitlesen.",
                    impact = "Man-in-the-Middle-Angriffe, Session-Hijacking und Datendiebstahl möglich.",
                    remediation = RemediationSteps(
                        priority = Priority.IMMEDIATE,
                        steps = listOf(
                            "Trenne sofort die Verbindung mit diesem Netzwerk.",
                            "Nutze nur WPA2- oder WPA3-gesicherte Netzwerke.",
                            "Aktiviere ein VPN für öffentliche Netzwerke."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.WIFI_SETTINGS",
                        officialDocUrl = "https://support.google.com/android/answer/9075925",
                        estimatedTime = "~2 Minuten"
                    ),
                    source = "NetworkSecurityScanner"
                )
            }
            capabilities.contains("WEP") -> {
                VulnerabilityEntry(
                    id = "NET-002",
                    title = "WEP-gesichertes WLAN ($ssid) – veraltet und unsicher",
                    severity = Severity.HIGH,
                    cvssScore = 7.4f,
                    cvssVector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    affectedComponent = "WLAN-Verschlüsselung",
                    description = "WEP (Wired Equivalent Privacy) ist seit 2004 gebrochen und " +
                            "kann in Minuten entschlüsselt werden.",
                    impact = "Netzwerkverkehr kann leicht entschlüsselt und abgehört werden.",
                    remediation = RemediationSteps(
                        priority = Priority.HIGH,
                        steps = listOf(
                            "Wechsle zu einem WPA2- oder WPA3-geschützten Netzwerk.",
                            "Konfiguriere deinen Router auf WPA3 (empfohlen) oder WPA2."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.WIFI_SETTINGS",
                        officialDocUrl = "https://www.wi-fi.org/discover-wi-fi/security",
                        estimatedTime = "~5 Minuten (Router-Konfiguration)"
                    ),
                    source = "NetworkSecurityScanner"
                )
            }
            capabilities.contains("WPA") && !capabilities.contains("WPA2") && !capabilities.contains("WPA3") -> {
                VulnerabilityEntry(
                    id = "NET-003",
                    title = "WPA (TKIP) Netzwerk – anfällig für KRACK-Angriff ($ssid)",
                    severity = Severity.MEDIUM,
                    cvssScore = 5.9f,
                    cvssVector = "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    affectedComponent = "WLAN-Verschlüsselung",
                    description = "WPA mit TKIP ist anfällig für den KRACK-Angriff (CVE-2017-13077).",
                    impact = "Unter bestimmten Umständen kann der Verschlüsselungsschlüssel wiederhergestellt werden.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Aktualisiere deinen Router auf WPA2-AES oder WPA3.",
                            "Stelle sicher, dass TKIP deaktiviert ist."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.WIFI_SETTINGS",
                        officialDocUrl = "https://www.krackattacks.com/",
                        estimatedTime = "~10 Minuten"
                    ),
                    cveLinks = listOf("https://nvd.nist.gov/vuln/detail/CVE-2017-13077"),
                    source = "NetworkSecurityScanner"
                )
            }
            else -> null
        }
    }

    private fun checkVpnStatus(): VulnerabilityEntry? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networks = cm.allNetworks
        val hasVpn = networks.any { network ->
            cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
        // VPN-Nutzung ist gut – keine Schwachstelle, aber Info wenn kein VPN in öffentlichem Netz
        val isOnPublicWifi = run {
            val active = cm.activeNetwork ?: return@run false
            val caps = cm.getNetworkCapabilities(active) ?: return@run false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) // kein VPN aktiv
        }
        return if (!hasVpn && isOnPublicWifi) {
            VulnerabilityEntry(
                id = "NET-004",
                title = "Kein VPN aktiv in öffentlichem WLAN",
                severity = Severity.LOW,
                cvssScore = 3.1f,
                cvssVector = "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                affectedComponent = "VPN / Netzwerksicherheit",
                description = "Es ist kein VPN aktiv, obwohl das Gerät mit einem WLAN verbunden ist. " +
                        "In öffentlichen Netzwerken ist ein VPN empfohlen.",
                impact = "Datenverkehr ist für Netzwerkteilnehmer potenziell sichtbar.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Aktiviere ein vertrauenswürdiges VPN für öffentliche Netzwerke.",
                        "Empfehlenswerte VPNs: Mullvad, ProtonVPN (keine Werbung-VPNs nutzen)."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.VPN_SETTINGS",
                    officialDocUrl = "https://support.google.com/android/answer/2819517",
                    estimatedTime = "~5 Minuten"
                ),
                source = "NetworkSecurityScanner"
            )
        } else null
    }

    private fun checkProxyConfiguration(): VulnerabilityEntry? {
        val proxyHost = System.getProperty("http.proxyHost")
        val proxyPort = System.getProperty("http.proxyPort")
        return if (!proxyHost.isNullOrEmpty() && !proxyPort.isNullOrEmpty()) {
            VulnerabilityEntry(
                id = "NET-005",
                title = "Proxy-Konfiguration erkannt ($proxyHost:$proxyPort)",
                severity = Severity.MEDIUM,
                cvssScore = 5.4f,
                cvssVector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Netzwerk-Proxy",
                description = "Ein Netzwerk-Proxy ist konfiguriert. Dies kann auf ein " +
                        "Man-in-the-Middle-Setup hinweisen, das TLS-Traffic entschlüsselt.",
                impact = "HTTPS-Verbindungen könnten von einem Proxy entschlüsselt und überwacht werden.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Prüfe, ob der Proxy von dir oder deinem Unternehmen eingerichtet wurde.",
                        "Entferne den Proxy, falls nicht benötigt: Einstellungen → WLAN → Proxy",
                        "Prüfe auf unbekannte Zertifikate im Benutzer-Vertrauensspeicher."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.WIFI_SETTINGS",
                    officialDocUrl = "https://developer.android.com/training/articles/security-ssl",
                    estimatedTime = "~3 Minuten"
                ),
                source = "NetworkSecurityScanner"
            )
        } else null
    }

    private suspend fun checkOpenPorts(portsToCheck: List<Int>): List<VulnerabilityEntry> =
        withContext(Dispatchers.IO) {
            val openPorts = mutableListOf<Int>()

            for (port in portsToCheck) {
                try {
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress("127.0.0.1", port), 200)
                        openPorts += port
                    }
                } catch (e: Exception) {
                    // Port geschlossen – erwartet
                }
            }

            val results = mutableListOf<VulnerabilityEntry>()

            if (openPorts.contains(5555)) {
                results += VulnerabilityEntry(
                    id = "NET-006",
                    title = "ADB-Port 5555 offen (ADB over Network aktiv)",
                    severity = Severity.CRITICAL,
                    cvssScore = 9.8f,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    affectedComponent = "Android Debug Bridge (ADB)",
                    description = "ADB over Network ist aktiv (Port 5555 offen). " +
                            "Jedes Gerät im gleichen Netzwerk kann vollständige Shell-Kontrolle übernehmen.",
                    impact = "Vollständige Gerätekontrolle ohne Passwort für jeden Netzwerkteilnehmer.",
                    remediation = RemediationSteps(
                        priority = Priority.IMMEDIATE,
                        steps = listOf(
                            "Deaktiviere ADB over Network sofort.",
                            "Navigiere zu: Einstellungen → Entwickleroptionen → ADB über Netzwerk",
                            "Wenn du keine Entwickleroptionen eingerichtet hast, prüfe auf Malware."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                        officialDocUrl = "https://developer.android.com/studio/command-line/adb",
                        estimatedTime = "~1 Minute"
                    ),
                    source = "NetworkSecurityScanner"
                )
            }

            // Weitere offene Ports melden (22=SSH, 23=Telnet, 21=FTP, 25=SMTP, 3306=MySQL, 27017=MongoDB)
            val criticalServicePorts = mapOf(
                22 to "SSH-Server aktiv (Port 22)",
                23 to "Telnet-Server aktiv (Port 23) – unverschlüsselt",
                21 to "FTP-Server aktiv (Port 21) – unverschlüsselt",
                25 to "SMTP-Server aktiv (Port 25)",
                3306 to "MySQL-Datenbankserver offen (Port 3306)",
                27017 to "MongoDB-Datenbankserver offen (Port 27017)",
                9090 to "Verdächtiger Management-Port offen (Port 9090)"
            )

            val suspiciousOpenPorts = openPorts.filter { it != 5555 && it in criticalServicePorts }
            if (suspiciousOpenPorts.isNotEmpty()) {
                results += VulnerabilityEntry(
                    id = "NET-008",
                    title = "${suspiciousOpenPorts.size} unerwartete offene Service-Port(s): ${suspiciousOpenPorts.joinToString()}",
                    severity = Severity.HIGH,
                    cvssScore = 7.3f,
                    cvssVector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    affectedComponent = "Netzwerk-Services",
                    description = "Unerwartete Netzwerkdienste laufen auf dem Gerät: " +
                            suspiciousOpenPorts.joinToString { criticalServicePorts[it] ?: "Port $it" } + ". " +
                            "Diese könnten durch Malware oder unbekannte Apps geöffnet worden sein.",
                    impact = "Angreifer im selben Netzwerk können diese Dienste missbrauchen.",
                    remediation = RemediationSteps(
                        priority = Priority.HIGH,
                        steps = listOf(
                            "Identifiziere welche App die Ports öffnet.",
                            "Nutze: Einstellungen → Apps → nach Netzwerkberechtigung filtern",
                            "Deinstalliere unbekannte Apps, die Serverdienste betreiben."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.APPLICATION_SETTINGS",
                        officialDocUrl = "https://developer.android.com/training/articles/security-tips",
                        estimatedTime = "~10 Minuten"
                    ),
                    source = "NetworkSecurityScanner"
                )
            }

            results
        }

    private fun checkDnsOverHttps(): VulnerabilityEntry? {
        // DNS-over-HTTPS ist ab Android 9 verfügbar (Private DNS)
        val privateDnsSetting = try {
            android.provider.Settings.Global.getString(
                context.contentResolver,
                "private_dns_mode"
            )
        } catch (e: Exception) {
            null
        }

        return if (Build.VERSION.SDK_INT >= 28 &&
            (privateDnsSetting == null || privateDnsSetting == "off")
        ) {
            VulnerabilityEntry(
                id = "NET-007",
                title = "DNS-over-HTTPS (Privates DNS) nicht aktiviert",
                severity = Severity.LOW,
                cvssScore = 3.7f,
                cvssVector = "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                affectedComponent = "DNS-Auflösung",
                description = "DNS-Anfragen werden unverschlüsselt gesendet und können " +
                        "von Netzwerkteilnehmern überwacht werden (DNS Snooping).",
                impact = "Besuchte Domains können von Netzwerkbetreibern protokolliert werden.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Aktiviere Privates DNS: Einstellungen → Netzwerk → Privates DNS",
                        "Empfohlene Server: dns.google, cloudflare-dns.com oder 1dot1dot1dot1.cloudflare-dns.com"
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.PRIVATE_DNS_SETTINGS",
                    officialDocUrl = "https://support.google.com/android/answer/9089903",
                    estimatedTime = "~2 Minuten"
                ),
                source = "NetworkSecurityScanner"
            )
        } else null
    }


    private fun checkInsecureTlsSettings(): VulnerabilityEntry? {
        // Prüfe ob schwache TLS-Version (SSLv3/TLS 1.0) noch systemweit erlaubt ist
        val secureSocketFactory = try {
            val sslContext = javax.net.ssl.SSLContext.getDefault()
            sslContext.supportedSSLParameters.protocols.toList()
        } catch (e: Exception) {
            return null
        }
        val hasWeakProtocols = secureSocketFactory.any { it in listOf("SSLv3", "TLSv1", "TLSv1.1") }
        return if (hasWeakProtocols) {
            VulnerabilityEntry(
                id = "NET-009",
                title = "Schwache TLS-Versionen unterstützt (SSLv3/TLS 1.0/1.1)",
                severity = Severity.MEDIUM,
                cvssScore = 5.9f,
                cvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "TLS/SSL Implementierung",
                description = "Das System unterstützt noch veraltete TLS-Protokolle: " +
                        "${secureSocketFactory.filter { it in listOf("SSLv3", "TLSv1", "TLSv1.1") }.joinToString()}. " +
                        "Diese sind anfällig für POODLE, BEAST und andere Downgrade-Angriffe.",
                impact = "TLS-Verbindungen können zu unsicheren Versionen herabgestuft werden.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Prüfe ob Apps das System-TLS nutzen oder eigene Implementierungen verwenden.",
                        "Nutze nur TLS 1.2 oder TLS 1.3 für alle Verbindungen.",
                        "Systemupdates können die Standard-TLS-Konfiguration verbessern."
                    ),
                    automatable = false,
                    officialDocUrl = "https://developer.android.com/training/articles/security-ssl",
                    estimatedTime = "~5 Minuten"
                ),
                cveLinks = listOf("https://nvd.nist.gov/vuln/detail/CVE-2014-3566"),
                source = "NetworkSecurityScanner"
            )
        } else null
    }

    private fun checkCaptivePortalDetection(): VulnerabilityEntry? {
        val captivePortalMode = try {
            android.provider.Settings.Global.getInt(
                context.contentResolver,
                "captive_portal_mode",
                1
            )
        } catch (e: Exception) {
            return null
        }
        return if (captivePortalMode == 0) {
            VulnerabilityEntry(
                id = "NET-010",
                title = "Captive-Portal-Erkennung deaktiviert",
                severity = Severity.LOW,
                cvssScore = 2.9f,
                cvssVector = "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                affectedComponent = "Netzwerk-Verbindungsprüfung",
                description = "Die automatische Captive-Portal-Erkennung ist deaktiviert. " +
                        "Dies ist ein Indikator dafür, dass jemand Netzwerkanalyse-Tools oder " +
                        "einen MITM-Proxy eingerichtet hat.",
                impact = "Verbindungen zu unsicheren Netzwerken werden möglicherweise nicht erkannt.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Aktiviere die Captive-Portal-Erkennung wieder.",
                        "Prüfe ob eine Security-App diese Einstellung deaktiviert hat.",
                        "Setze: adb shell settings put global captive_portal_mode 1"
                    ),
                    automatable = false,
                    officialDocUrl = "https://source.android.com/docs/core/connect/network-connectivity",
                    estimatedTime = "~2 Minuten"
                ),
                source = "NetworkSecurityScanner"
            )
        } else null
    }
}
