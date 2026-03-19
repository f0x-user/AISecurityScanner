package com.aisecurity.scanner.domain.scanner

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import com.aisecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

class SystemInfoScanner @Inject constructor(private val context: Context) {

    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()

        findings += checkAndroidVersion()
        findings += checkSecurityPatchLevel()
        findings += checkSELinuxMode()
        findings += checkEncryptionStatus()
        findings += checkVerifiedBootState()
        findings += checkKernelVersion()
        findings += checkBootloaderLockStatus()
        findings += checkBuildIntegrity()
        findings += checkSystemPartitionMounts()

        findings.filterNotNull()
    }

    private fun checkAndroidVersion(): VulnerabilityEntry? {
        val apiLevel = Build.VERSION.SDK_INT
        // Android < 10 (API 29) erhält keine Sicherheitsupdates mehr
        if (apiLevel < 29) {
            return VulnerabilityEntry(
                id = "SYS-001",
                title = "Veraltete Android-Version (API $apiLevel / Android ${Build.VERSION.RELEASE})",
                severity = Severity.CRITICAL,
                cvssScore = 9.8f,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                isZeroDay = false,
                isActivelyExploited = false,
                affectedComponent = "Android OS",
                description = "Das Gerät läuft auf Android ${Build.VERSION.RELEASE} (API $apiLevel), " +
                        "das keine Sicherheitsupdates mehr von Google erhält. " +
                        "Hunderte bekannte Schwachstellen sind dauerhaft ungepatcht.",
                impact = "Alle bekannten Android-Exploits für diese Version sind permanent anwendbar. " +
                        "Angreifer können Gerätedaten stehlen, Malware installieren und Konten übernehmen.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = listOf(
                        "Prüfe, ob dein Hersteller ein Android-Update anbietet.",
                        "Navigiere zu: Einstellungen → Über das Telefon → Systemaktualisierung",
                        "Falls kein Update verfügbar: Gerätewechsel dringend empfohlen.",
                        "Minimiere bis dahin die Nutzung sensibler Dienste (Banking, etc.)."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.SYSTEM_UPDATE_SETTINGS",
                    officialDocUrl = "https://support.google.com/android/answer/3094712",
                    estimatedTime = "~5 Minuten (Update) oder Gerätewechsel"
                ),
                cveLinks = listOf("https://nvd.nist.gov/vuln/search/results?query=android+${Build.VERSION.RELEASE}"),
                patchAvailable = false,
                source = "SystemInfoScanner"
            )
        }
        return null
    }

    private fun checkSecurityPatchLevel(): VulnerabilityEntry? {
        val patchLevel = Build.VERSION.SECURITY_PATCH // Format: "YYYY-MM-DD"
        if (patchLevel.isEmpty()) return null

        return try {
            val parts = patchLevel.split("-")
            if (parts.size != 3) return null
            val year = parts[0].toInt()
            val month = parts[1].toInt()

            val currentYear = java.time.LocalDate.now().year
            val currentMonth = java.time.LocalDate.now().monthValue
            val monthsDiff = (currentYear - year) * 12 + (currentMonth - month)

            when {
                monthsDiff >= 12 -> VulnerabilityEntry(
                    id = "SYS-002-CRITICAL",
                    title = "Sicherheitspatch über 12 Monate veraltet ($patchLevel)",
                    severity = Severity.CRITICAL,
                    cvssScore = 9.1f,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    affectedComponent = "Android Security Patches",
                    description = "Der letzte Sicherheitspatch ist $monthsDiff Monate alt. " +
                            "Zahlreiche kritische Schwachstellen sind ungepatcht.",
                    impact = "Aktiv ausgenutzte Schwachstellen (CVEs) aus den vergangenen Monaten sind angreifbar.",
                    remediation = RemediationSteps(
                        priority = Priority.IMMEDIATE,
                        steps = listOf(
                            "Öffne Einstellungen → Sicherheit → Sicherheitsupdates",
                            "Installiere alle verfügbaren Updates sofort.",
                            "Kontaktiere deinen Gerätehersteller, falls kein Update bereitsteht."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.SECURITY_SETTINGS",
                        officialDocUrl = "https://source.android.com/docs/security/bulletin",
                        estimatedTime = "~15 Minuten"
                    ),
                    source = "SystemInfoScanner"
                )
                monthsDiff >= 6 -> VulnerabilityEntry(
                    id = "SYS-002-HIGH",
                    title = "Sicherheitspatch 6+ Monate veraltet ($patchLevel)",
                    severity = Severity.HIGH,
                    cvssScore = 7.5f,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    affectedComponent = "Android Security Patches",
                    description = "Sicherheitspatch ist $monthsDiff Monate alt.",
                    impact = "Mehrere bekannte Schwachstellen sind potenziell ausnutzbar.",
                    remediation = RemediationSteps(
                        priority = Priority.HIGH,
                        steps = listOf(
                            "Prüfe auf verfügbare Sicherheitsupdates in den Einstellungen.",
                            "Installiere Updates über Einstellungen → System → Systemaktualisierung."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.SYSTEM_UPDATE_SETTINGS",
                        officialDocUrl = "https://source.android.com/docs/security/bulletin",
                        estimatedTime = "~10 Minuten"
                    ),
                    source = "SystemInfoScanner"
                )
                monthsDiff >= 3 -> VulnerabilityEntry(
                    id = "SYS-002-MEDIUM",
                    title = "Sicherheitspatch 3+ Monate veraltet ($patchLevel)",
                    severity = Severity.MEDIUM,
                    cvssScore = 5.3f,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    affectedComponent = "Android Security Patches",
                    description = "Sicherheitspatch ist $monthsDiff Monate alt.",
                    impact = "Einige Schwachstellen sind ungepatcht.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf("Installiere verfügbare Sicherheitsupdates."),
                        automatable = false,
                        deepLinkSettings = "android.settings.SYSTEM_UPDATE_SETTINGS",
                        officialDocUrl = "https://source.android.com/docs/security/bulletin",
                        estimatedTime = "~10 Minuten"
                    ),
                    source = "SystemInfoScanner"
                )
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun checkSELinuxMode(): VulnerabilityEntry? {
        return try {
            val selinuxStatus = File("/sys/fs/selinux/enforce").readText().trim()
            if (selinuxStatus == "0") {
                VulnerabilityEntry(
                    id = "SYS-003",
                    title = "SELinux ist im Permissive-Modus",
                    severity = Severity.CRITICAL,
                    cvssScore = 9.3f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                    affectedComponent = "SELinux / Mandatory Access Control",
                    description = "SELinux läuft im Permissive-Modus statt im Enforcing-Modus. " +
                            "Dies bedeutet, dass alle Sicherheitsregeln nur protokolliert, aber nicht durchgesetzt werden.",
                    impact = "Apps können auf Systemressourcen zugreifen, die normalerweise blockiert wären. " +
                            "Privilege Escalation deutlich erleichtert.",
                    remediation = RemediationSteps(
                        priority = Priority.IMMEDIATE,
                        steps = listOf(
                            "SELinux Permissive-Modus ist ein starkes Indiz für ein gerootetes Gerät.",
                            "Prüfe, ob du dein Gerät nicht absichtlich gerootet hast.",
                            "Factory Reset empfohlen, wenn Manipulation nicht von dir durchgeführt wurde."
                        ),
                        automatable = false,
                        officialDocUrl = "https://source.android.com/docs/security/features/selinux",
                        estimatedTime = "~30 Minuten (Factory Reset)"
                    ),
                    source = "SystemInfoScanner"
                )
            } else null
        } catch (e: Exception) {
            null // Datei nicht lesbar – normaler Zustand ohne Root
        }
    }

    private fun checkEncryptionStatus(): VulnerabilityEntry? {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val encryptionStatus = dpm.storageEncryptionStatus
        return if (encryptionStatus == DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE ||
            encryptionStatus == DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED
        ) {
            VulnerabilityEntry(
                id = "SYS-004",
                title = "Gerätespeicher nicht verschlüsselt",
                severity = Severity.HIGH,
                cvssScore = 7.8f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "Gerätespeicher-Verschlüsselung",
                description = "Der interne Gerätespeicher ist nicht verschlüsselt. " +
                        "Bei physischem Zugriff können alle Daten direkt ausgelesen werden.",
                impact = "Vollständige Datenkompromittierung bei Gerätediebstahl oder Verlust.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Navigiere zu: Einstellungen → Sicherheit → Verschlüsselung",
                        "Aktiviere die vollständige Geräteverschlüsselung.",
                        "Hinweis: Dieser Vorgang kann 1-2 Stunden dauern. Gerät vorher aufladen."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.SECURITY_SETTINGS",
                    officialDocUrl = "https://source.android.com/docs/security/features/encryption",
                    estimatedTime = "~2 Stunden"
                ),
                source = "SystemInfoScanner"
            )
        } else null
    }

    private fun checkVerifiedBootState(): VulnerabilityEntry? {
        val verifiedBootState = getSystemProperty("ro.boot.verifiedbootstate")
        return if (verifiedBootState == "orange" || verifiedBootState == "red") {
            VulnerabilityEntry(
                id = "SYS-005",
                title = "Verified Boot deaktiviert oder fehlgeschlagen (Status: $verifiedBootState)",
                severity = if (verifiedBootState == "red") Severity.CRITICAL else Severity.HIGH,
                cvssScore = if (verifiedBootState == "red") 9.0f else 7.5f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "Android Verified Boot (AVB)",
                description = "Verified Boot-Status ist '$verifiedBootState'. " +
                        "Dies weist auf einen entsperrten Bootloader oder manipuliertes System-Image hin.",
                impact = "Das System-Image könnte manipuliert sein. Rootkits und persistente Malware sind möglich.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = listOf(
                        "Status 'orange': Bootloader ist entsperrt. Prüfe, ob dies gewollt ist.",
                        "Status 'red': System-Image-Prüfung fehlgeschlagen – Factory Reset empfohlen.",
                        "Wende dich an deinen Gerätehersteller für Unterstützung."
                    ),
                    automatable = false,
                    officialDocUrl = "https://source.android.com/docs/security/features/verifiedboot",
                    estimatedTime = "Variabel"
                ),
                source = "SystemInfoScanner"
            )
        } else null
    }

    private fun checkKernelVersion(): VulnerabilityEntry? {
        return try {
            val kernelVersion = File("/proc/version").readText()
            // Kernel-Version aus String extrahieren (z.B. "Linux version 5.4.0-...")
            val versionMatch = Regex("""Linux version (\d+\.\d+)""").find(kernelVersion)
            val majorMinor = versionMatch?.groupValues?.get(1)?.split(".")
            if (majorMinor != null && majorMinor.size >= 2) {
                val major = majorMinor[0].toIntOrNull() ?: return null
                val minor = majorMinor[1].toIntOrNull() ?: return null
                // Kernel < 5.4 ist End-of-Life
                if (major < 5 || (major == 5 && minor < 4)) {
                    return VulnerabilityEntry(
                        id = "SYS-006",
                        title = "Veralteter Linux-Kernel ($major.$minor)",
                        severity = Severity.HIGH,
                        cvssScore = 7.0f,
                        cvssVector = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
                        affectedComponent = "Linux Kernel",
                        description = "Der Linux-Kernel $major.$minor ist End-of-Life und " +
                                "erhält keine Sicherheitsupdates mehr.",
                        impact = "Kernel-Level-Exploits (Privilege Escalation, Container Escape) möglich.",
                        remediation = RemediationSteps(
                            priority = Priority.HIGH,
                            steps = listOf(
                                "Prüfe ob ein Gerätehersteller-Update verfügbar ist.",
                                "Kernel-Updates sind nur über vollständige Systemupdates möglich."
                            ),
                            automatable = false,
                            deepLinkSettings = "android.settings.SYSTEM_UPDATE_SETTINGS",
                            officialDocUrl = "https://kernel.org/category/releases.html",
                            estimatedTime = "~15 Minuten"
                        ),
                        source = "SystemInfoScanner"
                    )
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun checkBootloaderLockStatus(): VulnerabilityEntry? {
        val bootloaderState = getSystemProperty("ro.boot.flash.locked")
            ?: getSystemProperty("ro.secureboot.lockstate")
        return if (bootloaderState == "0" || bootloaderState == "unlocked") {
            VulnerabilityEntry(
                id = "SYS-007",
                title = "Bootloader entsperrt",
                severity = Severity.HIGH,
                cvssScore = 7.2f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                affectedComponent = "Bootloader",
                description = "Der Bootloader ist entsperrt. Dies erlaubt das Booten von " +
                        "unsignierten System-Images und Custom-Recovery.",
                impact = "Angreifer mit physischem Zugriff können beliebigen Code auf Kernel-Ebene ausführen.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Sperre den Bootloader über den Hersteller-Entsperrvorgang rückgängig.",
                        "Beachte: Das Sperren des Bootloaders erfordert oft einen Factory Reset.",
                        "Anleitungen sind gerätespezifisch – konsultiere die Herstellerdokumentation."
                    ),
                    automatable = false,
                    officialDocUrl = "https://source.android.com/docs/core/architecture/bootloader",
                    estimatedTime = "~1 Stunde (inkl. Factory Reset)"
                ),
                source = "SystemInfoScanner"
            )
        } else null
    }


    private fun checkBuildIntegrity(): VulnerabilityEntry? {
        val buildType = getSystemProperty("ro.build.type") ?: return null
        return if (buildType == "userdebug" || buildType == "eng") {
            VulnerabilityEntry(
                id = "SYS-008",
                title = "Unsicherer Build-Typ erkannt: $buildType",
                severity = Severity.HIGH,
                cvssScore = 7.8f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
                affectedComponent = "Android Build System",
                description = "Das Gerät läuft auf einem '${buildType}'-Build statt eines 'user'-Builds. " +
                        "Debug- und Engineering-Builds haben absichtlich geschwächte Sicherheitskontrollen.",
                impact = "Erweiterte Root-Rechte, ADB ohne RSA-Schlüssel-Verifizierung, deaktivierte SELinux-Policies möglich.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Installiere ein offizielles 'user'-Build deines Herstellers.",
                        "Kontaktiere deinen Gerätehersteller für ein offizielles Firmware-Image.",
                        "Vermeide den Betrieb mit Debug-Builds auf produktiven Geräten."
                    ),
                    automatable = false,
                    officialDocUrl = "https://source.android.com/docs/setup/create/new-device#build-variants",
                    estimatedTime = "~1-2 Stunden (Firmware-Flash)"
                ),
                source = "SystemInfoScanner"
            )
        } else null
    }

    private fun checkSystemPartitionMounts(): VulnerabilityEntry? {
        return try {
            val mounts = File("/proc/mounts").readText()
            val systemRw = mounts.lines().any { line ->
                (line.contains(" /system ") || line.contains(" /vendor ")) &&
                        line.contains(" rw,") && !line.contains("ro,")
            }
            if (systemRw) {
                VulnerabilityEntry(
                    id = "SYS-009",
                    title = "System-Partition im Schreib-Lese-Modus gemountet",
                    severity = Severity.CRITICAL,
                    cvssScore = 9.5f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                    affectedComponent = "Linux Dateisystem / /system Partition",
                    description = "Die /system- oder /vendor-Partition ist beschreibbar gemountet. " +
                            "Dies ist ein starker Indikator für Root-Zugriff oder Systemmanipulation.",
                    impact = "Persistente Malware kann Systemdateien manipulieren und überlebt Factory Resets.",
                    remediation = RemediationSteps(
                        priority = Priority.IMMEDIATE,
                        steps = listOf(
                            "Dies ist ein starker Indikator für aktive Root-Exploits oder Malware.",
                            "Führe sofort einen vollständigen Factory Reset durch.",
                            "Flashe ein offizielles Firmware-Image vom Hersteller.",
                            "Ändere alle Passwörter nach dem Reset."
                        ),
                        automatable = false,
                        officialDocUrl = "https://source.android.com/docs/security/features/verifiedboot",
                        estimatedTime = "~1-2 Stunden"
                    ),
                    source = "SystemInfoScanner"
                )
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun getSystemProperty(key: String): String? = try {
        @Suppress("UNCHECKED_CAST")
        val systemProperties = Class.forName("android.os.SystemProperties")
        val get = systemProperties.getMethod("get", String::class.java)
        val value = get.invoke(null, key) as String
        value.ifEmpty { null }
    } catch (e: Exception) {
        null
    }
}
