package com.aisecurity.scanner.domain.scanner

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Environment
import android.os.storage.StorageManager
import android.security.KeyChain
import com.aisecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyStore
import javax.inject.Inject

class StorageSecurityScanner @Inject constructor(private val context: Context) {

    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()

        findings += checkDeviceEncryption()
        findings += checkUserCertificates()
        findings += checkExternalLogFiles()
        findings += checkBackupDataLeaks()
        findings += checkWorldReadableFiles()
        findings += checkSensitiveFilesInDownloads()

        findings.filterNotNull()
    }

    private fun checkDeviceEncryption(): VulnerabilityEntry? {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        return when (dpm.storageEncryptionStatus) {
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> VulnerabilityEntry(
                id = "STR-001",
                title = "Geräteverschlüsselung nicht aktiv",
                severity = Severity.HIGH,
                cvssScore = 7.8f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                affectedComponent = "Gerätespeicher-Verschlüsselung",
                description = "Die Geräteverschlüsselung ist inaktiv. Alle gespeicherten Daten " +
                        "sind bei physischem Zugriff ohne Passwort lesbar.",
                impact = "Vollständige Datenkompromittierung bei Gerätediebstahl.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Aktiviere Geräteverschlüsselung: Einstellungen → Sicherheit → Verschlüsselung",
                        "Stelle sicher, dass das Gerät dabei vollständig geladen ist.",
                        "Erstelle vorher ein Backup aller wichtigen Daten."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.SECURITY_SETTINGS",
                    officialDocUrl = "https://source.android.com/docs/security/features/encryption",
                    estimatedTime = "~2 Stunden"
                ),
                source = "StorageSecurityScanner"
            )
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> VulnerabilityEntry(
                id = "STR-002",
                title = "Verschlüsselung mit Standard-Schlüssel (kein Benutzerpasswort)",
                severity = Severity.MEDIUM,
                cvssScore = 5.3f,
                cvssVector = "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Gerätespeicher-Verschlüsselung",
                description = "Die Verschlüsselung ist aktiv, aber ohne Benutzerpasswort gebunden. " +
                        "Der Schlüssel ist nicht an die Bildschirmsperre gekoppelt.",
                impact = "Verschlüsselung bietet reduzierten Schutz ohne Bildschirmsperren-Binding.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Richte eine starke Bildschirmsperre ein, um die Verschlüsselung an dein Passwort zu binden.",
                        "Navigiere zu: Einstellungen → Sicherheit → Bildschirmsperre"
                    ),
                    automatable = false,
                    deepLinkSettings = "android.app.action.SET_NEW_PASSWORD",
                    officialDocUrl = "https://source.android.com/docs/security/features/encryption",
                    estimatedTime = "~3 Minuten"
                ),
                source = "StorageSecurityScanner"
            )
            else -> null
        }
    }

    private fun checkUserCertificates(): VulnerabilityEntry? {
        return try {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val userCerts = keyStore.aliases().toList().filter { alias ->
                alias.startsWith("user:")
            }
            if (userCerts.isNotEmpty()) {
                VulnerabilityEntry(
                    id = "STR-003",
                    title = "${userCerts.size} Benutzerzertifikat(e) im Vertrauensspeicher",
                    severity = Severity.HIGH,
                    cvssScore = 7.4f,
                    cvssVector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    affectedComponent = "Zertifikat-Vertrauensspeicher",
                    description = "Es sind ${userCerts.size} benutzerdefinierte CA-Zertifikate " +
                            "installiert. Diese können TLS-Verbindungen abfangen (Man-in-the-Middle).",
                    impact = "HTTPS-Verbindungen könnten durch diese CAs entschlüsselt werden. " +
                            "Typisch bei Firmen-MDM, aber auch bei Malware.",
                    remediation = RemediationSteps(
                        priority = Priority.HIGH,
                        steps = listOf(
                            "Prüfe alle Benutzerzertifikate: Einstellungen → Sicherheit → Zertifikate → Vertrauenswürdige Anmeldeinformationen → BENUTZER",
                            "Entferne alle unbekannten Zertifikate.",
                            "Legitime Zertifikate: Nur von deinem Arbeitgeber oder bekannten Diensten."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.TRUSTED_CREDENTIALS_USER",
                        officialDocUrl = "https://support.google.com/android/answer/2819522",
                        estimatedTime = "~5 Minuten"
                    ),
                    source = "StorageSecurityScanner"
                )
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun checkExternalLogFiles(): VulnerabilityEntry? {
        val externalDir = context.getExternalFilesDir(null) ?: return null
        val logFiles = externalDir.listFiles { file ->
            file.extension.lowercase() in listOf("log", "txt", "json", "xml", "db")
        }
        return if (!logFiles.isNullOrEmpty()) {
            VulnerabilityEntry(
                id = "STR-004",
                title = "${logFiles.size} sensible Dateien im externen Speicher gefunden",
                severity = Severity.MEDIUM,
                cvssScore = 4.3f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Externer Speicher",
                description = "Log- und Datenbankdateien liegen im externen Speicher, " +
                        "der von anderen Apps mit Speicherberechtigung gelesen werden kann.",
                impact = "Sensible App-Daten könnten von anderen Apps ausgelesen werden.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Prüfe ob die betroffenen Apps sensible Daten extern speichern.",
                        "Wende dich an die App-Entwickler und weise auf das Problem hin.",
                        "Verwende nach Möglichkeit den internen verschlüsselten Speicher."
                    ),
                    automatable = false,
                    officialDocUrl = "https://developer.android.com/training/data-storage",
                    estimatedTime = "~10 Minuten"
                ),
                source = "StorageSecurityScanner"
            )
        } else null
    }

    private fun checkBackupDataLeaks(): VulnerabilityEntry? {
        // Prüfe ob der App-eigene Backup-Ordner sensible Daten enthält
        val backupDir = File(context.filesDir.parent, "backup")
        return if (backupDir.exists() && backupDir.listFiles()?.isNotEmpty() == true) {
            VulnerabilityEntry(
                id = "STR-005",
                title = "App-Backup-Verzeichnis enthält Daten",
                severity = Severity.LOW,
                cvssScore = 3.3f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                affectedComponent = "App-Backup",
                description = "Das Backup-Verzeichnis der App enthält Dateien, " +
                        "die über ADB-Backup oder Cloud-Backup zugänglich sein können.",
                impact = "Niedrigstes Risiko, da Backup-Zugriff bereits eine Schwachstelle voraussetzt.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Prüfe regelmäßig, welche Apps Backup erlauben.",
                        "Setze android:allowBackup=false für sensible Apps."
                    ),
                    automatable = false,
                    officialDocUrl = "https://developer.android.com/guide/topics/data/backup",
                    estimatedTime = "~5 Minuten"
                ),
                source = "StorageSecurityScanner"
            )
        } else null
    }

    // ─── FORENSIC-only ────────────────────────────────────────────────────────

    private fun checkWorldReadableFiles(): VulnerabilityEntry? {
        return try {
            val appDataDir = context.filesDir
            val worldReadableFiles = mutableListOf<String>()

            appDataDir.walkTopDown().take(200).forEach { file ->
                if (file.isFile) {
                    try {
                        val perms = Files.getPosixFilePermissions(file.toPath())
                        if (PosixFilePermission.OTHERS_READ in perms) {
                            worldReadableFiles += file.name
                        }
                    } catch (_: Exception) {}
                }
            }

            if (worldReadableFiles.isNotEmpty()) {
                VulnerabilityEntry(
                    id = "STR-006",
                    title = "${worldReadableFiles.size} weltlesbare Dateien im App-Datenverzeichnis",
                    severity = Severity.MEDIUM,
                    cvssScore = 4.7f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    affectedComponent = "App-Datei-Berechtigungen",
                    description = "Dateien im privaten App-Verzeichnis sind für alle Prozesse lesbar. " +
                            "Dies kann durch unsichere Dateioperationen oder Root-Zugriff entstehen.",
                    impact = "Andere Apps oder Prozesse können auf interne App-Daten zugreifen.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Apps sollten Dateien nur mit MODE_PRIVATE erstellen.",
                            "Prüfe ob Root-Prozesse die Berechtigungen geändert haben.",
                            "Factory Reset kann helfen wenn dies durch Malware verursacht wurde."
                        ),
                        automatable = false,
                        officialDocUrl = "https://developer.android.com/training/data-storage/app-specific",
                        estimatedTime = "~15 Minuten"
                    ),
                    source = "StorageSecurityScanner"
                )
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun checkSensitiveFilesInDownloads(): VulnerabilityEntry? {
        val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(
            android.os.Environment.DIRECTORY_DOWNLOADS
        )
        if (!downloadsDir.exists()) return null

        val sensitiveExtensions = setOf("key", "pem", "pfx", "p12", "cer", "crt", "kdb", "kdbx", "wallet")
        val sensitiveFiles = try {
            downloadsDir.listFiles { file ->
                file.extension.lowercase() in sensitiveExtensions
            }?.toList() ?: emptyList()
        } catch (e: Exception) {
            return null
        }

        return if (sensitiveFiles.isNotEmpty()) {
            VulnerabilityEntry(
                id = "STR-007",
                title = "${sensitiveFiles.size} potenziell sensible Datei(en) im Download-Ordner",
                severity = Severity.HIGH,
                cvssScore = 7.1f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Externer Speicher / Downloads",
                affectedApps = sensitiveFiles.map { it.name },
                description = "Kryptografische Schlüssel, Zertifikate oder Passwort-Datenbankdateien " +
                        "liegen im öffentlich zugänglichen Download-Ordner: " +
                        "${sensitiveFiles.take(5).joinToString { it.name }}",
                impact = "Diese Dateien sind für alle Apps mit Speicherberechtigung lesbar und bei Datei-Sharing gefährdet.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Verschiebe Schlüsseldateien in einen sicheren, verschlüsselten Bereich.",
                        "Lösche nicht mehr benötigte kryptografische Schlüssel sofort.",
                        "Speichere Passwort-Datenbanken (KeePass, etc.) im internen App-Speicher.",
                        "Prüfe ob diese Dateien absichtlich heruntergeladen wurden."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.INTERNAL_STORAGE_SETTINGS",
                    officialDocUrl = "https://developer.android.com/training/data-storage/shared/documents-files",
                    estimatedTime = "~10 Minuten"
                ),
                source = "StorageSecurityScanner"
            )
        } else null
    }
}
