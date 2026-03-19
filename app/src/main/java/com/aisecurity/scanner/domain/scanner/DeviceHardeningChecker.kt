package com.aisecurity.scanner.domain.scanner

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.provider.Settings
import com.aisecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject

class DeviceHardeningChecker @Inject constructor(private val context: Context) {

    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()

        findings += checkScreenLock()
        findings += checkAdbOverNetwork()
        findings += checkUsbDebugging()
        findings += checkDeveloperOptions()
        findings += checkUnknownSources()
        findings += checkScreenTimeout()
        findings += checkBackupEnabled()
        findings += checkBiometricSecurity()
        findings += checkAutoFillSecurity()
        findings += checkLockdownModeAvailability()

        findings.filterNotNull()
    }

    private fun checkScreenLock(): VulnerabilityEntry? {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return if (!km.isDeviceSecure) {
            VulnerabilityEntry(
                id = "DEV-001",
                title = "Keine Bildschirmsperre konfiguriert",
                severity = Severity.CRITICAL,
                cvssScore = 9.1f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "Bildschirmsperre",
                description = "Das Gerät hat keine Bildschirmsperre (PIN, Muster oder Passwort). " +
                        "Jede Person mit physischem Zugriff kann alle Daten einsehen.",
                impact = "Vollständiger Datenzugriff für jeden mit physischem Gerätekontakt.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = listOf(
                        "Richte sofort eine Bildschirmsperre ein.",
                        "Navigiere zu: Einstellungen → Sicherheit → Bildschirmsperre",
                        "Empfehlung: Mindestens 6-stellige PIN oder alphanumerisches Passwort.",
                        "Biometrie (Fingerabdruck) als zusätzliche Option möglich, nicht als einzige."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.app.action.SET_NEW_PASSWORD",
                    officialDocUrl = "https://support.google.com/android/answer/9079129",
                    estimatedTime = "~3 Minuten"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    private fun checkScreenTimeout(): VulnerabilityEntry? {
        val timeoutMs = try {
            Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_OFF_TIMEOUT)
        } catch (_: Exception) {
            return null
        }
        val timeoutMinutes = timeoutMs / 60000
        return if (timeoutMinutes > 5) {
            VulnerabilityEntry(
                id = "DEV-002",
                title = "Bildschirm-Timeout zu lang ($timeoutMinutes Minuten)",
                severity = Severity.LOW,
                cvssScore = 2.9f,
                cvssVector = "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                affectedComponent = "Bildschirm-Timeout",
                description = "Das Gerät sperrt sich erst nach $timeoutMinutes Minuten. " +
                        "Ein kurzes Ablegen des Geräts ermöglicht unbefugten Zugriff.",
                impact = "Kurzzeitiger physischer Zugriff auf entsperrtes Gerät.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Reduziere das Bildschirm-Timeout auf maximal 1-2 Minuten.",
                        "Navigiere zu: Einstellungen → Display → Bildschirm-Timeout"
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.DISPLAY_SETTINGS",
                    officialDocUrl = "https://support.google.com/android/answer/9075927",
                    estimatedTime = "~1 Minute"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    private fun checkDeveloperOptions(): VulnerabilityEntry? {
        val devOptions = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0)
        } catch (_: Exception) {
            return null
        }
        return if (devOptions == 1) {
            VulnerabilityEntry(
                id = "DEV-003",
                title = "Entwickleroptionen sind aktiviert",
                severity = Severity.MEDIUM,
                cvssScore = 5.5f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
                affectedComponent = "Entwickleroptionen",
                description = "Die Entwickleroptionen sind aktiv. Diese enthalten zahlreiche " +
                        "Einstellungen die die Sicherheit des Geräts gefährden können.",
                impact = "Angreifer können über ADB, Mock-Locations und weitere Entwicklertools auf das Gerät zugreifen.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Deaktiviere die Entwickleroptionen, falls du sie nicht benötigst.",
                        "Navigiere zu: Einstellungen → Entwickleroptionen → Deaktivieren",
                        "Oder: Einstellungen → System → Entwickleroptionen → Schalter oben ausschalten."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                    officialDocUrl = "https://developer.android.com/studio/debug/dev-options",
                    estimatedTime = "~1 Minute"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    private fun checkUsbDebugging(): VulnerabilityEntry? {
        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0)
        } catch (_: Exception) {
            return null
        }
        return if (adbEnabled == 1) {
            VulnerabilityEntry(
                id = "DEV-004",
                title = "USB-Debugging ist aktiviert",
                severity = Severity.HIGH,
                cvssScore = 7.6f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "USB-Debugging (ADB)",
                description = "USB-Debugging ermöglicht jedem Computer mit USB-Zugang volle " +
                        "Kontrolle über das Gerät über ADB (Android Debug Bridge).",
                impact = "Vollständiger Datenzugriff, App-Installation und Shell-Kontrolle über USB.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Deaktiviere USB-Debugging: Einstellungen → Entwickleroptionen → USB-Debugging",
                        "Verbinde keine unbekannten USB-Ladekabel an öffentlichen Stationen."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                    officialDocUrl = "https://developer.android.com/studio/command-line/adb",
                    estimatedTime = "~1 Minute"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    private fun checkAdbOverNetwork(): VulnerabilityEntry? {
        val adbNetworkEnabled = try {
            Settings.Global.getInt(context.contentResolver, "adb_wifi_enabled", 0)
        } catch (_: Exception) {
            0
        }
        return if (adbNetworkEnabled == 1) {
            VulnerabilityEntry(
                id = "DEV-005",
                title = "ADB über WLAN ist aktiviert",
                severity = Severity.CRITICAL,
                cvssScore = 9.8f,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affectedComponent = "ADB over Network",
                description = "ADB ist über das Netzwerk zugänglich. Jeder im gleichen Netz kann " +
                        "ohne Passwort vollständige Gerätekontrolle übernehmen.",
                impact = "Ferngesteuerter Zugriff auf das Gerät ohne Authentifizierung.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = listOf(
                        "Deaktiviere sofort: Einstellungen → Entwickleroptionen → Kabelloses Debugging",
                        "Trenne alle laufenden ADB-Verbindungen."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                    officialDocUrl = "https://developer.android.com/studio/command-line/adb",
                    estimatedTime = "~1 Minute"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    @Suppress("ObsoleteSdkInt")
    private fun checkUnknownSources(): VulnerabilityEntry? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Android 8+: Globale Einstellung entfernt – stattdessen per-App REQUEST_INSTALL_PACKAGES prüfen
            return checkUnknownSourcesPerApp()
        }

        @Suppress("DEPRECATION")
        val unknownSources = try {
            Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0)
        } catch (_: Exception) {
            return null
        }
        return if (unknownSources == 1) {
            VulnerabilityEntry(
                id = "DEV-006",
                title = "Installation aus unbekannten Quellen erlaubt",
                severity = Severity.MEDIUM,
                cvssScore = 6.1f,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
                affectedComponent = "App-Installation",
                description = "Apps können aus nicht verifizierten Quellen installiert werden.",
                impact = "Einfachere Malware-Installation über manipulierte APKs.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Deaktiviere: Einstellungen → Sicherheit → Unbekannte Quellen"
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.SECURITY_SETTINGS",
                    officialDocUrl = "https://support.google.com/android/answer/2812853",
                    estimatedTime = "~1 Minute"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    private fun checkUnknownSourcesPerApp(): VulnerabilityEntry? {
        return try {
            val pm = context.packageManager
            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }

            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val appsWithInstallPermission = packages.filter { pkg ->
                val isSystem = (pkg.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
                if (isSystem || pkg.packageName == context.packageName) return@filter false
                // Nur Apps die tatsächlich die Berechtigung erhalten haben (nicht nur angefragt)
                try {
                    val opStr = "android:request_install_packages"
                    val opResult = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        appOps.unsafeCheckOpNoThrow(
                            opStr,
                            pkg.applicationInfo!!.uid,
                            pkg.packageName
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        appOps.checkOpNoThrow(
                            opStr,
                            pkg.applicationInfo!!.uid,
                            pkg.packageName
                        )
                    }
                    opResult == AppOpsManager.MODE_ALLOWED
                } catch (_: Exception) {
                    false
                }
            }.mapNotNull { pkg ->
                try { pm.getApplicationLabel(pkg.applicationInfo!!).toString() } catch (_: Exception) { null }
            }

            if (appsWithInstallPermission.isNotEmpty()) {
                VulnerabilityEntry(
                    id = "DEV-006",
                    title = "${appsWithInstallPermission.size} App(s) dürfen APKs installieren",
                    severity = Severity.MEDIUM,
                    cvssScore = 6.1f,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
                    affectedComponent = "App-Installation (REQUEST_INSTALL_PACKAGES)",
                    affectedApps = appsWithInstallPermission,
                    description = "Folgende Apps besitzen die Berechtigung, weitere APKs zu installieren: " +
                            "${appsWithInstallPermission.joinToString(", ")}. " +
                            "Diese Apps könnten ohne weitere Nutzerbestätigung Malware nachladen.",
                    impact = "Unerwünschte App-Installation durch kompromittierte oder bösartige Apps möglich.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Prüfe jede betroffene App: Einstellungen → Apps → [App] → Berechtigungen → Unbekannte Apps installieren",
                            "Entziehe die Berechtigung für Apps, die sie nicht legitim benötigen.",
                            "Nur vertrauenswürdige App-Stores (z.B. F-Droid) sollten diese Berechtigung haben."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.MANAGE_UNKNOWN_APP_SOURCES",
                        officialDocUrl = "https://developer.android.com/reference/android/Manifest.permission#REQUEST_INSTALL_PACKAGES",
                        estimatedTime = "~5 Minuten"
                    ),
                    source = "DeviceHardeningChecker"
                )
            } else null
        } catch (_: Exception) { null }
    }

    private fun checkBackupEnabled(): VulnerabilityEntry? {
        val backupEnabled = try {
            Settings.Secure.getInt(context.contentResolver, "backup_enabled", 0)
        } catch (_: Exception) {
            return null
        }
        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0)
        } catch (_: Exception) {
            0
        }
        return if (backupEnabled == 1 && adbEnabled == 1) {
            VulnerabilityEntry(
                id = "DEV-007",
                title = "ADB-Backup aktiviert (Datenleak über ADB möglich)",
                severity = Severity.MEDIUM,
                cvssScore = 5.7f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Android Backup",
                description = "ADB-Backup ist aktiviert. Mit USB-Zugang können alle App-Daten " +
                        "über `adb backup` extrahiert werden.",
                impact = "App-Daten, Dokumente und möglicherweise Zugangsdaten extrahierbar.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Deaktiviere USB-Debugging, um ADB-Backup zu verhindern.",
                        "Oder: Prüfe, ob Apps android:allowBackup=false setzen."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                    officialDocUrl = "https://developer.android.com/guide/topics/data/backup",
                    estimatedTime = "~2 Minuten"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    private fun checkBiometricSecurity(): VulnerabilityEntry? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null

        val bm = context.getSystemService(BiometricManager::class.java) ?: return null
        val strongResult = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        val weakResult = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)

        // Wenn nur schwache Biometrie (Class 2) aber keine starke (Class 3) verfügbar
        return if (weakResult == BiometricManager.BIOMETRIC_SUCCESS &&
            strongResult != BiometricManager.BIOMETRIC_SUCCESS
        ) {
            VulnerabilityEntry(
                id = "DEV-008",
                title = "Nur schwache Biometrie (Class 2) verfügbar",
                severity = Severity.LOW,
                cvssScore = 3.5f,
                cvssVector = "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                affectedComponent = "Biometrische Authentifizierung",
                description = "Das Gerät unterstützt nur Klasse-2-Biometrie (z.B. Gesichtserkennung " +
                        "ohne 3D-Sensor), die anfälliger für Spoofing ist.",
                impact = "Biometrische Entsperrung kann durch Fotos oder einfache Masken umgangen werden.",
                remediation = RemediationSteps(
                    priority = Priority.LOW,
                    steps = listOf(
                        "Nutze Fingerabdruck (falls verfügbar) statt Gesichtserkennung.",
                        "Setze eine starke PIN als primäre Sicherheitsmethode."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.BIOMETRIC_ENROLL",
                    officialDocUrl = "https://developer.android.com/training/sign-in/biometric-auth",
                    estimatedTime = "~3 Minuten"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }


    private fun checkAutoFillSecurity(): VulnerabilityEntry? {
        val autofillService = try {
            Settings.Secure.getString(context.contentResolver, "autofill_service")
        } catch (_: Exception) {
            return null
        } ?: return null

        val trustedAutofillServices = setOf(
            "com.google.android.gms/.autofill.service.AutofillService",
            "com.google.android.gms/com.google.android.gms.autofill.service.AutofillService",
            ""
        )

        return if (autofillService.isNotEmpty() && autofillService !in trustedAutofillServices &&
            !autofillService.startsWith("com.google.") &&
            !autofillService.startsWith("com.samsung.")
        ) {
            VulnerabilityEntry(
                id = "DEV-009",
                title = "Unbekannter Autofill-Dienst aktiv: ${autofillService.substringBefore("/")}",
                severity = Severity.MEDIUM,
                cvssScore = 5.7f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                affectedComponent = "Android Autofill-Framework",
                description = "Ein unbekannter Autofill-Dienst ist aktiv: $autofillService. " +
                        "Autofill-Dienste haben Zugang zu allen in Formulare eingegebenen Daten " +
                        "einschließlich Passwörter und Zahlungsdaten.",
                impact = "Passwörter, Kreditkarteninformationen und andere Formulardaten könnten abgefangen werden.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Überprüfe den aktiven Autofill-Dienst: Einstellungen → Allgemeine Verwaltung → Autofill-Dienst",
                        "Ändere zu einem vertrauenswürdigen Dienst wie Google Autofill oder deaktiviere ihn.",
                        "Deinstalliere unbekannte Passwort-Manager-Apps."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.REQUEST_SET_AUTOFILL_SERVICE",
                    officialDocUrl = "https://developer.android.com/guide/topics/text/autofill",
                    estimatedTime = "~3 Minuten"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }

    private fun checkLockdownModeAvailability(): VulnerabilityEntry? {
        try {
            Settings.Secure.getInt(context.contentResolver, "lockdown_mode", 0)
        } catch (_: Exception) {
            return null
        }
        val keyguardDisabled = try {
            Settings.Global.getInt(context.contentResolver, "keyguard_disabled_features", 0)
        } catch (_: Exception) {
            0
        }
        // Wenn Keyguard-Features deaktiviert sind (z.B. alle Features disabled = 0x0fff)
        return if (keyguardDisabled and 0x0002 != 0) {  // 0x0002 = DISABLE_FINGERPRINT
            VulnerabilityEntry(
                id = "DEV-010",
                title = "Biometrische Bildschirmsperre durch MDM/Policy deaktiviert",
                severity = Severity.MEDIUM,
                cvssScore = 4.6f,
                cvssVector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                affectedComponent = "Bildschirmsperren-Konfiguration",
                description = "Eine Device-Policy hat biometrische Entsperrmethoden deaktiviert. " +
                        "Dies könnte durch MDM-Software oder eine schädliche Policy erfolgt sein.",
                impact = "Reduktion der Entsperroptionen kann in bestimmten Szenarien die Sicherheit verringern.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Prüfe ob eine MDM-App (Mobile Device Management) diese Policy setzt.",
                        "Überprüfe aktive Device-Admin-Apps: Einstellungen → Sicherheit → Geräteadministratoren",
                        "Widerrufe unbekannte Device-Admin-Rechte."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.app.action.DEVICE_ADMIN_SETTINGS",
                    officialDocUrl = "https://developer.android.com/guide/topics/admin/device-admin",
                    estimatedTime = "~5 Minuten"
                ),
                source = "DeviceHardeningChecker"
            )
        } else null
    }
}
