package com.mobilesecurity.scanner.domain.scanner

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.mobilesecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject

class AppPermissionAuditor @Inject constructor(private val context: Context) {

    private val dangerousPermissions = setOf(
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.GET_ACCOUNTS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION"
    )

    suspend fun scan(): Pair<List<VulnerabilityEntry>, List<AppAudit>> =
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(
                    PackageManager.PackageInfoFlags.of(
                        (PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES).toLong()
                    )
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES)
            }

            val audits = packages.map { buildAudit(pm, it) }
            val vulnerabilities = buildVulnerabilityList(audits)
            Pair(vulnerabilities, audits)
        }

    private fun buildAudit(pm: PackageManager, pkg: PackageInfo): AppAudit {
        val appName = try {
            pm.getApplicationLabel(pkg.applicationInfo!!).toString()
        } catch (e: Exception) {
            pkg.packageName
        }

        // Nur tatsächlich vom Nutzer gewährte gefährliche Berechtigungen zählen
        val grantedDangerous = pkg.requestedPermissions
            ?.filterNotNull()
            ?.filter { perm ->
                perm in dangerousPermissions &&
                pm.checkPermission(perm, pkg.packageName) == android.content.pm.PackageManager.PERMISSION_GRANTED
            }
            ?: emptyList()

        val hasOverlay = pkg.requestedPermissions?.contains(
            "android.permission.SYSTEM_ALERT_WINDOW"
        ) == true

        val hasAccessibility = pkg.requestedPermissions?.contains(
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ) == true

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val hasDeviceAdmin = dpm.activeAdmins?.any {
            it.packageName == pkg.packageName
        } == true

        val installSource = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                pm.getInstallSourceInfo(pkg.packageName).installingPackageName
            } catch (e: Exception) {
                null
            }
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg.packageName)
        }

        val trustedInstallers = setOf(
            "com.android.vending",            // Google Play Store
            "com.google.android.feedback",    // Google Feedback
            "com.amazon.venezia",             // Amazon Appstore
            "org.fdroid.fdroid",              // F-Droid (legitimer Open-Source-Store)
            "com.aurora.store",               // Aurora Store (Play-Store-Wrapper)
            "com.sec.android.app.samsungapps",// Samsung Galaxy Store
            "com.huawei.appmarket",           // Huawei AppGallery
            "com.xiaomi.market",              // Xiaomi GetApps
            "com.oppo.market",                // OPPO Store
            "com.vivo.appstore"               // Vivo App Store
        )
        val isSystemApp = (pkg.applicationInfo?.flags ?: 0) and
                android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
        // System-Apps (Hersteller-Apps) gelten nicht als sideloaded
        val isSideloaded = !isSystemApp &&
                (installSource == null || installSource !in trustedInstallers)
        val isDebugBuild = (pkg.applicationInfo?.flags ?: 0) and
                android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0

        val riskFlags = mutableListOf<String>()
        if (grantedDangerous.size >= 5) riskFlags += "Viele sensible Berechtigungen (${grantedDangerous.size})"
        if (hasOverlay) riskFlags += "Overlay-Berechtigung (Overlay-Angriff möglich)"
        if (hasAccessibility) riskFlags += "Accessibility-Service (Keylogger-Risiko)"
        if (hasDeviceAdmin) riskFlags += "Device-Admin-Rechte (Remote-Wipe möglich)"
        if (isSideloaded) riskFlags += "Sideloaded (nicht aus Play Store)"
        if (isDebugBuild) riskFlags += "Debug-Build (unsicher für Produktivnutzung)"
        val targetSdk = pkg.applicationInfo?.targetSdkVersion ?: 0
        if (targetSdk in 1..27) riskFlags += "Veraltetes targetSdkVersion ($targetSdk < API 28)"

        val riskScore = minOf(100,
            (if (hasDeviceAdmin) 40 else 0) +
                    (if (hasAccessibility) 30 else 0) +
                    (if (hasOverlay) 20 else 0) +
                    (if (isSideloaded) 15 else 0) +
                    (if (isDebugBuild) 20 else 0) +
                    (if (targetSdk < 28 && targetSdk > 0) 15 else 0) +
                    (grantedDangerous.size * 2)
        )

        return AppAudit(
            packageName = pkg.packageName,
            appName = appName,
            versionName = pkg.versionName ?: "Unbekannt",
            targetSdkVersion = targetSdk,
            installSource = installSource,
            isSideloaded = isSideloaded,
            isDebugBuild = isDebugBuild,
            dangerousPermissions = grantedDangerous,
            hasOverlayPermission = hasOverlay,
            hasAccessibilityPermission = hasAccessibility,
            hasDeviceAdminRights = hasDeviceAdmin,
            riskScore = riskScore,
            riskFlags = riskFlags
        )
    }

    private fun buildVulnerabilityList(audits: List<AppAudit>): List<VulnerabilityEntry> {
        val findings = mutableListOf<VulnerabilityEntry>()

        // Device-Admin prüfen (immer kritisch)
        val deviceAdminApps = audits.filter { it.hasDeviceAdminRights }
        if (deviceAdminApps.isNotEmpty()) {
            findings += VulnerabilityEntry(
                id = "APP-001",
                title = "${deviceAdminApps.size} App(s) mit Device-Admin-Rechten gefunden",
                severity = Severity.HIGH,
                cvssScore = 7.8f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                affectedComponent = "Device Administration",
                affectedApps = deviceAdminApps.map { it.appName },
                description = "Apps mit Device-Admin-Rechten: ${deviceAdminApps.joinToString { it.appName }}. " +
                        "Diese können Fernlöschung, Passwortpolitiken und andere kritische Aktionen ausführen.",
                impact = "Kompromittierung dieser Apps ermöglicht Remote-Wipe und Gerätesperre.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Prüfe jede App mit Device-Admin-Rechten auf Legitimität.",
                        "Widerrufe unbekannte Device-Admin-Apps: Einstellungen → Sicherheit → Geräteadministratoren",
                        "Oder: Einstellungen → Biometrie und Sicherheit → Geräteadmin-Apps",
                        "Behalte nur vertrauenswürdige Apps wie MDM-Software deines Arbeitgebers."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.SECURITY_SETTINGS",
                    officialDocUrl = "https://developer.android.com/guide/topics/admin/device-admin",
                    estimatedTime = "~5 Minuten"
                ),
                source = "AppPermissionAuditor"
            )
        }

        // Accessibility-Apps prüfen
        val accessibilityApps = audits.filter { it.hasAccessibilityPermission }
        if (accessibilityApps.isNotEmpty()) {
            findings += VulnerabilityEntry(
                    id = "APP-002",
                    title = "${accessibilityApps.size} App(s) mit Accessibility-Berechtigung",
                    severity = Severity.MEDIUM,
                    cvssScore = 6.5f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    affectedComponent = "Android Accessibility Service",
                    affectedApps = accessibilityApps.map { it.appName },
                    description = "Apps mit Accessibility-Service können alle Bildschirminhalte lesen " +
                            "und Aktionen im Namen des Nutzers ausführen (potenzielle Keylogger).",
                    impact = "Passwörter, PINs und andere sensible Eingaben könnten abgefangen werden.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Prüfe alle Apps unter Einstellungen → Barrierefreiheit → Heruntergeladene Apps.",
                            "Deaktiviere nicht vertrauenswürdige Apps.",
                            "Behalte nur legitime Accessibility-Apps (z.B. TalkBack)."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.ACCESSIBILITY_SETTINGS",
                        officialDocUrl = "https://developer.android.com/guide/topics/ui/accessibility",
                        estimatedTime = "~3 Minuten"
                    ),
                    source = "AppPermissionAuditor"
                )
        }

        // Apps mit übermäßig vielen Berechtigungen melden
        val permissionHeavyApps = audits.filter {
            it.dangerousPermissions.size >= 7 && !it.hasDeviceAdminRights
        }
        if (permissionHeavyApps.isNotEmpty()) {
            findings += VulnerabilityEntry(
                    id = "APP-004",
                    title = "${permissionHeavyApps.size} App(s) mit ≥7 tatsächlich gewährten gefährlichen Berechtigungen",
                    severity = Severity.MEDIUM,
                    cvssScore = 5.8f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    affectedComponent = "App-Berechtigungen",
                    affectedApps = permissionHeavyApps.map { it.appName },
                    description = "Apps mit sehr vielen tatsächlich gewährten gefährlichen Berechtigungen haben " +
                            "weitreichenden Zugriff auf persönliche Daten. " +
                            "Hinweis: Systemapps und vorinstallierte Berechtigungen können nicht durch den Nutzer widerrufen werden – " +
                            "diese sind hier bereits herausgefiltert.",
                    impact = "Datenmissbrauch durch umfangreiche Zugriffsrechte auf Kontakte, " +
                            "Standort, Kamera, Mikrofon und SMS.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Überprüfe für jede App, ob alle Berechtigungen wirklich notwendig sind.",
                            "Entziehe nicht benötigte Berechtigungen: Einstellungen → Apps → [App] → Berechtigungen",
                            "Falls Berechtigungen nicht widerrufbar sind (ausgegraut), sind diese system-seitig vergeben.",
                            "Deinstalliere Apps, die du nicht kennst oder nicht mehr nutzt."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.APPLICATION_SETTINGS",
                        officialDocUrl = "https://developer.android.com/guide/topics/permissions/overview",
                        estimatedTime = "~10 Minuten"
                    ),
                    source = "AppPermissionAuditor"
                )
        }

        // Sideloaded Debug-Build-Apps melden
        val debugApps = audits.filter { it.isDebugBuild && it.isSideloaded }
        if (debugApps.isNotEmpty()) {
            findings += VulnerabilityEntry(
                    id = "APP-005",
                    title = "${debugApps.size} sideloaded Debug-Build-App(s) gefunden",
                    severity = Severity.HIGH,
                    cvssScore = 7.1f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    affectedComponent = "App-Debugging",
                    affectedApps = debugApps.map { it.appName },
                    description = "Sideloaded Apps im Debug-Modus erlauben Debugger-Attachment, " +
                            "Bytecode-Manipulation und WebView-Remote-Debugging.",
                    impact = "Angreifer mit lokalem Zugang können App-Daten auslesen und Code injizieren.",
                    remediation = RemediationSteps(
                        priority = Priority.HIGH,
                        steps = listOf(
                            "Deinstalliere alle unbekannten Debug-Apps sofort.",
                            "Nutze ausschließlich Apps aus dem Play Store oder verifizierten Quellen.",
                            "Prüfe ob du diese Apps selbst installiert hast."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.APPLICATION_SETTINGS",
                        officialDocUrl = "https://developer.android.com/studio/debug",
                        estimatedTime = "~5 Minuten"
                    ),
                    source = "AppPermissionAuditor"
                )
        }

        // Sideloaded Apps mit veraltetem targetSdkVersion
        val outdatedSdkApps = audits.filter { it.isSideloaded && it.targetSdkVersion in 1..27 }
        if (outdatedSdkApps.isNotEmpty()) {
            findings += VulnerabilityEntry(
                id = "APP-006",
                title = "${outdatedSdkApps.size} sideloaded App(s) mit veraltetem targetSdkVersion",
                severity = Severity.MEDIUM,
                cvssScore = 5.3f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                affectedComponent = "App-Sicherheitsstandards",
                affectedApps = outdatedSdkApps.map { "${it.appName} (API ${it.targetSdkVersion})" },
                description = "Sideloaded Apps mit targetSdkVersion < 28 umgehen neuere Android-Sicherheitsfeatures " +
                    "wie Scoped Storage, FLAG_SECURE-Erzwingung und sichere Netzwerkkonfiguration.",
                impact = "Apps können auf nicht-sandboxed-Daten zugreifen und ältere, unsichere APIs nutzen.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Aktualisiere oder ersetze betroffene Apps durch aktuelle Versionen.",
                        "Falls eine App keine Updates erhält, erwäge sie zu deinstallieren.",
                        "Installiere Apps bevorzugt aus dem Play Store – dort werden Mindest-targetSdk-Anforderungen durchgesetzt."
                    ),
                    automatable = false,
                    officialDocUrl = "https://developer.android.com/google/play/requirements/target-sdk",
                    estimatedTime = "~10 Minuten"
                ),
                source = "AppPermissionAuditor"
            )
        }

        val sideloadedApps = audits.filter { it.isSideloaded }
        val sideloadedCount = sideloadedApps.size
        if (sideloadedCount > 0) {
            val sideloadedDesc = sideloadedApps.take(5).joinToString("; ") { audit ->
                val source = when {
                    audit.installSource == null -> "${audit.appName} (Installationsquelle unbekannt)"
                    else -> "${audit.appName} (installiert von: ${audit.installSource})"
                }
                source
            }
            findings += VulnerabilityEntry(
                id = "APP-003",
                title = "$sideloadedCount App(s) außerhalb vertrauenswürdiger Stores installiert",
                severity = Severity.MEDIUM,
                cvssScore = 5.5f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
                affectedComponent = "App-Installation",
                affectedApps = sideloadedApps.map { it.appName },
                description = "Diese Apps wurden nicht über einen vertrauenswürdigen Store (z.B. Google Play, Galaxy Store) " +
                        "installiert. Das bedeutet: keine automatische Sicherheitsprüfung durch den Store.\n" +
                        "Hinweis: Apps aus F-Droid, Aurora Store oder selbst via ADB installierte Entwickler-Apps " +
                        "können legitim sein.\n" +
                        "Gefundene Apps: $sideloadedDesc",
                impact = "Nicht geprüfte Apps können Malware, Spyware oder unerwünschte Werbung enthalten.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Überprüfe jede aufgelistete App: Erkennst du sie? Hast du sie bewusst installiert?",
                        "Apps aus F-Droid oder Aurora Store sind oft legitime Open-Source-Apps.",
                        "Apps ohne erkennbare Installationsquelle sollten genauer geprüft werden.",
                        "Unbekannte Apps deinstallieren: Einstellungen → Apps → [App] → Deinstallieren",
                        "Für mehr Infos: VirusTotal.com erlaubt die Prüfung von APK-Dateien auf Malware."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.MANAGE_UNKNOWN_APP_SOURCES",
                    officialDocUrl = "https://support.google.com/android/answer/2812853",
                    estimatedTime = "~10 Minuten"
                ),
                source = "AppPermissionAuditor"
            )
        }

        return findings
    }
}
