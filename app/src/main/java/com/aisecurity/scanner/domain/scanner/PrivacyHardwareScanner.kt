package com.aisecurity.scanner.domain.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import com.aisecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStreamReader
import java.io.BufferedReader
import javax.inject.Inject

class PrivacyHardwareScanner @Inject constructor(private val context: Context) {

    suspend fun scan(): List<VulnerabilityEntry> =
        withContext(Dispatchers.IO) {
            val findings = mutableListOf<VulnerabilityEntry?>()

            findings += checkCameraAndMicrophoneAccess()
            findings += checkVpnConnections()
            findings += checkBatteryOptimizationBypass()
            findings += checkDangerousSystemPermissions()
            findings += checkRootIndicators()
            findings += checkOpenNetworkPorts()
            findings += checkBootReceiverApps()
            findings += checkFridaAndInstrumentation()
            findings += checkLogcatForSecurityIssues()
            findings += checkSuspiciousProcesses()

            findings.filterNotNull()
        }

    // ─── Kamera & Mikrofon ───────────────────────────────────────────────────

    private fun checkCameraAndMicrophoneAccess(): List<VulnerabilityEntry> {
        val results = mutableListOf<VulnerabilityEntry>()
        val pm = context.packageManager
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager

        val cameraApps = mutableListOf<String>()
        val micApps = mutableListOf<String>()
        val backgroundCameraApps = mutableListOf<String>()
        val backgroundMicApps = mutableListOf<String>()

        val packages = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }
        } catch (e: Exception) { return emptyList() }

        for (pkg in packages) {
            val appName = try { pm.getApplicationLabel(pkg.applicationInfo!!).toString() } catch (e: Exception) { pkg.packageName }
            val isSystemApp = (pkg.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
            if (isSystemApp) continue

            // Kamera-Zugriff prüfen
            try {
                val cameraOp = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    appOps.unsafeCheckOpNoThrow("android:camera", pkg.applicationInfo!!.uid, pkg.packageName)
                } else {
                    @Suppress("DEPRECATION")
                    appOps.checkOpNoThrow(AppOpsManager.OPSTR_CAMERA, pkg.applicationInfo!!.uid, pkg.packageName)
                }
                if (cameraOp == AppOpsManager.MODE_ALLOWED) {
                    cameraApps += appName
                }
            } catch (_: Exception) {}

            // Mikrofon-Zugriff prüfen
            try {
                val micOp = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    appOps.unsafeCheckOpNoThrow("android:record_audio", pkg.applicationInfo!!.uid, pkg.packageName)
                } else {
                    @Suppress("DEPRECATION")
                    appOps.checkOpNoThrow(AppOpsManager.OPSTR_RECORD_AUDIO, pkg.applicationInfo!!.uid, pkg.packageName)
                }
                if (micOp == AppOpsManager.MODE_ALLOWED) {
                    micApps += appName
                }
            } catch (_: Exception) {}

            // Hintergrund-Kamera (Android 11+): App hat aktiven Kamera-Op und Kamera-Berechtigung
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                try {
                    val bgCamera = appOps.unsafeCheckOpNoThrow(
                        "android:camera",
                        pkg.applicationInfo!!.uid,
                        pkg.packageName
                    )
                    val hasCamPerm = pkg.requestedPermissions?.contains("android.permission.CAMERA") == true
                    if (bgCamera == AppOpsManager.MODE_ALLOWED && hasCamPerm && !isSystemApp) {
                        backgroundCameraApps += appName
                    }
                } catch (_: Exception) {}
            }
        }

        // Kamera-Zugriffswarnung: Nur Apps die wirklich keinen Kamera-Bedarf haben.
        // "vpn"/"caller"/"flashlight" werden entfernt – VPN-Apps scannen QR-Codes,
        // Anruf-Apps können Videoanrufe machen, Taschenlampen-Apps existieren legitim.
        val highRiskCameraApps = cameraApps.filter { app ->
            val suspiciousKeywords = listOf("cleaner", "battery", "optimizer", "booster")
            suspiciousKeywords.any { app.lowercase().contains(it) }
        }
        if (highRiskCameraApps.isNotEmpty()) {
            results += VulnerabilityEntry(
                id = "PRI-001",
                title = "${highRiskCameraApps.size} verdächtige App(s) mit Kamera-Zugriff",
                severity = Severity.HIGH,
                cvssScore = 7.2f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Kamera-Hardware",
                affectedApps = highRiskCameraApps,
                description = "Apps mit unerwarteter Kamera-Berechtigung gefunden: ${highRiskCameraApps.joinToString(", ")}. " +
                        "Apps die keine Kamera-Funktion haben, sollten keinen Kamera-Zugriff besitzen.",
                impact = "Heimliche Aktivierung der Kamera zur Überwachung möglich.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Prüfe jede App: Einstellungen → Apps → [App] → Berechtigungen → Kamera",
                        "Entziehe Kamera-Berechtigung für Apps ohne legitimen Bedarf.",
                        "Deinstalliere Apps, die du nicht erkennst."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.APPLICATION_DETAILS_SETTINGS",
                    officialDocUrl = "https://developer.android.com/training/permissions/usage-notes",
                    estimatedTime = "~10 Minuten"
                ),
                source = "PrivacyHardwareScanner"
            )
        }

        // Mikrofon-Zugriffswarnung
        // Mikrofon: "vpn"/"caller"/"launcher"/"flashlight" herausgenommen –
        // diese Apps können legitime Gründe für Mikrofon-Zugriff haben.
        val highRiskMicApps = micApps.filter { app ->
            val suspiciousKeywords = listOf("cleaner", "battery", "optimizer", "booster")
            suspiciousKeywords.any { app.lowercase().contains(it) }
        }
        if (highRiskMicApps.isNotEmpty()) {
            results += VulnerabilityEntry(
                id = "PRI-002",
                title = "${highRiskMicApps.size} verdächtige App(s) mit Mikrofon-Zugriff",
                severity = Severity.HIGH,
                cvssScore = 7.8f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                affectedComponent = "Mikrofon-Hardware",
                affectedApps = highRiskMicApps,
                description = "Apps mit unerwarteter Mikrofon-Berechtigung: ${highRiskMicApps.joinToString(", ")}. " +
                        "Diese können Umgebungsgeräusche und Gespräche aufzeichnen.",
                impact = "Heimliche Tonaufnahme von Gesprächen und Umgebungsgeräuschen.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Prüfe: Einstellungen → Apps → [App] → Berechtigungen → Mikrofon",
                        "Entziehe Mikrofon-Berechtigung für Apps ohne legitimen Bedarf (kein Anruf/Sprache).",
                        "Nutze die Mikrofon-Nutzungsanzeige (orangener Punkt oben rechts) zur Überwachung."
                    ),
                    automatable = false,
                    deepLinkSettings = "android.settings.APPLICATION_DETAILS_SETTINGS",
                    officialDocUrl = "https://developer.android.com/training/permissions/explaining-access",
                    estimatedTime = "~10 Minuten"
                ),
                source = "PrivacyHardwareScanner"
            )
        }

        return results
    }

    // ─── VPN ────────────────────────────────────────────────────────────────

    private fun checkVpnConnections(): VulnerabilityEntry? {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork ?: return null
            val capabilities = cm.getNetworkCapabilities(activeNetwork) ?: return null

            // VPN ist eine Sicherheitsfunktion, keine Schwachstelle.
            // Nur unseriöse/kostenlose VPN-Apps ohne klaren Anbieter sind problematisch.
            // Da wir den VPN-Anbieter nicht zuverlässig unterscheiden können, gibt es hier
            // keinen Befund – NetworkSecurityScanner empfiehlt VPN für öffentliche WLANs.
            null
        } catch (e: Exception) { null }
    }

    // ─── Akku-Optimierung Bypass ─────────────────────────────────────────────

    private fun checkBatteryOptimizationBypass(): VulnerabilityEntry? {
        return try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            val packageManager = context.packageManager
            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstalledPackages(0)
            }

            val bypassApps = packages.filter { pkg ->
                val isSystemApp = (pkg.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
                !isSystemApp && pm.isIgnoringBatteryOptimizations(pkg.packageName)
            }.map { pkg ->
                try { packageManager.getApplicationLabel(pkg.applicationInfo!!).toString() } catch (e: Exception) { pkg.packageName }
            }

            // Schwellwert >15: Ein typisches Gerät hat 8-12 Apps mit Akku-Optimierungsausnahme
            // (Gmail, WhatsApp, Signal, Maps, etc.). Erst ab >15 ist das verdächtig.
            if (bypassApps.size > 15) {
                VulnerabilityEntry(
                    id = "PRI-004",
                    title = "${bypassApps.size} Apps umgehen Akku-Optimierung (Hintergrundaktivität)",
                    severity = Severity.MEDIUM,
                    cvssScore = 4.5f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L",
                    affectedComponent = "Energieverwaltung / Doze Mode",
                    affectedApps = bypassApps.take(10),
                    description = "Diese Apps sind von der Android-Akku-Optimierung ausgenommen und " +
                            "können jederzeit im Hintergrund laufen, auch wenn das Gerät im Standby ist.",
                    impact = "Apps können uneingeschränkt im Hintergrund Daten sammeln, Netzwerkanfragen stellen und Ressourcen verbrauchen.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Prüfe: Einstellungen → Akku → Akku-Optimierung",
                            "Entferne Ausnahmen für Apps, die keine ständige Hintergrundaktivität benötigen.",
                            "Behalte Ausnahmen nur für: Messenger, E-Mail, Alarme und ähnliche Apps."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.IGNORE_BATTERY_OPTIMIZATION_SETTINGS",
                        officialDocUrl = "https://developer.android.com/training/monitoring-device-state/doze-standby",
                        estimatedTime = "~5 Minuten"
                    ),
                    source = "PrivacyHardwareScanner"
                )
            } else null
        } catch (e: Exception) { null }
    }

    // ─── Gefährliche System-Berechtigungen ───────────────────────────────────

    private fun checkDangerousSystemPermissions(): VulnerabilityEntry? {
        val dangerousSystemPerms = listOf(
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.WRITE_SETTINGS",
            "android.permission.DUMP",
            "android.permission.READ_LOGS",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.MANAGE_DEVICE_ADMINS",
            "android.permission.CHANGE_COMPONENT_ENABLED_STATE"
        )

        return try {
            val pm = context.packageManager
            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }

            val suspiciousApps = mutableListOf<Pair<String, List<String>>>()
            for (pkg in packages) {
                val isSystemApp = (pkg.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
                if (isSystemApp) continue
                val foundPerms = pkg.requestedPermissions?.filter { it in dangerousSystemPerms } ?: emptyList()
                if (foundPerms.isNotEmpty()) {
                    val appName = try { pm.getApplicationLabel(pkg.applicationInfo!!).toString() } catch (e: Exception) { pkg.packageName }
                    suspiciousApps += Pair(appName, foundPerms)
                }
            }

            if (suspiciousApps.isNotEmpty()) {
                val description = suspiciousApps.joinToString("\n") { (app, perms) ->
                    "$app: ${perms.joinToString { it.substringAfterLast(".") }}"
                }
                VulnerabilityEntry(
                    id = "PRI-005",
                    title = "${suspiciousApps.size} Drittanbieter-App(s) mit kritischen System-Berechtigungen",
                    severity = Severity.HIGH,
                    cvssScore = 8.1f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
                    affectedComponent = "Android-Systemberechtigungen",
                    affectedApps = suspiciousApps.map { it.first },
                    description = "Drittanbieter-Apps mit privilegierten System-Berechtigungen:\n$description",
                    impact = "Diese Apps können Systemeinstellungen ändern, Logs lesen oder Pakete installieren/deinstallieren.",
                    remediation = RemediationSteps(
                        priority = Priority.HIGH,
                        steps = listOf(
                            "Prüfe jede betroffene App auf Legitimität.",
                            "Deinstalliere unbekannte Apps mit System-Berechtigungen sofort.",
                            "Behalte solche Apps nur wenn sie von vertrauenswürdigen MDM- oder Sicherheitsanbietern stammen."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.APPLICATION_SETTINGS",
                        officialDocUrl = "https://developer.android.com/reference/android/Manifest.permission",
                        estimatedTime = "~15 Minuten"
                    ),
                    source = "PrivacyHardwareScanner"
                )
            } else null
        } catch (e: Exception) { null }
    }

    // ─── Root-Erkennung ──────────────────────────────────────────────────────

    private fun checkRootIndicators(): VulnerabilityEntry? {
        val indicators = mutableListOf<String>()

        // Su-Binary prüfen
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/su/bin/su"
        )
        if (suPaths.any { File(it).exists() }) indicators += "su-Binary gefunden"

        // Test-Keys (unsignierter Build)
        val buildTags = Build.TAGS ?: ""
        if (buildTags.contains("test-keys")) indicators += "Test-Keys (unsignierter Build)"

        // Bekannte Root-Management-Apps
        val rootApps = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global"
        )
        val pm = context.packageManager
        val installedRootApps = rootApps.filter { pkg ->
            try { pm.getPackageInfo(pkg, 0); true } catch (e: Exception) { false }
        }.map { pkg ->
            try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (e: Exception) { pkg }
        }
        if (installedRootApps.isNotEmpty()) {
            indicators += "Root-Apps: ${installedRootApps.joinToString(", ")}"
        }

        // Magisk Hide / Zygisk prüfen
        if (File("/data/adb/magisk").exists() || File("/data/adb/modules").exists()) {
            indicators += "Magisk-Verzeichnis gefunden"
        }

        // Schreibbarer /system-Mount: präzise Analyse zeilenweise
        // Falsch-Positive vermeiden: overlay/tmpfs-Mounts auf /system/apex etc. sind normal
        try {
            val proc = Runtime.getRuntime().exec("mount")
            val output = BufferedReader(InputStreamReader(proc.inputStream)).readText()
            proc.destroy()

            val systemRw = output.lines().any { line ->
                // Format: "<gerät> on <mountpoint> type <fstyp> (<optionen>)"
                val onIdx = line.indexOf(" on ")
                val typeIdx = line.indexOf(" type ")
                if (onIdx < 0 || typeIdx < 0 || typeIdx <= onIdx) return@any false

                val mountPoint = line.substring(onIdx + 4, typeIdx).trim()
                val afterType = line.substring(typeIdx + 6)
                val spaceAfterFs = afterType.indexOf(' ')
                val fsType = if (spaceAfterFs > 0) afterType.substring(0, spaceAfterFs) else afterType
                val options = line.substringAfterLast("(").substringBefore(")")
                val optionList = options.split(",").map { it.trim() }

                mountPoint == "/system"
                    && fsType !in setOf("overlay", "overlayfs", "tmpfs")
                    && optionList.contains("rw")
            }

            if (systemRw) indicators += "/system als read-write gemountet (mögliche Root-Manipulation)"
        } catch (_: Exception) {}

        val hasMagisk = installedRootApps.any { it.lowercase().contains("magisk") }
                || File("/data/adb/magisk").exists() || File("/data/adb/modules").exists()

        val remediationSteps = mutableListOf<String>()

        // Kontextspezifische Behebungsschritte
        if (hasMagisk) {
            remediationSteps += "Magisk erkannt: Öffne die Magisk-App → 'Deinstallation' → 'Vollständige Deinstallation'."
            remediationSteps += "Falls Magisk-App nicht mehr vorhanden: Fastboot-Deinstallation über Recovery erforderlich."
        }
        if (indicators.any { it.contains("su-Binary") }) {
            remediationSteps += "su-Binary gefunden: Wird normalerweise durch Magisk-Deinstallation entfernt."
            remediationSteps += "Alternativ: Root-Manager-App (z.B. Magisk, SuperSU) vollständig deinstallieren."
        }
        if (indicators.any { it.contains("Root-Apps") }) {
            remediationSteps += "Root-Management-Apps deinstallieren: Einstellungen → Apps → [App] → Deinstallieren."
        }
        if (indicators.any { it.contains("Test-Keys") }) {
            remediationSteps += "Test-Keys weisen auf ein inoffizielles ROM hin (Custom ROM)."
            remediationSteps += "Lösung: Offizielles Firmware-Image des Herstellers via Fastboot oder Odin flashen."
        }
        remediationSteps += "Falls Root nicht selbst installiert: Gerät auf Werkseinstellungen zurücksetzen."
        remediationSteps += "Nach Factory Reset alle Passwörter ändern, die auf dem Gerät verwendet wurden."
        remediationSteps += "Für Fastboot/Odin: Offizielle Anleitungen des Geräteherstellers nutzen."

        return if (indicators.isNotEmpty()) {
            VulnerabilityEntry(
                id = "PRI-006",
                title = "Root-Indikatoren gefunden (${indicators.size} Anzeichen)",
                severity = Severity.CRITICAL,
                cvssScore = 9.3f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                affectedComponent = "Android-Sicherheitsmodell (Root)",
                affectedApps = indicators,
                description = "Das Gerät zeigt folgende Anzeichen einer Root-Kompromittierung:\n" +
                        indicators.joinToString("\n• ", "• "),
                impact = "Alle Android-Sicherheitsmechanismen sind umgangen. Jede App kann unbegrenzt auf alle Daten zugreifen.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = remediationSteps,
                    automatable = false,
                    deepLinkSettings = "android.settings.APPLICATION_SETTINGS",
                    officialDocUrl = "https://source.android.com/docs/security/overview",
                    estimatedTime = "~30 Minuten bis 2 Stunden"
                ),
                source = "PrivacyHardwareScanner"
            )
        } else null
    }

    // ─── Offene Netzwerk-Ports ───────────────────────────────────────────────

    private fun checkOpenNetworkPorts(): VulnerabilityEntry? {
        return try {
            val suspiciousPorts = setOf(4444, 5555, 27042, 27043, 1604, 31337, 8888, 9999, 2323, 23)
            val openSuspiciousPorts = mutableListOf<Int>()

            for (procFile in listOf("/proc/net/tcp", "/proc/net/tcp6")) {
                try {
                    File(procFile).forEachLine { line ->
                        val parts = line.trim().split("\\s+".toRegex())
                        if (parts.size >= 4 && parts[0] != "sl") {
                            val localAddress = parts[1]
                            val state = parts[3]
                            if (state == "0A") { // LISTEN
                                val portHex = localAddress.substringAfter(":").take(4)
                                val port = portHex.toIntOrNull(16) ?: return@forEachLine
                                if (port in suspiciousPorts) openSuspiciousPorts += port
                            }
                        }
                    }
                } catch (_: Exception) {}
            }

            if (openSuspiciousPorts.isNotEmpty()) {
                val portDescriptions = openSuspiciousPorts.map { port ->
                    when (port) {
                        4444 -> "4444 (Metasploit/ADB)"
                        5555 -> "5555 (ADB over Network)"
                        27042, 27043 -> "$port (Frida Instrumentation)"
                        1604 -> "1604 (Stalkerware)"
                        31337 -> "31337 (Backdoor/Elite)"
                        2323, 23 -> "$port (Telnet – unsicher)"
                        else -> "$port"
                    }
                }
                VulnerabilityEntry(
                    id = "PRI-007",
                    title = "${openSuspiciousPorts.size} verdächtige(r) offene(r) Port(s) gefunden",
                    severity = Severity.CRITICAL,
                    cvssScore = 9.8f,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    affectedComponent = "Netzwerk-Sockets",
                    description = "Kritische Ports offen: ${portDescriptions.joinToString(", ")}. " +
                            "Diese deuten auf Backdoors, Remote-Access-Tools oder Instrumentation hin.",
                    impact = "Entfernter Zugriff auf das Gerät ohne Authentifizierung möglich.",
                    remediation = RemediationSteps(
                        priority = Priority.IMMEDIATE,
                        steps = listOf(
                            "Identifiziere die Prozesse hinter diesen Ports.",
                            "Port 5555: Deaktiviere ADB über WLAN in den Entwickleroptionen.",
                            "Unbekannte Ports: Führe sofort einen Factory Reset durch.",
                            "Stelle keine Verbindung zu öffentlichen WLAN-Netzwerken her bis das Problem behoben ist."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                        officialDocUrl = "https://developer.android.com/studio/command-line/adb",
                        estimatedTime = "~30 Minuten"
                    ),
                    source = "PrivacyHardwareScanner"
                )
            } else null
        } catch (e: Exception) { null }
    }

    // ─── Boot-Receiver Apps ──────────────────────────────────────────────────

    private fun checkBootReceiverApps(): VulnerabilityEntry? {
        return try {
            val pm = context.packageManager
            val bootIntent = Intent(Intent.ACTION_BOOT_COMPLETED)
            val receivers = pm.queryBroadcastReceivers(bootIntent, PackageManager.GET_RESOLVED_FILTER)

            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager

            val suspiciousBootApps = receivers
                .map { it.activityInfo.packageName }
                .distinct()
                .filter { pkg ->
                    try {
                        val info = pm.getApplicationInfo(pkg, 0)
                        val isSystem = (info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                        if (isSystem || pkg == context.packageName) return@filter false

                        // Apps ausschließen, bei denen "Hintergrundnutzung" deaktiviert wurde
                        // (OP_RUN_ANY_IN_BACKGROUND → MODE_IGNORED = eingeschränkt)
                        val bgRestricted = try {
                            val opResult = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                appOps.unsafeCheckOpNoThrow(
                                    "android:run_any_in_background", info.uid, pkg
                                )
                            } else {
                                @Suppress("DEPRECATION")
                                appOps.checkOpNoThrow(
                                    "android:run_any_in_background", info.uid, pkg
                                )
                            }
                            opResult == AppOpsManager.MODE_IGNORED
                        } catch (_: Exception) { false }

                        !bgRestricted
                    } catch (_: Exception) { false }
                }
                .mapNotNull { pkg ->
                    try {
                        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
                    } catch (_: Exception) { null }
                }

            // Schwellwert >15: Moderne Geräte haben typischerweise 10-20 Apps mit BOOT_COMPLETED
            // (Messenger, Kalender, Alarm-Apps, Synchronisierungs-Dienste).
            if (suspiciousBootApps.size > 15) {
                VulnerabilityEntry(
                    id = "PRI-008",
                    title = "${suspiciousBootApps.size} Drittanbieter-Apps können beim Boot starten",
                    severity = Severity.MEDIUM,
                    cvssScore = 4.8f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                    affectedComponent = "Auto-Start (BOOT_COMPLETED)",
                    affectedApps = suspiciousBootApps.take(10),
                    description = "Diese Apps haben einen Boot-Receiver registriert und können beim Gerätestart aktiv werden: " +
                            "${suspiciousBootApps.take(8).joinToString(", ")}.\n" +
                            "Hinweis: Apps, die bereits durch Android eingeschränkt sind (z.B. durch 'Eingeschränkt' im Akku-Menü), " +
                            "werden hier trotzdem angezeigt, da sie technisch registriert sind.",
                    impact = "Zu viele Auto-Start-Apps verlangsamen den Boot und können unerwünschte Hintergrundprozesse starten.",
                    remediation = RemediationSteps(
                        priority = Priority.LOW,
                        steps = listOf(
                            "Prüfe unter 'Akku-Optimierung' welche Apps Ausnahmen haben.",
                            "Apps bereits einschränken: Einstellungen → Apps → [App] → Akku → Einschränken",
                            "Übersicht App-Energieverbrauch: Einstellungen → Akku → Akku-Nutzung",
                            "Deinstalliere unbekannte Apps, die du nicht benötigst."
                        ),
                        automatable = false,
                        deepLinkSettings = "android.settings.IGNORE_BATTERY_OPTIMIZATION_SETTINGS",
                        officialDocUrl = "https://developer.android.com/training/monitoring-device-state/doze-standby",
                        estimatedTime = "~10 Minuten"
                    ),
                    source = "PrivacyHardwareScanner"
                )
            } else null
        } catch (e: Exception) { null }
    }

    // ─── Frida / Instrumentierung ────────────────────────────────────────────

    private fun checkFridaAndInstrumentation(): VulnerabilityEntry? {
        val indicators = mutableListOf<String>()

        // Frida-Port prüfen
        try {
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 100)
            socket.close()
            indicators += "Frida-Server Port 27042 offen"
        } catch (_: Exception) {}

        try {
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress("127.0.0.1", 27043), 100)
            socket.close()
            indicators += "Frida-Server Port 27043 offen"
        } catch (_: Exception) {}

        // Frida-bezogene Bibliotheken prüfen
        val fridaLibPaths = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/frida-gadget.so",
            "/sdcard/frida-server"
        )
        if (fridaLibPaths.any { File(it).exists() }) {
            indicators += "Frida-Binärdateien gefunden"
        }

        // Frida-Prozess in /proc
        try {
            File("/proc").listFiles()?.forEach { pidDir ->
                if (pidDir.isDirectory && pidDir.name.all { it.isDigit() }) {
                    val cmdline = File(pidDir, "cmdline").readText().lowercase()
                    if (cmdline.contains("frida") || cmdline.contains("gadget")) {
                        indicators += "Frida-Prozess läuft (PID: ${pidDir.name})"
                        return@forEach
                    }
                }
            }
        } catch (_: Exception) {}

        return if (indicators.isNotEmpty()) {
            VulnerabilityEntry(
                id = "PRI-009",
                title = "Frida/Instrumentation-Framework erkannt",
                severity = Severity.CRITICAL,
                cvssScore = 10.0f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                isActivelyExploited = true,
                affectedComponent = "Prozess-Integrität",
                description = "Frida Instrumentation Framework wurde erkannt: ${indicators.joinToString("; ")}. " +
                        "Frida ermöglicht das Einhängen in jeden Prozess und das Abfangen aller Daten.",
                impact = "Alle verschlüsselten Verbindungen, Passwörter und Kryptoschlüssel können abgefangen werden.",
                remediation = RemediationSteps(
                    priority = Priority.IMMEDIATE,
                    steps = listOf(
                        "SOFORT: Trenne das Gerät vom Netzwerk.",
                        "Führe einen vollständigen Factory Reset durch.",
                        "Ändere alle Passwörter die auf dem Gerät verwendet wurden.",
                        "Prüfe ob das Gerät in einem Pentest-Szenario eingesetzt wird."
                    ),
                    automatable = false,
                    officialDocUrl = "https://frida.re/docs/android/",
                    estimatedTime = "~2 Stunden"
                ),
                source = "PrivacyHardwareScanner"
            )
        } else null
    }

    // ─── Logcat-Analyse ──────────────────────────────────────────────────────

    private fun checkLogcatForSecurityIssues(): VulnerabilityEntry? {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("logcat", "-d", "-t", "500", "*:W"))
            val output = BufferedReader(InputStreamReader(process.inputStream)).readLines()
            process.destroy()

            val securityKeywords = mapOf(
                "permission denied" to "Berechtigungsfehler",
                "ssl error" to "SSL/TLS-Fehler",
                "certificate" to "Zertifikatsproblem",
                "cleartext" to "Klartext-HTTP-Datenverkehr",
                "insecure" to "Unsichere Verbindung",
                "leaked" to "Datenleck",
                "injection" to "Injection-Versuch",
                "overflow" to "Buffer Overflow"
            )

            val foundIssues = mutableMapOf<String, Int>()
            for (line in output) {
                val lowerLine = line.lowercase()
                for ((keyword, label) in securityKeywords) {
                    if (keyword in lowerLine) {
                        foundIssues[label] = (foundIssues[label] ?: 0) + 1
                    }
                }
            }

            if (foundIssues.isNotEmpty()) {
                val summary = foundIssues.entries
                    .sortedByDescending { it.value }
                    .take(5)
                    .joinToString(", ") { "${it.key}: ${it.value}x" }

                VulnerabilityEntry(
                    id = "PRI-010",
                    title = "Sicherheitsrelevante Logcat-Einträge gefunden",
                    severity = Severity.MEDIUM,
                    cvssScore = 5.3f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    affectedComponent = "System-Log (Logcat)",
                    description = "Der Systemlog enthält sicherheitsrelevante Warnungen: $summary",
                    impact = "Hinweise auf Sicherheitsprobleme, Berechtigungsfehler oder unsichere Verbindungen im Betrieb.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Analysiere die vollständigen Logs via Android Studio → Logcat.",
                            "Suche nach Apps die wiederholt Berechtigungsfehler verursachen.",
                            "Cleartext-Warnungen: Betroffene Apps nutzen unsicheres HTTP statt HTTPS.",
                            "Zertifikatsfehler: Kann auf Man-in-the-Middle-Angriffe hinweisen."
                        ),
                        automatable = false,
                        officialDocUrl = "https://developer.android.com/studio/debug/am-logcat",
                        estimatedTime = "~20 Minuten"
                    ),
                    source = "PrivacyHardwareScanner"
                )
            } else null
        } catch (e: Exception) { null }
    }

    // ─── Verdächtige Prozesse ────────────────────────────────────────────────

    private fun checkSuspiciousProcesses(): VulnerabilityEntry? {
        return try {
            val suspiciousProcessKeywords = listOf("tcpdump", "strace", "gdbserver", "nmap", "netcat", "nc ", "socat", "busybox")
            val foundProcesses = mutableListOf<String>()

            File("/proc").listFiles()?.forEach { pidDir ->
                if (pidDir.isDirectory && pidDir.name.all { it.isDigit() }) {
                    try {
                        val cmdline = File(pidDir, "cmdline").readText().replace('\u0000', ' ').trim().lowercase()
                        val matched = suspiciousProcessKeywords.find { cmdline.contains(it) }
                        if (matched != null && cmdline.isNotEmpty()) {
                            foundProcesses += cmdline.take(50)
                        }
                    } catch (_: Exception) {}
                }
            }

            if (foundProcesses.isNotEmpty()) {
                VulnerabilityEntry(
                    id = "PRI-011",
                    title = "${foundProcesses.size} verdächtige(r) Prozess(e) aktiv",
                    severity = Severity.HIGH,
                    cvssScore = 7.5f,
                    cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    affectedComponent = "Prozessliste",
                    description = "Sicherheitsrelevante Prozesse laufen: ${foundProcesses.take(5).joinToString("; ")}. " +
                            "Diese Werkzeuge können für Netzwerkanalyse, Prozess-Überwachung oder Angriffe genutzt werden.",
                    impact = "Aktive Überwachungs- oder Angriffswerkzeuge können Daten abfangen.",
                    remediation = RemediationSteps(
                        priority = Priority.HIGH,
                        steps = listOf(
                            "Identifiziere welche App diese Prozesse gestartet hat.",
                            "Falls kein legitimer Grund bekannt: Gerät sofort vom Netzwerk trennen.",
                            "Factory Reset durchführen.",
                            "Nur bei Pentest/Security-Research: Prüfe ob du diese Tools selbst installiert hast."
                        ),
                        automatable = false,
                        officialDocUrl = "https://source.android.com/docs/security",
                        estimatedTime = "~30 Minuten"
                    ),
                    source = "PrivacyHardwareScanner"
                )
            } else null
        } catch (e: Exception) { null }
    }
}
