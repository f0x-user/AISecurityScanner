package com.mobilesecurity.scanner.domain.scanner

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.mobilesecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * SurveillanceScanner – detects indicators of stalkerware, spyware and covert
 * surveillance tooling ("Staatstrojaner" / commercial monitoring apps).
 *
 * Honesty note (important, do not remove):
 * A non-root user-space app CANNOT reliably detect or remove a nation-state
 * implant (e.g. Pegasus/Predator class). Those abuse 0-day kernel exploits,
 * run with system/root privileges, often live only in memory and actively hide
 * from the very APIs this scanner uses. This module therefore reports
 * INDICATORS that are observable from user space:
 *   1. Installed packages matching a known stalkerware IoC database (Echap).
 *   2. Apps hidden from the launcher that hold a surveillance permission cluster.
 *   3. Non-system notification listeners (can read every message preview).
 *   4. Non-system device-admin apps (used by spyware to block uninstall).
 * A match is a strong signal; the absence of matches is NOT proof of a clean
 * device. Findings are phrased accordingly.
 */
class SurveillanceScanner @Inject constructor(private val context: Context) {

    /** Permissions that, in combination, characterise covert surveillance. */
    private val surveillancePermissions = setOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
    )

    /** Installers that are considered trustworthy (not sideloaded). */
    private val trustedInstallers = setOf(
        "com.android.vending",
        "com.google.android.feedback",
        "com.amazon.venezia",
        "org.fdroid.fdroid",
        "com.aurora.store",
        "com.sec.android.app.samsungapps",
        "com.huawei.appmarket",
        "com.xiaomi.market",
        "com.oppo.market",
        "com.vivo.appstore"
    )

    private var cachedIocs: Set<String>? = null

    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()
        val packages = installedPackagesWithPermissions()

        findings += checkKnownStalkerware(packages)
        findings += checkHiddenSurveillanceApps(packages)
        findings += checkNotificationListeners()
        findings += checkSurveillanceDeviceAdmins()

        findings.filterNotNull()
    }

    // -------------------------------------------------------------------------
    // 1. Known stalkerware IoC match (bundled Echap database)
    // -------------------------------------------------------------------------

    private fun checkKnownStalkerware(packages: List<PackageInfo>): VulnerabilityEntry? {
        val iocs = loadIocs()
        if (iocs.isEmpty()) return null

        val hits = packages
            .filter { it.packageName.lowercase() in iocs }
            .map { pkg -> "${appLabel(pkg)} (${pkg.packageName})" }

        if (hits.isEmpty()) return null

        return VulnerabilityEntry(
            id = "SPY-001",
            title = "${hits.size} known surveillance/stalkerware app(s) installed",
            severity = Severity.CRITICAL,
            cvssScore = 9.8f,
            cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            isActivelyExploited = true,
            affectedComponent = "Installed applications",
            affectedApps = hits,
            description = "One or more installed packages match a curated database of " +
                "documented stalkerware/spyware (Echap indicators): " +
                hits.joinToString(", ") + ". Such apps are built to secretly monitor " +
                "location, messages, calls, microphone and camera.",
            impact = "Full covert surveillance of the device and its owner. If the app was " +
                "installed by another person, treat physical safety as a priority.",
            remediation = RemediationSteps(
                priority = Priority.IMMEDIATE,
                steps = listOf(
                    "Consider your personal safety first: if someone may have installed this " +
                        "app, removing it can alert them. If you are at risk, seek support before acting.",
                    "Revoke Device Admin for the app: Settings -> Security -> Device admin apps.",
                    "Uninstall the app: Settings -> Apps -> [app] -> Uninstall.",
                    "If it cannot be uninstalled, back up your data and perform a factory reset.",
                    "Afterwards change all passwords from a different, trusted device and enable 2FA."
                ),
                automatable = false,
                deepLinkSettings = Settings.ACTION_SECURITY_SETTINGS,
                officialDocUrl = "https://stopstalkerware.org/",
                estimatedTime = "~30 min + password rotation"
            ),
            source = "SurveillanceScanner"
        )
    }

    // -------------------------------------------------------------------------
    // 2. Hidden apps with surveillance permission cluster
    // -------------------------------------------------------------------------

    private fun checkHiddenSurveillanceApps(packages: List<PackageInfo>): VulnerabilityEntry? {
        val pm = context.packageManager
        val suspects = mutableListOf<String>()

        for (pkg in packages) {
            if (pkg.packageName == context.packageName) continue
            if (isSystemApp(pkg)) continue
            if (!isSideloaded(pkg.packageName)) continue

            // No launcher entry == hidden from the app drawer, a hallmark of covert spyware.
            val hasLauncherIcon = pm.getLaunchIntentForPackage(pkg.packageName) != null
            if (hasLauncherIcon) continue

            val requested = pkg.requestedPermissions?.toSet() ?: emptySet()
            val matched = surveillancePermissions.intersect(requested)
            val hasSensitiveCore = matched.any {
                it == "android.permission.RECORD_AUDIO" ||
                    it == "android.permission.CAMERA" ||
                    it == "android.permission.READ_SMS" ||
                    it == "android.permission.ACCESS_FINE_LOCATION"
            }
            if (matched.size >= 3 && hasSensitiveCore) {
                suspects += "${appLabel(pkg)} (${pkg.packageName})"
            }
        }

        if (suspects.isEmpty()) return null

        return VulnerabilityEntry(
            id = "SPY-002",
            title = "${suspects.size} hidden app(s) with a surveillance permission profile",
            severity = Severity.HIGH,
            cvssScore = 8.1f,
            cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            affectedComponent = "Installed applications",
            affectedApps = suspects,
            description = "Sideloaded app(s) with no launcher icon requesting a combination of " +
                "microphone/camera/SMS/location permissions: " + suspects.joinToString(", ") +
                ". Hiding from the app drawer while requesting these permissions is a classic " +
                "covert-spyware pattern.",
            impact = "Possible silent recording of audio/video, message interception or location tracking.",
            remediation = RemediationSteps(
                priority = Priority.HIGH,
                steps = listOf(
                    "Review each app under Settings -> Apps -> Show system / all apps.",
                    "Revoke its permissions and uninstall it if you did not install it deliberately.",
                    "Check Settings -> Security -> Device admin apps in case it resists uninstall."
                ),
                automatable = false,
                deepLinkSettings = Settings.ACTION_APPLICATION_SETTINGS,
                officialDocUrl = "https://support.google.com/android/answer/9596555",
                estimatedTime = "~10 min"
            ),
            source = "SurveillanceScanner"
        )
    }

    // -------------------------------------------------------------------------
    // 3. Non-system notification listeners (read every message preview)
    // -------------------------------------------------------------------------

    private fun checkNotificationListeners(): VulnerabilityEntry? {
        val enabled = try {
            Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners"
            )
        } catch (_: Exception) {
            return null
        } ?: return null

        val listeners = enabled.split(":")
            .map { it.substringBefore("/") }
            .filter { it.isNotEmpty() && it != context.packageName }
            .distinct()
            .filter { pkg -> !isSystemPackage(pkg) }

        if (listeners.isEmpty()) return null

        return VulnerabilityEntry(
            id = "SPY-003",
            title = "${listeners.size} non-system app(s) can read all notifications",
            severity = Severity.MEDIUM,
            cvssScore = 6.5f,
            cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            affectedComponent = "Notification Listener Service",
            affectedApps = listeners,
            description = "The following apps have notification-listener access and can read the " +
                "content of every notification, including message previews from Signal, WhatsApp, " +
                "SMS and 2FA codes: " + listeners.joinToString(", ") + ".",
            impact = "Bypasses end-to-end encryption at the display layer: chat previews and one-time " +
                "codes can be exfiltrated without ever touching the messenger itself.",
            remediation = RemediationSteps(
                priority = Priority.NORMAL,
                steps = listOf(
                    "Open Settings -> Notifications -> Device & app notifications (notification access).",
                    "Disable access for any app you do not explicitly trust.",
                    "Be especially wary of apps you did not knowingly grant this to."
                ),
                automatable = false,
                deepLinkSettings = "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS",
                officialDocUrl = "https://support.google.com/android/answer/9079584",
                estimatedTime = "~5 min"
            ),
            source = "SurveillanceScanner"
        )
    }

    // -------------------------------------------------------------------------
    // 4. Non-system device-admin apps (used to block uninstall)
    // -------------------------------------------------------------------------

    private fun checkSurveillanceDeviceAdmins(): VulnerabilityEntry? {
        val dpm = try {
            context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        } catch (_: Exception) {
            return null
        }

        val admins = dpm.activeAdmins ?: return null
        val suspicious = admins
            .map { it.packageName }
            .distinct()
            .filter { it != context.packageName && !isSystemPackage(it) && isSideloaded(it) }

        if (suspicious.isEmpty()) return null

        return VulnerabilityEntry(
            id = "SPY-004",
            title = "${suspicious.size} sideloaded app(s) hold Device Admin rights",
            severity = Severity.HIGH,
            cvssScore = 7.6f,
            cvssVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            affectedComponent = "Device Administration API",
            affectedApps = suspicious,
            description = "Sideloaded app(s) are registered as Device Administrators: " +
                suspicious.joinToString(", ") + ". Spyware commonly requests this to make itself " +
                "hard to uninstall and to survive removal attempts.",
            impact = "The app can enforce policies, wipe data and resist normal uninstallation.",
            remediation = RemediationSteps(
                priority = Priority.HIGH,
                steps = listOf(
                    "Open Settings -> Security -> Device admin apps.",
                    "Deactivate admin rights for any app you do not recognise.",
                    "Then uninstall the app under Settings -> Apps."
                ),
                automatable = false,
                deepLinkSettings = Settings.ACTION_SECURITY_SETTINGS,
                officialDocUrl = "https://support.google.com/android/answer/9459346",
                estimatedTime = "~10 min"
            ),
            source = "SurveillanceScanner"
        )
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun loadIocs(): Set<String> {
        cachedIocs?.let { return it }
        val result = try {
            context.assets.open("stalkerware_appids.txt").bufferedReader().useLines { lines ->
                lines.map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { it.lowercase() }
                    .toSet()
            }
        } catch (_: Exception) {
            emptySet()
        }
        cachedIocs = result
        return result
    }

    private fun installedPackagesWithPermissions(): List<PackageInfo> {
        val pm = context.packageManager
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun appLabel(pkg: PackageInfo): String {
        val info = pkg.applicationInfo ?: return pkg.packageName
        return try {
            context.packageManager.getApplicationLabel(info).toString()
        } catch (_: Exception) {
            pkg.packageName
        }
    }

    private fun isSystemApp(pkg: PackageInfo): Boolean {
        val flags = pkg.applicationInfo?.flags ?: 0
        return flags and ApplicationInfo.FLAG_SYSTEM != 0
    }

    private fun isSystemPackage(packageName: String): Boolean {
        return try {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            info.flags and ApplicationInfo.FLAG_SYSTEM != 0
        } catch (_: Exception) {
            false
        }
    }

    private fun isSideloaded(packageName: String): Boolean {
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching {
                context.packageManager.getInstallSourceInfo(packageName).installingPackageName
            }.getOrNull()
        } else {
            @Suppress("DEPRECATION")
            runCatching { context.packageManager.getInstallerPackageName(packageName) }.getOrNull()
        }
        return installer == null || installer.isEmpty() || installer !in trustedInstallers
    }
}
