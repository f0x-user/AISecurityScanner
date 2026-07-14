package com.mobilesecurity.scanner.domain.integrity

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.edit
import com.mobilesecurity.scanner.domain.model.Severity
import com.squareup.moshi.Moshi
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Captures and compares the device's security-relevant state (Ist vs. Soll).
 *
 * The idea: many compromises – including implants that cannot be fingerprinted –
 * still *change* the observable configuration (a new device admin, a new
 * accessibility service, a downgraded patch level, a re-flashed system image,
 * a newly appeared root binary). By storing a trusted baseline and reporting
 * every deviation, we surface the change even when we cannot name the malware.
 *
 * The baseline is stored in EncryptedSharedPreferences and never leaves the device.
 */
@Singleton
class IntegrityBaselineManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val encryptedPrefs: SharedPreferences,
    moshi: Moshi
) {
    private val adapter = moshi.adapter(IntegrityState::class.java)

    companion object {
        private const val KEY_BASELINE = "integrity_baseline_json"
    }

    fun hasBaseline(): Boolean = encryptedPrefs.getString(KEY_BASELINE, null) != null

    fun getBaseline(): IntegrityState? {
        val json = encryptedPrefs.getString(KEY_BASELINE, null) ?: return null
        return try {
            adapter.fromJson(json)
        } catch (_: Exception) {
            null
        }
    }

    suspend fun saveBaseline(state: IntegrityState) = withContext(Dispatchers.IO) {
        encryptedPrefs.edit { putString(KEY_BASELINE, adapter.toJson(state)) }
    }

    /** Captures the current state and persists it as the new trusted baseline. */
    suspend fun captureAndStoreBaseline(): IntegrityState {
        val state = captureCurrentState()
        saveBaseline(state)
        return state
    }

    /** Compares the current state (Ist) against the stored baseline (Soll). */
    suspend fun compareWithBaseline(): IntegrityDiff = withContext(Dispatchers.IO) {
        val current = captureCurrentState()
        val baseline = getBaseline()
            ?: return@withContext IntegrityDiff(
                hasBaseline = false,
                baselineCapturedAt = null,
                current = current,
                changes = emptyList()
            )
        IntegrityDiff(
            hasBaseline = true,
            baselineCapturedAt = baseline.capturedAt,
            current = current,
            changes = diff(baseline, current)
        )
    }

    suspend fun captureCurrentState(): IntegrityState = withContext(Dispatchers.IO) {
        IntegrityState(
            capturedAt = System.currentTimeMillis(),
            androidRelease = Build.VERSION.RELEASE ?: "unknown",
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "unknown",
            buildFingerprint = Build.FINGERPRINT ?: "unknown",
            buildTags = Build.TAGS ?: "unknown",
            bootloaderLocked = getSystemProperty("ro.boot.flash.locked").ifEmpty { "unknown" },
            verifiedBootState = getSystemProperty("ro.boot.verifiedbootstate").ifEmpty { "unknown" },
            rooted = detectRoot(),
            installedPackages = readInstalledPackages(),
            deviceAdmins = readDeviceAdmins(),
            accessibilityServices = readSecureList(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES),
            notificationListeners = readSecureList("enabled_notification_listeners")
        )
    }

    // -------------------------------------------------------------------------
    // Diff logic
    // -------------------------------------------------------------------------

    private fun diff(baseline: IntegrityState, current: IntegrityState): List<IntegrityChange> {
        val changes = mutableListOf<IntegrityChange>()

        // Security patch level – a downgrade is a strong tampering signal.
        if (baseline.securityPatch != current.securityPatch) {
            val downgrade = current.securityPatch < baseline.securityPatch &&
                current.securityPatch != "unknown"
            changes += IntegrityChange(
                category = "Security patch level",
                kind = ChangeKind.CHANGED,
                detail = "${baseline.securityPatch} -> ${current.securityPatch}",
                severity = if (downgrade) Severity.CRITICAL else Severity.INFO,
                advice = if (downgrade)
                    "The patch level went BACKWARDS. A genuine update never lowers it – this can " +
                        "indicate a re-flashed or tampered system image. Verify and consider a factory reset."
                else
                    "Patch level increased – this is expected after a system update."
            )
        }

        // System build fingerprint – changes on OTA updates but also on re-flash / implant.
        if (baseline.buildFingerprint != current.buildFingerprint) {
            changes += IntegrityChange(
                category = "System image (build fingerprint)",
                kind = ChangeKind.CHANGED,
                detail = "changed since baseline",
                severity = Severity.HIGH,
                advice = "The system image identity changed. If you did NOT just install an official " +
                    "system update, this can indicate a re-flashed OS. Re-establish the baseline only " +
                    "after confirming the update was legitimate."
            )
        }

        // Verified boot state / bootloader lock.
        if (baseline.verifiedBootState != current.verifiedBootState) {
            changes += IntegrityChange(
                category = "Verified boot state",
                kind = ChangeKind.CHANGED,
                detail = "${baseline.verifiedBootState} -> ${current.verifiedBootState}",
                severity = Severity.CRITICAL,
                advice = "Verified boot protects the OS integrity chain. A change to 'orange'/'yellow'/'red' " +
                    "means the boot chain is no longer fully trusted."
            )
        }
        if (baseline.bootloaderLocked != current.bootloaderLocked) {
            changes += IntegrityChange(
                category = "Bootloader lock state",
                kind = ChangeKind.CHANGED,
                detail = "${baseline.bootloaderLocked} -> ${current.bootloaderLocked}",
                severity = Severity.CRITICAL,
                advice = "An unlocked bootloader lets anyone flash software onto the device. If you did " +
                    "not unlock it yourself, treat the device as compromised."
            )
        }

        // Root status.
        if (current.rooted && !baseline.rooted) {
            changes += IntegrityChange(
                category = "Root access",
                kind = ChangeKind.CHANGED,
                detail = "root indicators newly present",
                severity = Severity.CRITICAL,
                advice = "Root binaries (su/Magisk) appeared since the baseline. If you did not root the " +
                    "device, malware or a spyware installer may have gained elevated privileges."
            )
        }

        // Build tags going to test-keys.
        if (baseline.buildTags != current.buildTags && current.buildTags.contains("test-keys")) {
            changes += IntegrityChange(
                category = "Build tags",
                kind = ChangeKind.CHANGED,
                detail = "${baseline.buildTags} -> ${current.buildTags}",
                severity = Severity.HIGH,
                advice = "The build is now signed with test-keys, typical of a custom/unofficial ROM."
            )
        }

        // Newly registered device admins – classic anti-uninstall persistence.
        (current.deviceAdmins - baseline.deviceAdmins.toSet()).forEach {
            changes += IntegrityChange(
                category = "Device admin",
                kind = ChangeKind.ADDED,
                detail = it,
                severity = Severity.HIGH,
                advice = "A new app gained Device Admin rights. Spyware uses this to resist uninstallation. " +
                    "Revoke it under Settings -> Security -> Device admin apps if unexpected."
            )
        }

        // Newly enabled accessibility services – can read the whole screen / act as keylogger.
        (current.accessibilityServices - baseline.accessibilityServices.toSet()).forEach {
            changes += IntegrityChange(
                category = "Accessibility service",
                kind = ChangeKind.ADDED,
                detail = it,
                severity = Severity.HIGH,
                advice = "A new accessibility service was enabled. These can read all screen content and " +
                    "input. Disable it under Settings -> Accessibility if you did not enable it."
            )
        }

        // Newly enabled notification listeners – read every message preview.
        (current.notificationListeners - baseline.notificationListeners.toSet()).forEach {
            changes += IntegrityChange(
                category = "Notification listener",
                kind = ChangeKind.ADDED,
                detail = it,
                severity = Severity.MEDIUM,
                advice = "A new app can read all notifications (incl. chat previews and 2FA codes). " +
                    "Revoke it under Settings -> Notifications -> Notification access if unexpected."
            )
        }

        // Newly installed packages.
        val newPackages = current.installedPackages - baseline.installedPackages.toSet()
        newPackages.forEach {
            changes += IntegrityChange(
                category = "Installed app",
                kind = ChangeKind.ADDED,
                detail = it,
                severity = Severity.MEDIUM,
                advice = "This app was installed after the baseline was taken. Confirm you installed it " +
                    "deliberately from a trusted source."
            )
        }

        return changes
    }

    // -------------------------------------------------------------------------
    // Capture helpers
    // -------------------------------------------------------------------------

    private fun readInstalledPackages(): List<String> {
        val pm = context.packageManager
        return try {
            val pkgs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
            pkgs.map { it.packageName }.sorted()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun readDeviceAdmins(): List<String> {
        return try {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.activeAdmins?.map { it.packageName }?.distinct()?.sorted() ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun readSecureList(key: String): List<String> {
        return try {
            val raw = Settings.Secure.getString(context.contentResolver, key) ?: return emptyList()
            raw.split(":")
                .map { it.substringBefore("/") }
                .filter { it.isNotEmpty() }
                .distinct()
                .sorted()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun detectRoot(): Boolean {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk",
            "/data/adb/magisk", "/data/adb/ksu"
        )
        return try {
            suPaths.any { File(it).exists() }
        } catch (_: Exception) {
            false
        }
    }

    private fun getSystemProperty(key: String): String {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, key) as? String) ?: ""
        } catch (_: Exception) {
            ""
        }
    }
}
