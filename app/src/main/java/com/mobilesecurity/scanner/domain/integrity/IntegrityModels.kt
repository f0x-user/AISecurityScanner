package com.mobilesecurity.scanner.domain.integrity

import com.mobilesecurity.scanner.domain.model.Severity
import com.squareup.moshi.JsonClass

/**
 * A point-in-time capture of the security-relevant state of the device.
 * The stored instance is the "Soll" (baseline); a freshly captured one is the "Ist".
 * Drift between the two is what reveals an otherwise invisible compromise.
 */
@JsonClass(generateAdapter = true)
data class IntegrityState(
    val capturedAt: Long,
    val androidRelease: String,
    val sdkInt: Int,
    val securityPatch: String,
    val buildFingerprint: String,
    val buildTags: String,
    val bootloaderLocked: String,
    val verifiedBootState: String,
    val rooted: Boolean,
    val installedPackages: List<String>,
    val deviceAdmins: List<String>,
    val accessibilityServices: List<String>,
    val notificationListeners: List<String>
)

enum class ChangeKind { ADDED, REMOVED, CHANGED }

/** A single difference between the baseline (Soll) and the current state (Ist). */
data class IntegrityChange(
    val category: String,
    val kind: ChangeKind,
    val detail: String,
    val severity: Severity,
    val advice: String
)

/** Result of comparing the current state against the stored baseline. */
data class IntegrityDiff(
    val hasBaseline: Boolean,
    val baselineCapturedAt: Long?,
    val current: IntegrityState,
    val changes: List<IntegrityChange>
) {
    val isClean: Boolean get() = hasBaseline && changes.isEmpty()
}
