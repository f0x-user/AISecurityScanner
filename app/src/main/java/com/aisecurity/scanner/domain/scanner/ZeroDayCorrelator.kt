package com.aisecurity.scanner.domain.scanner

import android.os.Build
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.data.repository.VulnerabilityRepository
import com.aisecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import javax.inject.Inject

class ZeroDayCorrelator @Inject constructor(
    private val vulnRepository: VulnerabilityRepository,
    private val settingsRepository: SettingsRepository
) {

    suspend fun correlate(depth: ScanDepth = ScanDepth.STANDARD): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val settings = settingsRepository.settings.first()
        if (settings.offlineMode || settings.localOnlyMode) {
            return@withContext emptyList()
        }

        val findings = mutableListOf<VulnerabilityEntry>()

        val securityPatchLevel = Build.VERSION.SECURITY_PATCH
        val androidVersion = Build.VERSION.RELEASE
        val apiLevel = Build.VERSION.SDK_INT

        // CVSS-Mindestgrenze je nach Scan-Tiefe:
        // STANDARD: Nur High/Critical (≥7.0), DEEP: auch Medium (≥4.0), FORENSIC: alle (≥0.1)
        val minCvssThreshold = when (depth) {
            ScanDepth.STANDARD -> 7.0f
            ScanDepth.DEEP     -> 4.0f
            ScanDepth.FORENSIC -> 0.1f
            ScanDepth.QUICK    -> 9.0f  // Quick läuft den ZeroDayCorrelator gar nicht – aber sicher ist sicher
        }

        // CISA KEV: Aktiv ausgenutzte CVEs abrufen
        val activelyExploitedIds = vulnRepository.getActivelyExploitedCveIds()

        // NVD: Android-CVEs für aktuelle Version abrufen
        val nvdCves = vulnRepository.searchAndroidCves(securityPatchLevel)

        for (cve in nvdCves) {
            val metrics = cve.metrics?.cvssV31?.firstOrNull()
                ?: cve.metrics?.cvssV30?.firstOrNull()
            val cvssScore = metrics?.cvssData?.baseScore?.toFloat() ?: 0f
            if (cvssScore < minCvssThreshold) continue

            val isActivelyExploited = cve.id in activelyExploitedIds

            // Plausibilitätsprüfung: CVE überspringen, wenn das Gerät bereits gepatcht ist
            // und die Schwachstelle nicht aktiv ausgenutzt wird.
            // Verhindert, dass z.B. CVE-2011-1823 (Android 2.x) auf Android 14+ angezeigt wird.
            val alreadyPatched = isPatched(securityPatchLevel, cve.published)
            if (alreadyPatched && !isActivelyExploited) continue

            // Zusätzlich: CVE-Beschreibung auf veraltete Android-Versionen prüfen
            val description = cve.descriptions.firstOrNull { it.lang == "en" }?.value
                ?: cve.descriptions.firstOrNull()?.value
                ?: "Keine Beschreibung verfügbar"
            if (isDescriptionForOlderAndroid(description, apiLevel)) continue

            val kevEntry = if (isActivelyExploited) vulnRepository.getKevEntryForCve(cve.id) else null

            val severity = Severity.fromCvssScore(cvssScore)

            findings += VulnerabilityEntry(
                id = cve.id,
                title = buildTitle(cve.id, severity, isActivelyExploited),
                severity = severity,
                cvssScore = cvssScore,
                cvssVector = metrics?.cvssData?.vectorString ?: "",
                isZeroDay = isActivelyExploited && cvssScore >= 9.0f,
                isActivelyExploited = isActivelyExploited,
                affectedComponent = "Android $androidVersion (API $apiLevel)",
                description = description,
                impact = buildImpact(cvssScore, isActivelyExploited, kevEntry?.shortDescription),
                remediation = buildRemediation(
                    securityPatchLevel,
                    isActivelyExploited,
                    kevEntry?.requiredAction
                ),
                cveLinks = listOf(
                    "https://nvd.nist.gov/vuln/detail/${cve.id}",
                ) + cve.references.take(3).map { it.url },
                patchAvailable = isPatched(securityPatchLevel, cve.published),
                patchEta = if (!isPatched(securityPatchLevel, cve.published))
                    "Nächstes Android-Sicherheitsbulletin" else null,
                source = if (isActivelyExploited) "NVD + CISA KEV" else "NVD"
            )
        }

        findings.sortedByDescending { it.cvssScore }
    }

    private fun buildTitle(cveId: String, severity: Severity, isExploited: Boolean): String {
        val prefix = when {
            isExploited && severity == Severity.CRITICAL -> "[AKTIV AUSGENUTZT] "
            isExploited -> "[KEV] "
            else -> ""
        }
        return "${prefix}$cveId – ${severity.label} Schwachstelle"
    }

    private fun buildImpact(
        cvssScore: Float,
        isActivelyExploited: Boolean,
        kevDescription: String?
    ): String {
        val base = when {
            cvssScore >= 9.0f -> "Kritischer Angriff möglich – vollständige Gerätekompromittierung."
            cvssScore >= 7.0f -> "Schwerwiegender Angriff möglich – Datenverlust oder Privilegienerhöhung."
            else -> "Moderates Risiko."
        }
        return if (isActivelyExploited && kevDescription != null) {
            "$base Aktive Ausnutzung bekannt: $kevDescription"
        } else {
            base
        }
    }

    private fun buildRemediation(
        securityPatchLevel: String,
        isActivelyExploited: Boolean,
        requiredAction: String?
    ): RemediationSteps {
        val steps = mutableListOf<String>()
        if (isActivelyExploited) {
            steps += "DRINGLICH: Diese Schwachstelle wird aktiv ausgenutzt."
        }
        steps += "Aktualisiere das Gerät sofort auf den neuesten Sicherheitspatch."
        steps += "Navigiere zu: Einstellungen → System → Systemaktualisierung"
        steps += "Dein aktueller Patch-Level: $securityPatchLevel"
        if (requiredAction != null) {
            steps += "CISA-Empfehlung: $requiredAction"
        }
        steps += "Falls kein Update verfügbar: Wende dich an deinen Gerätehersteller."

        return RemediationSteps(
            priority = if (isActivelyExploited) Priority.IMMEDIATE else Priority.HIGH,
            steps = steps,
            automatable = false,
            deepLinkSettings = "android.settings.SYSTEM_UPDATE_SETTINGS",
            officialDocUrl = "https://source.android.com/docs/security/bulletin",
            estimatedTime = "~15 Minuten"
        )
    }

    private fun isPatched(devicePatchLevel: String, cvePublished: String): Boolean {
        if (devicePatchLevel.isEmpty() || cvePublished.isEmpty()) return false
        return try {
            val deviceDate = java.time.LocalDate.parse(devicePatchLevel)
            val pubDate = java.time.LocalDate.parse(cvePublished.take(10))
            deviceDate >= pubDate
        } catch (e: Exception) {
            // Bei Parse-Fehler: im Zweifel nicht als gepatcht behandeln
            false
        }
    }

    /**
     * Prüft anhand der CVE-Beschreibung, ob die Schwachstelle nur ältere Android-Versionen betrifft.
     * Gibt true zurück, wenn die Beschreibung explizit auf Versionen verweist, die kleiner als
     * die aktuelle API-Ebene sind (z.B. "Android 2.x" auf einem Android 14-Gerät).
     */
    private fun isDescriptionForOlderAndroid(description: String, currentApiLevel: Int): Boolean {
        // Mapping bekannter Android-Versionsnamen auf API-Level
        val versionApiMap = mapOf(
            "android 1." to 4,
            "android 2.0" to 5, "android 2.1" to 7, "android 2.2" to 8,
            "android 2.3" to 10,
            "android 3." to 13,
            "android 4.0" to 14, "android 4.1" to 16, "android 4.2" to 17,
            "android 4.3" to 18, "android 4.4" to 19,
            "android 5.0" to 21, "android 5.1" to 22,
            "android 6." to 23,
            "android 7.0" to 24, "android 7.1" to 25,
            "android 8.0" to 26, "android 8.1" to 27,
            "android 9" to 28,
            "android 10" to 29,
            "android 11" to 30,
            "android 12" to 31,
            "android 13" to 33,
            "android 14" to 34,
            "android 15" to 35,
            "android 16" to 36
        )
        val lowerDesc = description.lowercase()
        // Wenn die Beschreibung eine bestimmte Android-Version erwähnt und diese
        // maximal-API weniger als 2 API-Level unter der aktuellen liegt → überspringen
        for ((versionStr, maxApi) in versionApiMap) {
            if (lowerDesc.contains(versionStr) && maxApi < currentApiLevel - 1) {
                return true
            }
        }
        return false
    }
}
