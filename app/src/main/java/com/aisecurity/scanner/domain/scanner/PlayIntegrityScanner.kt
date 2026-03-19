package com.aisecurity.scanner.domain.scanner

import android.content.Context
import com.aisecurity.scanner.domain.model.*
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.IntegrityTokenResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume

@Singleton
class PlayIntegrityScanner @Inject constructor(
    private val context: Context
) {
    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry>()
        try {
            val nonce = generateNonce()
            val integrityManager = IntegrityManagerFactory.create(context)
            val tokenResponse = suspendCancellableCoroutine<IntegrityTokenResponse?> { cont ->
                integrityManager.requestIntegrityToken(
                    IntegrityTokenRequest.builder()
                        .setNonce(nonce)
                        .build()
                ).addOnSuccessListener { cont.resume(it) }
                 .addOnFailureListener { cont.resume(null) }
            }

            if (tokenResponse == null) {
                findings += VulnerabilityEntry(
                    id = "INT-001",
                    title = "Play Integrity API nicht verfügbar",
                    severity = Severity.MEDIUM,
                    cvssScore = 5.0f,
                    cvssVector = "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    affectedComponent = "Google Play Integrity",
                    description = "Die Play Integrity API konnte nicht ausgeführt werden. " +
                        "Dies kann auf ein nicht-zertifiziertes Gerät, einen Emulator oder " +
                        "fehlende Google Play Services hinweisen.",
                    impact = "Keine unabhängige Verifikation der Geräteintegrität möglich.",
                    remediation = RemediationSteps(
                        priority = Priority.NORMAL,
                        steps = listOf(
                            "Stelle sicher dass Google Play Services installiert und aktuell sind.",
                            "Prüfe ob das Gerät Play-zertifiziert ist: Einstellungen → Über das Telefon"
                        ),
                        automatable = false,
                        officialDocUrl = "https://developer.android.com/google/play/integrity",
                        estimatedTime = "~5 Minuten"
                    ),
                    source = "PlayIntegrityScanner"
                )
                return@withContext findings
            }

            val payload = decodeJwtPayload(tokenResponse.token())
            findings += interpretIntegrityPayload(payload)

        } catch (e: Exception) {
            // Fehler still ignorieren – kein Befund wenn API nicht erreichbar
        }
        findings
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP)
    }

    private fun decodeJwtPayload(token: String): Map<String, Any> {
        return try {
            val parts = token.split(".")
            if (parts.size < 2) return emptyMap()
            val decoded = android.util.Base64.decode(
                parts[1], android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING
            )
            val json = String(decoded, Charsets.UTF_8)
            val result = mutableMapOf<String, Any>()
            json.removePrefix("{").removeSuffix("}")
                .split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*\$)".toRegex())
                .forEach { pair ->
                    val kv = pair.trim().split(":", limit = 2)
                    if (kv.size == 2) {
                        val key = kv[0].trim().removeSurrounding("\"")
                        val value = kv[1].trim().removeSurrounding("\"")
                        result[key] = value
                    }
                }
            result
        } catch (e: Exception) { emptyMap() }
    }

    private fun interpretIntegrityPayload(payload: Map<String, Any>): List<VulnerabilityEntry> {
        val findings = mutableListOf<VulnerabilityEntry>()
        val deviceVerdict = payload["deviceIntegrity"]?.toString() ?: ""
        if (!deviceVerdict.contains("MEETS_DEVICE_INTEGRITY")) {
            findings += VulnerabilityEntry(
                id = "INT-002",
                title = "Geräte-Integrität nicht bestätigt (Play Integrity)",
                severity = Severity.HIGH,
                cvssScore = 8.0f,
                cvssVector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                affectedComponent = "Google Play Device Integrity",
                description = "Google Play Integrity meldet dass dieses Gerät die " +
                    "Integritätsanforderungen nicht erfüllt. Mögliche Ursachen: " +
                    "entsperrter Bootloader, Root, manipuliertes System-Image oder Emulator.",
                impact = "Alle Android-Sicherheitsgarantien könnten kompromittiert sein.",
                remediation = RemediationSteps(
                    priority = Priority.HIGH,
                    steps = listOf(
                        "Prüfe ob der Bootloader entsperrt ist.",
                        "Entferne Root-Zugriff und Custom-ROMs.",
                        "Flashe ein offizielles Hersteller-Image."
                    ),
                    automatable = false,
                    officialDocUrl = "https://developer.android.com/google/play/integrity/verdicts",
                    estimatedTime = "~1-2 Stunden"
                ),
                source = "PlayIntegrityScanner"
            )
        }
        return findings
    }
}
