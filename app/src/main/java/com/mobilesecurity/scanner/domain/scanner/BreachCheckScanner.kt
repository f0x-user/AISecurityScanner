package com.mobilesecurity.scanner.domain.scanner

import android.accounts.AccountManager
import android.content.Context
import android.os.Build
import com.mobilesecurity.scanner.data.network.HibpApiService
import com.mobilesecurity.scanner.data.network.PwnedPasswordsApiService
import com.mobilesecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import javax.inject.Inject

/**
 * Modul 13: Datenleck-Check (HaveIBeenPwned-Stil).
 *
 * Prueft ob auf dem Geraet gespeicherte E-Mail-Konten in bekannten
 * Datenlecks aufgetaucht sind. Nutzt die k-Anonymity-Methode fuer
 * Passwort-Hashes (keine Klartextpasswoerter werden uebertragen).
 */
class BreachCheckScanner @Inject constructor(
    private val context: Context,
    private val hibpApiService: HibpApiService,
    private val pwnedPasswordsApiService: PwnedPasswordsApiService
) {

    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<VulnerabilityEntry?>()
        findings += checkAccountsForBreaches()
        findings += checkCommonPasswordPatterns()
        findings.filterNotNull()
    }

    private suspend fun checkAccountsForBreaches(): VulnerabilityEntry? {
        val emailAccounts = getDeviceEmailAccounts()
        if (emailAccounts.isEmpty()) return null

        return VulnerabilityEntry(
            id = "BREACH-001",
            title = "Datenleck-Pruefung fuer gespeicherte Konten",
            severity = Severity.INFO,
            cvssScore = 0.0f,
            affectedComponent = "Konto-Datenleck-Pruefung",
            description = "Auf diesem Geraet sind ${emailAccounts.size} E-Mail-Konten gespeichert: " +
                "${emailAccounts.take(3).joinToString(", ")}${if (emailAccounts.size > 3) " ..." else ""}. " +
                "Verwende den Datenleck-Checker (Menupunkt 'Datenleck pruefen') um zu ueberpruefen, " +
                "ob diese Konten von bekannten Datenpannen betroffen sind.",
            impact = "Bei einem Datenleck koennen Passwoerter, persoenliche Daten und " +
                "Finanzdaten kompromittiert sein.",
            remediation = RemediationSteps(
                priority = Priority.NORMAL,
                steps = listOf(
                    "Den 'Datenleck pruefen' Screen oeffnen",
                    "E-Mail-Adresse eingeben und auf Datenlecks pruefen",
                    "Bei Treffer: Passwort sofort aendern und 2FA aktivieren",
                    "Alle Dienste mit dem gleichen Passwort aktualisieren"
                ),
                automatable = false,
                estimatedTime = "5-10 Minuten"
            ),
            source = "BreachCheckScanner"
        )
    }

    private fun checkCommonPasswordPatterns(): VulnerabilityEntry? {
        return VulnerabilityEntry(
            id = "BREACH-002",
            title = "Passwort-Sicherheitspruefung verfuegbar",
            severity = Severity.INFO,
            cvssScore = 0.0f,
            affectedComponent = "Passwort-Sicherheit",
            description = "Die Passwort-Sicherheitspruefung ermoeglicht es, Passwoerter anonym " +
                "auf Datenlecks zu pruefen (k-Anonymity: nur die ersten 5 Zeichen des SHA-1-Hashes " +
                "werden uebertragen, das Passwort selbst verlasst das Geraet nie).",
            impact = "Kompromittierte Passwoerter erhoehen das Risiko fuer unbefugten Kontozugriff erheblich.",
            remediation = RemediationSteps(
                priority = Priority.NORMAL,
                steps = listOf(
                    "Den 'Datenleck pruefen' Screen oeffnen",
                    "Passwort-Tab auswaehlen und Passwort eingeben",
                    "Bei Treffer: Passwort sofort durch ein starkes, einzigartiges Passwort ersetzen",
                    "Passwort-Manager verwenden fuer sichere Passwoerter"
                ),
                automatable = false,
                estimatedTime = "10-15 Minuten"
            ),
            source = "BreachCheckScanner"
        )
    }

    private fun getDeviceEmailAccounts(): List<String> {
        return try {
            val am = context.getSystemService(Context.ACCOUNT_SERVICE) as AccountManager
            am.accounts
                .filter { it.type == "com.google" || it.type == "com.microsoft.exchange" ||
                    it.name.contains("@") }
                .map { it.name }
                .filter { it.contains("@") }
                .distinct()
        } catch (_: Exception) {
            emptyList()
        }
    }

    suspend fun checkEmailForBreaches(email: String, apiKey: String): BreachCheckResult {
        return withContext(Dispatchers.IO) {
            try {
                val response = hibpApiService.getBreachesForAccount(email, apiKey)
                when {
                    response.code() == 200 -> {
                        val breaches = response.body() ?: emptyList()
                        BreachCheckResult.Found(email, breaches.map { breach ->
                            BreachInfo(
                                name = breach.title,
                                domain = breach.domain,
                                breachDate = breach.breachDate,
                                dataClasses = breach.dataClasses,
                                pwnCount = breach.pwnCount,
                                isVerified = breach.isVerified
                            )
                        })
                    }
                    response.code() == 404 -> BreachCheckResult.NotFound(email)
                    response.code() == 401 -> BreachCheckResult.ApiKeyRequired
                    response.code() == 429 -> BreachCheckResult.RateLimited
                    else -> BreachCheckResult.Error("HTTP ${response.code()}")
                }
            } catch (e: Exception) {
                BreachCheckResult.Error(e.message ?: "Unbekannter Fehler")
            }
        }
    }

    suspend fun checkPasswordPwned(password: String): PasswordPwnedResult {
        return withContext(Dispatchers.IO) {
            try {
                val sha1 = sha1Hex(password).uppercase()
                val prefix = sha1.take(5)
                val suffix = sha1.drop(5)

                val response = pwnedPasswordsApiService.getHashRange(prefix)
                if (!response.isSuccessful) {
                    return@withContext PasswordPwnedResult.Error("API nicht erreichbar")
                }

                val body = response.body() ?: return@withContext PasswordPwnedResult.Error("Leere Antwort")
                val matchLine = body.lines().firstOrNull { line ->
                    line.startsWith(suffix, ignoreCase = true)
                }

                if (matchLine != null) {
                    val count = matchLine.substringAfter(":").trim().toLongOrNull() ?: 0L
                    PasswordPwnedResult.Pwned(count)
                } else {
                    PasswordPwnedResult.Safe
                }
            } catch (e: Exception) {
                PasswordPwnedResult.Error(e.message ?: "Unbekannter Fehler")
            }
        }
    }

    private fun sha1Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

data class BreachInfo(
    val name: String,
    val domain: String,
    val breachDate: String,
    val dataClasses: List<String>,
    val pwnCount: Long,
    val isVerified: Boolean
)

sealed class BreachCheckResult {
    data class Found(val email: String, val breaches: List<BreachInfo>) : BreachCheckResult()
    data class NotFound(val email: String) : BreachCheckResult()
    object ApiKeyRequired : BreachCheckResult()
    object RateLimited : BreachCheckResult()
    data class Error(val message: String) : BreachCheckResult()
}

sealed class PasswordPwnedResult {
    data class Pwned(val count: Long) : PasswordPwnedResult()
    object Safe : PasswordPwnedResult()
    data class Error(val message: String) : PasswordPwnedResult()
}
