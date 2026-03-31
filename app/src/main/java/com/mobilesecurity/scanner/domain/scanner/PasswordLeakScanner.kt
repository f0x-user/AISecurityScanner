package com.mobilesecurity.scanner.domain.scanner

import android.content.Context
import com.mobilesecurity.scanner.domain.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class PasswordLeakScanner @Inject constructor(
    private val context: Context
) {
    suspend fun scan(): List<VulnerabilityEntry> = withContext(Dispatchers.IO) {
        val accounts = getDeviceAccounts()
        val accountInfo = if (accounts.isEmpty())
            "Keine Konten automatisch erkannt – prüfe manuell deine E-Mail-Adressen."
        else
            "Gefundene Konten: ${accounts.joinToString(", ")}"

        listOf(
            VulnerabilityEntry(
                id = "LEAK-INFO",
                title = "Datenleck-Prüfung empfohlen",
                severity = Severity.INFO,
                cvssScore = 0f,
                affectedComponent = "Konto-Credentials",
                affectedApps = accounts,
                description = "Prüfe ob deine E-Mail-Adressen in bekannten Datenlecks auftauchen. " +
                    accountInfo,
                impact = "Kompromittierte Credentials ermöglichen Kontoübernahmen.",
                remediation = RemediationSteps(
                    priority = Priority.NORMAL,
                    steps = listOf(
                        "Besuche haveibeenpwned.com und prüfe jede E-Mail-Adresse.",
                        "Ändere Passwörter für alle betroffenen Konten sofort.",
                        "Aktiviere 2FA überall wo es angeboten wird."
                    ),
                    automatable = false,
                    officialDocUrl = "https://haveibeenpwned.com",
                    estimatedTime = "~15 Minuten"
                ),
                source = "PasswordLeakScanner"
            )
        )
    }

    private fun getDeviceAccounts(): List<String> {
        return try {
            val accountManager = context.getSystemService(Context.ACCOUNT_SERVICE)
                as android.accounts.AccountManager
            accountManager.accounts
                .filter { it.name.contains("@") }
                .map { it.name }
                .distinct()
                .take(5)
        } catch (e: SecurityException) {
            emptyList()
        }
    }
}
