package com.aisecurity.scanner.domain.remediation

/** Beschreibt eine konkrete Behebungsaktion für eine Schwachstelle */
data class RemediationAction(
    val vulnId: String,
    val actionType: RemediationActionType,
    val description: String,
    /** Settings-DeepLink, der für OPEN_SETTINGS geöffnet wird */
    val settingsDeepLink: String? = null,
    /** Shell-Kommando, das als Root ausgeführt wird (nur wenn requiresRoot=true) */
    val shellCommand: String? = null,
    val requiresRoot: Boolean = false
)

enum class RemediationActionType {
    /** Öffnet eine Android-Settings-Seite für manuelle Korrektur durch den Nutzer */
    OPEN_SETTINGS,
    /** Führt Shell-Kommando aus (erfordert Root) */
    SHELL_COMMAND,
    /** Rein informativer Eintrag – keine automatische Aktion möglich */
    VIRTUAL_ONLY
}

/** Ergebnis einer ausgeführten Behebungsaktion */
data class RemediationResult(
    val vulnId: String,
    val success: Boolean,
    val actionDescription: String,
    val errorMessage: String? = null,
    /** True wenn der Nutzer manuell eingreifen muss (z. B. Settings öffnen) */
    val requiresManualIntervention: Boolean = false
)
