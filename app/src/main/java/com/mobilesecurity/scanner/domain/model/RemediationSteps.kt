package com.mobilesecurity.scanner.domain.model

data class RemediationSteps(
    val priority: Priority,
    val steps: List<String>,
    val automatable: Boolean,
    val deepLinkSettings: String? = null,
    val officialDocUrl: String = "",
    val estimatedTime: String = "Unbekannt"
)
