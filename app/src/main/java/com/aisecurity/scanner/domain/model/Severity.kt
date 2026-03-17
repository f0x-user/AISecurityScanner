package com.aisecurity.scanner.domain.model

enum class Severity(val label: String, val order: Int) {
    CRITICAL("KRITISCH", 0),
    HIGH("HOCH", 1),
    MEDIUM("MITTEL", 2),
    LOW("NIEDRIG", 3),
    INFO("INFO", 4);

    companion object {
        fun fromCvssScore(score: Float): Severity = when {
            score >= 9.0f -> CRITICAL
            score >= 7.0f -> HIGH
            score >= 4.0f -> MEDIUM
            score >= 0.1f -> LOW
            else -> INFO
        }
    }
}

enum class Priority {
    IMMEDIATE, HIGH, NORMAL, LOW
}

enum class ScanDepth(val label: String, val durationMinutes: Int) {
    QUICK("Schnell", 2),
    STANDARD("Standard", 5),
    DEEP("Tief", 15),
    FORENSIC("Forensisch", 30)
}
