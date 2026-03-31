package com.mobilesecurity.scanner.domain.model

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

// ScanDepth wird nur noch für historische DB-Einträge beibehalten
// Alle Scans laufen immer mit maximaler Tiefe
object ScanDepth {
    const val FULL = "FULL"
}
