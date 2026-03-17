package com.aisecurity.scanner.util

import android.content.Context
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Debug-Logger für die AISecurityScanner-App.
 *
 * Wird über die Einstellungen aktiviert. Schreibt alle App-Aktivitäten,
 * Scan-Module, Befunde und Fehler in eine Datei unter:
 *   /sdcard/Android/data/com.aisecurity.scanner/files/debug/aisec_debug_YYYY-MM-DD_HH-mm-ss.log
 *
 * Die Datei kann nach Deaktivierung über den Teilen-Dialog exportiert werden.
 */
@Singleton
class DebugLogger @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val mutex = Mutex()
    private var writer: BufferedWriter? = null
    private var currentLogFile: File? = null
    private var lastFinishedLogFile: File? = null

    private val timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
    private val fileTimestampFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss")

    var isEnabled: Boolean = false
        private set

    // ─── Session-Steuerung ────────────────────────────────────────────────────

    fun startLogging(): File {
        // Alten Writer schließen falls noch offen
        runCatching { writer?.close() }
        writer = null

        val dir = context.getExternalFilesDir("debug") ?: File(context.filesDir, "debug")
        dir.mkdirs()

        val timestamp = LocalDateTime.now().format(fileTimestampFormatter)
        val file = File(dir, "aisec_debug_$timestamp.log")

        writer = BufferedWriter(FileWriter(file, false))
        currentLogFile = file
        isEnabled = true

        // Session-Header schreiben
        writer?.apply {
            val sep = "=".repeat(70)
            write("$sep\n")
            write("  AI Security Scanner – Debug-Log\n")
            write("$sep\n")
            write("  Session-Start : ${LocalDateTime.now()}\n")
            write("  Gerät         : ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})\n")
            write("  Android       : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n")
            write("  Sicherheits-  : ${Build.VERSION.SECURITY_PATCH}\n")
            write("  patch\n")
            write("  Build-Typ     : ${Build.TYPE}\n")
            write("  Fingerprint   : ${Build.FINGERPRINT.take(60)}\n")
            write("$sep\n\n")
            flush()
        }

        return file
    }

    fun stopLogging(): File? {
        if (!isEnabled) return lastFinishedLogFile

        runCatching {
            writer?.apply {
                val sep = "=".repeat(70)
                write("\n$sep\n")
                write("  Session-Ende: ${LocalDateTime.now()}\n")
                write("$sep\n")
                flush()
                close()
            }
        }
        writer = null
        lastFinishedLogFile = currentLogFile
        currentLogFile = null
        isEnabled = false
        return lastFinishedLogFile
    }

    // ─── Log-Methoden ─────────────────────────────────────────────────────────

    suspend fun log(tag: String, message: String) {
        if (!isEnabled) return
        mutex.withLock { writeLine("INFO ", tag, message) }
    }

    suspend fun logWarn(tag: String, message: String) {
        if (!isEnabled) return
        mutex.withLock { writeLine("WARN ", tag, message) }
    }

    suspend fun logError(tag: String, message: String, throwable: Throwable? = null) {
        if (!isEnabled) return
        mutex.withLock {
            writeLine("ERROR", tag, message)
            throwable?.let { t ->
                writer?.write("         Exception : ${t.javaClass.name}: ${t.message}\n")
                t.stackTrace.take(8).forEach { frame ->
                    writer?.write("           at $frame\n")
                }
                writer?.flush()
            }
        }
    }

    suspend fun logSection(title: String) {
        if (!isEnabled) return
        mutex.withLock {
            val ts = LocalDateTime.now().format(timeFormatter)
            writer?.write("\n[$ts] ─── $title ─────────────────────────────────────\n")
            writer?.flush()
        }
    }

    suspend fun logFinding(id: String, severity: String, cvss: Float, title: String) {
        if (!isEnabled) return
        mutex.withLock {
            writeLine("FIND ", "Finding", "[$severity | CVSS ${"%.1f".format(cvss)}] $id – $title")
        }
    }

    suspend fun logTiming(tag: String, label: String, durationMs: Long) {
        if (!isEnabled) return
        mutex.withLock {
            writeLine("TIME ", tag, "$label: ${durationMs}ms")
        }
    }

    // ─── Datei-Zugriff ────────────────────────────────────────────────────────

    /** Aktuell laufende Log-Datei (wenn isEnabled == true). */
    fun getActiveLogFile(): File? = currentLogFile

    /** Zuletzt abgeschlossene Log-Datei (nachdem Logging gestoppt wurde). */
    fun getLastFinishedLogFile(): File? = lastFinishedLogFile

    /** Alle vorhandenen Debug-Log-Dateien (älteste zuerst). */
    fun getAllLogFiles(): List<File> {
        val dir = context.getExternalFilesDir("debug") ?: File(context.filesDir, "debug")
        return dir.listFiles { f -> f.name.startsWith("aisec_debug_") && f.extension == "log" }
            ?.sortedBy { it.lastModified() }
            ?: emptyList()
    }

    /** Löscht alle abgeschlossenen Debug-Log-Dateien. */
    fun deleteAllLogFiles() {
        getAllLogFiles().filter { it != currentLogFile }.forEach { it.delete() }
        if (lastFinishedLogFile?.exists() == false) lastFinishedLogFile = null
    }

    // ─── Intern ───────────────────────────────────────────────────────────────

    private fun writeLine(level: String, tag: String, message: String) {
        val ts = LocalDateTime.now().format(timeFormatter)
        val tagPadded = tag.take(24).padEnd(24)
        writer?.write("[$ts] [$level] [$tagPadded] $message\n")
        writer?.flush()
    }
}
