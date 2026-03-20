package com.aisecurity.scanner.domain.snapshot

import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.time.Instant
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Snapshot-Manager: Erstellt vor kritischen Schreiboperationen Sicherungspunkte.
 *
 * Unterstützt drei Mechanismen (je nach Gerätekonfiguration):
 * 1. VIRTUAL  – speichert Schlüsselzustände in verschlüsselten SharedPreferences
 *               (immer verfügbar, kein Root benötigt)
 * 2. BTRFS    – erstellt echten Subvolume-Snapshot (Root + BTRFS-Dateisystem)
 * 3. LVM      – erstellt LVM-Thin-Snapshot (Root + LVM)
 *
 * Hinweis: Schreibt NICHT auf das Host-System, auf dem dieser Scanner läuft.
 * Alle Operationen beziehen sich auf das Android-Gerät und prüfen zuerst,
 * ob die jeweilige Infrastruktur vorhanden ist.
 */
@Singleton
class SnapshotManager @Inject constructor(
    private val encryptedPrefs: SharedPreferences
) {
    companion object {
        private const val PREFS_KEY_PREFIX = "snapshot_"
        private const val SNAPSHOTS_INDEX_KEY = "snapshot_index"
    }

    /**
     * Erstellt einen Snapshot vor einer Schreiboperation.
     * Versucht automatisch den besten verfügbaren Mechanismus.
     *
     * @param targetPath Pfad, auf den gleich geschrieben wird (für Kontextinformation)
     * @param reason     Beschreibung warum der Snapshot erstellt wird
     */
    suspend fun createSnapshot(
        targetPath: String,
        reason: String = "Pre-Remediation Backup"
    ): SnapshotResult = withContext(Dispatchers.IO) {
        val snapshotId = UUID.randomUUID().toString().take(8)
        val timestamp = Instant.now()

        // Versuche echte Dateisystem-Snapshots nur auf Root-Geräten
        if (isRootAvailable()) {
            val btrfsResult = tryBtrfsSnapshot(snapshotId, targetPath, timestamp)
            if (btrfsResult != null) return@withContext btrfsResult

            val lvmResult = tryLvmSnapshot(snapshotId, targetPath, timestamp)
            if (lvmResult != null) return@withContext lvmResult
        }

        // Fallback: Virtueller App-interner Snapshot (immer verfügbar)
        createVirtualSnapshot(snapshotId, targetPath, reason, timestamp)
    }

    /**
     * Stellt einen früheren Snapshot wieder her.
     *
     * @param snapshotId ID des wiederherzustellenden Snapshots
     */
    suspend fun restoreSnapshot(snapshotId: String): Boolean = withContext(Dispatchers.IO) {
        val type = encryptedPrefs.getString("${PREFS_KEY_PREFIX}${snapshotId}_type", null)
            ?: return@withContext false

        when (SnapshotType.valueOf(type)) {
            SnapshotType.VIRTUAL -> restoreVirtualSnapshot(snapshotId)
            SnapshotType.BTRFS -> restoreBtrfsSnapshot(snapshotId)
            SnapshotType.LVM -> restoreLvmSnapshot(snapshotId)
        }
    }

    /** Listet alle gespeicherten Snapshot-IDs auf */
    fun listSnapshots(): List<String> {
        val index = encryptedPrefs.getString(SNAPSHOTS_INDEX_KEY, "") ?: ""
        return index.split(",").filter { it.isNotBlank() }
    }

    /** Löscht alle virtuellen Snapshots die älter als [maxAgeMs] Millisekunden sind */
    suspend fun purgeOldSnapshots(maxAgeMs: Long = 7 * 24 * 60 * 60 * 1000L) =
        withContext(Dispatchers.IO) {
            val now = Instant.now().toEpochMilli()
            val ids = listSnapshots().toMutableList()
            val toRemove = ids.filter { id ->
                val ts = encryptedPrefs.getLong("${PREFS_KEY_PREFIX}${id}_ts", 0L)
                (now - ts) > maxAgeMs
            }
            toRemove.forEach { id -> deleteSnapshot(id) }
            ids.removeAll(toRemove.toSet())
            encryptedPrefs.edit().putString(SNAPSHOTS_INDEX_KEY, ids.joinToString(",")).apply()
        }

    // -------------------------------------------------------------------------
    // Private – Virtueller Snapshot
    // -------------------------------------------------------------------------

    private fun createVirtualSnapshot(
        snapshotId: String,
        targetPath: String,
        reason: String,
        timestamp: Instant
    ): SnapshotResult {
        return try {
            // Lese den aktuellen Inhalt der Zieldatei (falls lesbar)
            val currentContent = try {
                File(targetPath).takeIf { it.exists() && it.canRead() }?.readText() ?: ""
            } catch (_: Exception) {
                ""
            }

            encryptedPrefs.edit()
                .putString("${PREFS_KEY_PREFIX}${snapshotId}_path", targetPath)
                .putString("${PREFS_KEY_PREFIX}${snapshotId}_reason", reason)
                .putString("${PREFS_KEY_PREFIX}${snapshotId}_content", currentContent)
                .putString("${PREFS_KEY_PREFIX}${snapshotId}_type", SnapshotType.VIRTUAL.name)
                .putLong("${PREFS_KEY_PREFIX}${snapshotId}_ts", timestamp.toEpochMilli())
                .apply()

            // Index aktualisieren
            val current = encryptedPrefs.getString(SNAPSHOTS_INDEX_KEY, "") ?: ""
            val updated = if (current.isBlank()) snapshotId else "$current,$snapshotId"
            encryptedPrefs.edit().putString(SNAPSHOTS_INDEX_KEY, updated).apply()

            SnapshotResult(
                snapshotId = snapshotId,
                timestamp = timestamp,
                success = true,
                type = SnapshotType.VIRTUAL,
                path = "prefs:$PREFS_KEY_PREFIX$snapshotId"
            )
        } catch (e: Exception) {
            SnapshotResult(
                snapshotId = snapshotId,
                timestamp = timestamp,
                success = false,
                type = SnapshotType.VIRTUAL,
                errorMessage = "Virtueller Snapshot fehlgeschlagen: ${e.message}"
            )
        }
    }

    private fun restoreVirtualSnapshot(snapshotId: String): Boolean {
        return try {
            val targetPath = encryptedPrefs.getString(
                "${PREFS_KEY_PREFIX}${snapshotId}_path", null
            ) ?: return false
            val content = encryptedPrefs.getString(
                "${PREFS_KEY_PREFIX}${snapshotId}_content", null
            ) ?: return false

            val file = File(targetPath)
            if (content.isNotEmpty() && file.canWrite()) {
                file.writeText(content)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    // -------------------------------------------------------------------------
    // Private – BTRFS-Snapshot
    // -------------------------------------------------------------------------

    private fun tryBtrfsSnapshot(
        snapshotId: String,
        targetPath: String,
        timestamp: Instant
    ): SnapshotResult? {
        // Prüfe ob BTRFS verfügbar ist
        val mounts = readFile("/proc/mounts") ?: return null
        val btrfsMountPoint = mounts.lines()
            .firstOrNull { it.contains("btrfs") }
            ?.split(" ")?.getOrNull(1) ?: return null

        return try {
            val snapshotPath = "$btrfsMountPoint/.snapshots/aisecurity_$snapshotId"
            val result = executeShellCommand("btrfs subvolume snapshot $btrfsMountPoint $snapshotPath")

            if (result.isSuccess) {
                encryptedPrefs.edit()
                    .putString("${PREFS_KEY_PREFIX}${snapshotId}_type", SnapshotType.BTRFS.name)
                    .putString("${PREFS_KEY_PREFIX}${snapshotId}_path", snapshotPath)
                    .putLong("${PREFS_KEY_PREFIX}${snapshotId}_ts", timestamp.toEpochMilli())
                    .apply()

                SnapshotResult(
                    snapshotId = snapshotId,
                    timestamp = timestamp,
                    success = true,
                    type = SnapshotType.BTRFS,
                    path = snapshotPath
                )
            } else null
        } catch (_: Exception) {
            null
        }
    }

    private fun restoreBtrfsSnapshot(snapshotId: String): Boolean {
        val snapshotPath = encryptedPrefs.getString(
            "${PREFS_KEY_PREFIX}${snapshotId}_path", null
        ) ?: return false
        return try {
            val result = executeShellCommand("btrfs subvolume snapshot $snapshotPath /")
            result.isSuccess
        } catch (_: Exception) {
            false
        }
    }

    // -------------------------------------------------------------------------
    // Private – LVM-Snapshot
    // -------------------------------------------------------------------------

    private fun tryLvmSnapshot(
        snapshotId: String,
        targetPath: String,
        timestamp: Instant
    ): SnapshotResult? {
        // Prüfe ob LVM verfügbar ist (lvm-Tools im Pfad)
        if (!fileExists("/sbin/lvcreate") && !fileExists("/usr/sbin/lvcreate")) return null

        return try {
            val lvName = "aisecurity_snap_$snapshotId"
            // Snapshot des Root-Volumes mit 1GB Größe
            val result = executeShellCommand(
                "lvcreate -L1G -s -n $lvName \$(lvdisplay | grep 'LV Path' | head -1 | awk '{print \$3}')"
            )

            if (result.isSuccess) {
                encryptedPrefs.edit()
                    .putString("${PREFS_KEY_PREFIX}${snapshotId}_type", SnapshotType.LVM.name)
                    .putString("${PREFS_KEY_PREFIX}${snapshotId}_path", "/dev/mapper/$lvName")
                    .putLong("${PREFS_KEY_PREFIX}${snapshotId}_ts", timestamp.toEpochMilli())
                    .apply()

                SnapshotResult(
                    snapshotId = snapshotId,
                    timestamp = timestamp,
                    success = true,
                    type = SnapshotType.LVM,
                    path = "/dev/mapper/$lvName"
                )
            } else null
        } catch (_: Exception) {
            null
        }
    }

    private fun restoreLvmSnapshot(snapshotId: String): Boolean {
        val lvPath = encryptedPrefs.getString(
            "${PREFS_KEY_PREFIX}${snapshotId}_path", null
        ) ?: return false
        return try {
            val result = executeShellCommand("lvconvert --merge $lvPath")
            result.isSuccess
        } catch (_: Exception) {
            false
        }
    }

    private fun deleteSnapshot(snapshotId: String) {
        val type = encryptedPrefs.getString("${PREFS_KEY_PREFIX}${snapshotId}_type", null)
        if (type == SnapshotType.BTRFS.name || type == SnapshotType.LVM.name) {
            val path = encryptedPrefs.getString("${PREFS_KEY_PREFIX}${snapshotId}_path", null)
            if (path != null && isRootAvailable()) {
                when (type) {
                    SnapshotType.BTRFS.name -> executeShellCommand("btrfs subvolume delete $path")
                    SnapshotType.LVM.name -> executeShellCommand("lvremove -f $path")
                }
            }
        }
        encryptedPrefs.edit()
            .remove("${PREFS_KEY_PREFIX}${snapshotId}_path")
            .remove("${PREFS_KEY_PREFIX}${snapshotId}_reason")
            .remove("${PREFS_KEY_PREFIX}${snapshotId}_content")
            .remove("${PREFS_KEY_PREFIX}${snapshotId}_type")
            .remove("${PREFS_KEY_PREFIX}${snapshotId}_ts")
            .apply()
    }

    // -------------------------------------------------------------------------
    // Hilfsfunktionen
    // -------------------------------------------------------------------------

    private fun isRootAvailable(): Boolean = try {
        val result = executeShellCommand("id")
        result.isSuccess && result.output.contains("uid=0")
    } catch (_: Exception) {
        false
    }

    private fun fileExists(path: String): Boolean = try {
        File(path).exists()
    } catch (_: Exception) {
        false
    }

    private fun readFile(path: String): String? = try {
        File(path).takeIf { it.exists() && it.canRead() }?.readText()
    } catch (_: Exception) {
        null
    }

    private fun executeShellCommand(command: String): ShellResult {
        return try {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            ShellResult(exitCode == 0, output)
        } catch (e: Exception) {
            ShellResult(false, e.message ?: "Unbekannter Fehler")
        }
    }

    private data class ShellResult(val isSuccess: Boolean, val output: String)
}
