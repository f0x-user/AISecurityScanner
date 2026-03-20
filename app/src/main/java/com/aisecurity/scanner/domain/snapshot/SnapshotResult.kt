package com.aisecurity.scanner.domain.snapshot

import java.time.Instant

enum class SnapshotType {
    /** App-interner Zustand in SharedPreferences gespeichert (immer verfügbar) */
    VIRTUAL,
    /** Echter BTRFS-Subvolume-Snapshot (erfordert Root + BTRFS-Dateisystem) */
    BTRFS,
    /** Echter LVM-Snapshot (erfordert Root + LVM-Volume-Group) */
    LVM
}

data class SnapshotResult(
    val snapshotId: String,
    val timestamp: Instant,
    val success: Boolean,
    val type: SnapshotType,
    /** Dateisystempfad oder SharedPreferences-Schlüssel des Snapshots */
    val path: String = "",
    val errorMessage: String? = null
)
