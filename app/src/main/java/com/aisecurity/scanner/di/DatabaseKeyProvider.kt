package com.aisecurity.scanner.di

import android.content.SharedPreferences
import android.util.Base64
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Verwaltet die SQLCipher-Datenbank-Passphrase.
 *
 * Beim ersten Aufruf wird ein 32-Byte-Zufallsschlüssel erzeugt,
 * Base64-kodiert und sicher in EncryptedSharedPreferences gespeichert.
 * Bei allen weiteren Aufrufen wird der gespeicherte Schlüssel zurückgegeben.
 */
@Singleton
class DatabaseKeyProvider @Inject constructor(
    private val encryptedPrefs: SharedPreferences
) {
    fun getOrCreatePassphrase(): ByteArray {
        val stored = encryptedPrefs.getString(KEY_DB_PASSPHRASE, null)
        if (stored != null) {
            return Base64.decode(stored, Base64.DEFAULT)
        }
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val encoded = Base64.encodeToString(bytes, Base64.DEFAULT)
        encryptedPrefs.edit().putString(KEY_DB_PASSPHRASE, encoded).apply()
        return bytes
    }

    companion object {
        private const val KEY_DB_PASSPHRASE = "db_passphrase"
    }
}
