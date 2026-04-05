package com.mobilesecurity.scanner.di

import android.content.SharedPreferences
import androidx.core.content.edit
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class NvdKeyProvider @Inject constructor(
    private val encryptedPrefs: SharedPreferences
) {
    fun getApiKey(): String =
        encryptedPrefs.getString(KEY_NVD_API_KEY, "") ?: ""

    fun setApiKey(key: String) =
        encryptedPrefs.edit { putString(KEY_NVD_API_KEY, key) }

    companion object {
        private const val KEY_NVD_API_KEY = "nvd_api_key"
    }
}
