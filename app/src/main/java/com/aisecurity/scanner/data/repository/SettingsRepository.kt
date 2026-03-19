package com.aisecurity.scanner.data.repository

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

data class AppSettings(
    val theme: String = "System",
    val dynamicColor: Boolean = true,
    val fontSize: String = "Standard",
    val language: String = "Deutsch",
    val screenshotAllowed: Boolean = false,
    val autoUpdateDb: Boolean = true,
    val updateInterval: String = "Täglich",
    val offlineMode: Boolean = false,
    val dataRetentionDays: Int = 30,
    val localOnlyMode: Boolean = false,
    val encryptLocalData: Boolean = true,
    val exportFormat: String = "PDF",
    val includeRemediation: Boolean = true,
    val onboardingCompleted: Boolean = false,
    val debugMode: Boolean = false
)

@Singleton
class SettingsRepository @Inject constructor(
    private val dataStore: DataStore<androidx.datastore.preferences.core.Preferences>
) {
    companion object {
        val KEY_THEME = stringPreferencesKey("theme")
        val KEY_DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
        val KEY_FONT_SIZE = stringPreferencesKey("font_size")
        val KEY_LANGUAGE = stringPreferencesKey("language")
        val KEY_AUTO_UPDATE_DB = booleanPreferencesKey("auto_update_db")
        val KEY_UPDATE_INTERVAL = stringPreferencesKey("update_interval")
        val KEY_OFFLINE_MODE = booleanPreferencesKey("offline_mode")
        val KEY_DATA_RETENTION_DAYS = intPreferencesKey("data_retention_days")
        val KEY_LOCAL_ONLY_MODE = booleanPreferencesKey("local_only_mode")
        val KEY_ENCRYPT_LOCAL_DATA = booleanPreferencesKey("encrypt_local_data")
        val KEY_EXPORT_FORMAT = stringPreferencesKey("export_format")
        val KEY_INCLUDE_REMEDIATION = booleanPreferencesKey("include_remediation")
        val KEY_ONBOARDING_COMPLETED = booleanPreferencesKey("onboarding_completed")
        val KEY_DEBUG_MODE = booleanPreferencesKey("debug_mode")
        val KEY_SCREENSHOT_ALLOWED = booleanPreferencesKey("screenshot_allowed")
    }

    val settings: Flow<AppSettings> = dataStore.data
        .catch { emit(emptyPreferences()) }
        .map { prefs ->
            AppSettings(
                theme = prefs[KEY_THEME] ?: "System",
                dynamicColor = prefs[KEY_DYNAMIC_COLOR] ?: true,
                fontSize = prefs[KEY_FONT_SIZE] ?: "Standard",
                language = prefs[KEY_LANGUAGE] ?: "Deutsch",
                screenshotAllowed = prefs[KEY_SCREENSHOT_ALLOWED] ?: false,
                autoUpdateDb = prefs[KEY_AUTO_UPDATE_DB] ?: true,
                updateInterval = prefs[KEY_UPDATE_INTERVAL] ?: "Täglich",
                offlineMode = prefs[KEY_OFFLINE_MODE] ?: false,
                dataRetentionDays = prefs[KEY_DATA_RETENTION_DAYS] ?: 30,
                localOnlyMode = prefs[KEY_LOCAL_ONLY_MODE] ?: false,
                encryptLocalData = prefs[KEY_ENCRYPT_LOCAL_DATA] ?: true,
                exportFormat = prefs[KEY_EXPORT_FORMAT] ?: "PDF",
                includeRemediation = prefs[KEY_INCLUDE_REMEDIATION] ?: true,
                onboardingCompleted = prefs[KEY_ONBOARDING_COMPLETED] ?: false,
                debugMode = prefs[KEY_DEBUG_MODE] ?: false
            )
        }

    suspend fun updateTheme(theme: String) = dataStore.edit { it[KEY_THEME] = theme }
    suspend fun updateDynamicColor(enabled: Boolean) = dataStore.edit { it[KEY_DYNAMIC_COLOR] = enabled }
    suspend fun updateOfflineMode(enabled: Boolean) = dataStore.edit { it[KEY_OFFLINE_MODE] = enabled }
    suspend fun updateDataRetentionDays(days: Int) = dataStore.edit { it[KEY_DATA_RETENTION_DAYS] = days }
    suspend fun updateOnboardingCompleted(completed: Boolean) = dataStore.edit { it[KEY_ONBOARDING_COMPLETED] = completed }
    suspend fun updateExportFormat(format: String) = dataStore.edit { it[KEY_EXPORT_FORMAT] = format }
    suspend fun updateLocalOnlyMode(enabled: Boolean) = dataStore.edit { it[KEY_LOCAL_ONLY_MODE] = enabled }
    suspend fun updateEncryptLocalData(enabled: Boolean) = dataStore.edit { it[KEY_ENCRYPT_LOCAL_DATA] = enabled }
    suspend fun updateAutoUpdateDb(enabled: Boolean) = dataStore.edit { it[KEY_AUTO_UPDATE_DB] = enabled }
    suspend fun updateLanguage(language: String) = dataStore.edit { it[KEY_LANGUAGE] = language }
    suspend fun updateFontSize(size: String) = dataStore.edit { it[KEY_FONT_SIZE] = size }
    suspend fun updateDebugMode(enabled: Boolean) = dataStore.edit { it[KEY_DEBUG_MODE] = enabled }
    suspend fun updateScreenshotAllowed(enabled: Boolean) = dataStore.edit { it[KEY_SCREENSHOT_ALLOWED] = enabled }
}
