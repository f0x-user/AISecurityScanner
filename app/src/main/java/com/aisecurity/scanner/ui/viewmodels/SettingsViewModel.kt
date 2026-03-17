package com.aisecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.AppSettings
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.domain.model.ScanDepth
import com.aisecurity.scanner.util.DebugLogger
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
    private val debugLogger: DebugLogger
) : ViewModel() {

    val settings: StateFlow<AppSettings> = settingsRepository.settings
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), AppSettings())

    /** Pfad zur zuletzt abgeschlossenen Debug-Log-Datei (zum Teilen/Speichern). */
    private val _lastDebugLogFile = MutableStateFlow<File?>(null)
    val lastDebugLogFile: StateFlow<File?> = _lastDebugLogFile.asStateFlow()

    /** Aktuelle Größe der laufenden Log-Datei in Bytes (live aktualisiert). */
    val activeLogFile: File? get() = debugLogger.getActiveLogFile()

    fun updateTheme(theme: String) = viewModelScope.launch { settingsRepository.updateTheme(theme) }
    fun updateDynamicColor(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateDynamicColor(enabled) }
    fun updateScanDepth(depth: ScanDepth) = viewModelScope.launch { settingsRepository.updateScanDepth(depth) }
    fun updateAutoScan(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateAutoScan(enabled) }
    fun updateCriticalAlerts(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateCriticalAlerts(enabled) }
    fun updateWeeklyReport(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateWeeklyReport(enabled) }
    fun updateNewCveAlerts(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateNewCveAlerts(enabled) }
    fun updateAutoUpdateDb(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateAutoUpdateDb(enabled) }
    fun updateOfflineMode(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateOfflineMode(enabled) }
    fun updateDataRetentionDays(days: Int) = viewModelScope.launch { settingsRepository.updateDataRetentionDays(days) }
    fun updateAnonymousTelemetry(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateAnonymousTelemetry(enabled) }
    fun updateLocalOnlyMode(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateLocalOnlyMode(enabled) }
    fun updateEncryptLocalData(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateEncryptLocalData(enabled) }
    fun updateExportFormat(format: String) = viewModelScope.launch { settingsRepository.updateExportFormat(format) }
    fun updateLanguage(language: String) = viewModelScope.launch { settingsRepository.updateLanguage(language) }
    fun updateFontSize(size: String) = viewModelScope.launch { settingsRepository.updateFontSize(size) }
    fun updateScanOnCharging(enabled: Boolean) = viewModelScope.launch { settingsRepository.updateScanOnCharging(enabled) }
    fun updateAutoScanInterval(interval: String) = viewModelScope.launch { settingsRepository.updateAutoScanInterval(interval) }

    fun updateDebugMode(enabled: Boolean) = viewModelScope.launch {
        if (enabled) {
            debugLogger.startLogging()
        } else {
            val file = debugLogger.stopLogging()
            _lastDebugLogFile.value = file
        }
        settingsRepository.updateDebugMode(enabled)
    }

    /** Löscht alle gespeicherten Debug-Log-Dateien. */
    fun deleteAllDebugLogs() {
        debugLogger.deleteAllLogFiles()
        _lastDebugLogFile.value = null
    }

    /** Gibt alle vorhandenen Log-Dateien zurück (für UI-Anzeige). */
    fun getAllDebugLogFiles(): List<File> = debugLogger.getAllLogFiles()
}
