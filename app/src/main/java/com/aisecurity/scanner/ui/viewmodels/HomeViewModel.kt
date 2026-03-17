package com.aisecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.data.repository.VulnerabilityRepository
import com.aisecurity.scanner.domain.model.ScanResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

data class HomeUiState(
    val latestScan: ScanResult? = null,
    val isLoading: Boolean = false,
    val isDbUpdating: Boolean = false,
    val dbUpdateError: String? = null,
    val dbUpdateSuccess: String? = null
)

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val scanRepository: ScanRepository,
    private val vulnRepository: VulnerabilityRepository,
    private val settingsRepository: SettingsRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeUiState(isLoading = true))
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    init {
        loadLatestScan()
    }

    private fun loadLatestScan() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            val latest = runCatching { scanRepository.getLatestScan() }.getOrNull()
            _uiState.update { it.copy(latestScan = latest, isLoading = false) }
        }
    }

    fun updateVulnerabilityDatabase() {
        viewModelScope.launch {
            _uiState.update { it.copy(isDbUpdating = true, dbUpdateError = null, dbUpdateSuccess = null) }
            val settings = settingsRepository.settings.first()
            if (settings.offlineMode || settings.localOnlyMode) {
                _uiState.update {
                    it.copy(
                        isDbUpdating = false,
                        dbUpdateError = "Offline-Modus aktiv – kein Download möglich."
                    )
                }
                return@launch
            }
            val result = runCatching { vulnRepository.updateAndCacheDatabase() }
            _uiState.update {
                if (result.isSuccess) {
                    val r = result.getOrThrow()
                    it.copy(
                        isDbUpdating = false,
                        dbUpdateSuccess = "${r.cachedTotal} CVEs im Cache (${r.nvdCount} NVD · ${r.cisaCount} CISA KEV)"
                    )
                } else {
                    it.copy(
                        isDbUpdating = false,
                        dbUpdateError = result.exceptionOrNull()?.message ?: "Unbekannter Fehler"
                    )
                }
            }
        }
    }

    fun refresh() = loadLatestScan()
}
