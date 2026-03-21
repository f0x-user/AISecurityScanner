package com.aisecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.data.repository.VulnerabilityRepository
import com.aisecurity.scanner.domain.model.ScanResult
import com.aisecurity.scanner.domain.model.VulnerabilityEntry
import com.aisecurity.scanner.domain.model.Severity
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

data class HomeUiState(
    val latestScan: ScanResult? = null,
    val isLoading: Boolean = false,
    val isDbUpdating: Boolean = false,
    val dbUpdateError: String? = null,
    val dbUpdateSuccess: String? = null,
    val scoreTrend: String = "Stabil",
    val topCriticalFindings: List<VulnerabilityEntry> = emptyList()
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
        // Flow-basierte Subscription: Dashboard aktualisiert sich automatisch nach jedem Scan
        viewModelScope.launch {
            scanRepository.getAllScans()
                .catch { _uiState.update { it.copy(isLoading = false) } }
                .collect { scans ->
                    val latestMeta = scans.firstOrNull()
                    val trend = computeTrend(scans)
                    val detailed = latestMeta?.let {
                        runCatching { scanRepository.getScanWithDetails(it.id) }.getOrNull()
                    }
                    val topFindings = detailed?.vulnerabilities
                        ?.filter { it.severity == Severity.CRITICAL || it.severity == Severity.HIGH }
                        ?.sortedWith(compareBy({ it.severity.order }, { -it.cvssScore }))
                        ?.take(3)
                        ?: emptyList()
                    _uiState.update {
                        it.copy(
                            latestScan = detailed ?: latestMeta,
                            isLoading = false,
                            scoreTrend = trend,
                            topCriticalFindings = topFindings
                        )
                    }
                }
        }
    }

    private fun computeTrend(scans: List<ScanResult>): String {
        if (scans.size < 2) return "Stabil"
        val latest = scans.first().overallScore
        val previous = scans[1].overallScore
        return when {
            latest > previous -> "Verbesserung"
            latest < previous -> "Verschlechterung"
            else -> "Stabil"
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

    // refresh() ist durch den Flow-Collector nicht mehr nötig – wird automatisch aktualisiert
}
