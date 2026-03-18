package com.aisecurity.scanner.ui.viewmodels

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.domain.model.ScanResult
import com.aisecurity.scanner.domain.model.Severity
import com.aisecurity.scanner.domain.model.VulnerabilityEntry
import com.aisecurity.scanner.domain.scanner.SecurityScanManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

enum class SortOrder { SEVERITY, CVSS, DATE }

data class ResultsUiState(
    val scanResult: ScanResult? = null,
    val filteredVulnerabilities: List<VulnerabilityEntry> = emptyList(),
    val selectedSeverity: Severity? = null,
    val sortOrder: SortOrder = SortOrder.SEVERITY,
    val isLoading: Boolean = true,
    val scanLogLines: List<String> = emptyList()
)

@HiltViewModel
class ResultsViewModel @Inject constructor(
    private val scanRepository: ScanRepository,
    private val scanManager: SecurityScanManager,
    savedStateHandle: SavedStateHandle
) : ViewModel() {

    private val scanId: String = savedStateHandle["scanId"] ?: ""

    private val _uiState = MutableStateFlow(ResultsUiState())
    val uiState: StateFlow<ResultsUiState> = _uiState.asStateFlow()

    init {
        loadScan()
    }

    private fun loadScan() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            val result = runCatching { scanRepository.getScanWithDetails(scanId) }.getOrNull()
            _uiState.update {
                it.copy(
                    scanResult = result,
                    filteredVulnerabilities = result?.vulnerabilities ?: emptyList(),
                    isLoading = false,
                    scanLogLines = scanManager.lastScanLog
                )
            }
        }
    }

    fun filterBySeverity(severity: Severity?) {
        _uiState.update { state ->
            val base = state.scanResult?.vulnerabilities ?: emptyList()
            val filtered = if (severity == null) base
            else base.filter { it.severity == severity }
            state.copy(
                selectedSeverity = severity,
                filteredVulnerabilities = applySorting(filtered, state.sortOrder)
            )
        }
    }

    fun setSortOrder(order: SortOrder) {
        _uiState.update { state ->
            state.copy(
                sortOrder = order,
                filteredVulnerabilities = applySorting(state.filteredVulnerabilities, order)
            )
        }
    }

    private fun applySorting(
        list: List<VulnerabilityEntry>,
        order: SortOrder
    ): List<VulnerabilityEntry> = when (order) {
        SortOrder.SEVERITY -> list.sortedWith(compareBy({ it.severity.order }, { -it.cvssScore }))
        SortOrder.CVSS -> list.sortedByDescending { it.cvssScore }
        SortOrder.DATE -> list.sortedByDescending { it.detectedAt }
    }
}
