package com.aisecurity.scanner.ui.viewmodels

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.domain.model.ScanResult
import com.aisecurity.scanner.domain.model.Severity
import com.aisecurity.scanner.domain.model.VulnerabilityEntry
import com.aisecurity.scanner.domain.scanner.SecurityScanManager
import com.aisecurity.scanner.util.JsonExporter
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
    private val jsonExporter: JsonExporter,
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

    fun exportCurrentScanAsJson(context: Context) = viewModelScope.launch {
        val scan = uiState.value.scanResult ?: return@launch
        runCatching {
            val file = jsonExporter.export(scan)
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "AI Security Scanner – Scan-Ergebnisse")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(Intent.createChooser(intent, "JSON exportieren"))
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
