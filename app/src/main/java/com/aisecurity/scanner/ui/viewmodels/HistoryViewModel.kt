package com.aisecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.domain.model.ScanDelta
import com.aisecurity.scanner.domain.model.ScanResult
import com.aisecurity.scanner.domain.model.compareTo
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class HistoryViewModel @Inject constructor(
    private val scanRepository: ScanRepository
) : ViewModel() {

    val scans: StateFlow<List<ScanResult>> = scanRepository.getAllScans()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _deletingId = MutableStateFlow<String?>(null)
    val deletingId: StateFlow<String?> = _deletingId.asStateFlow()

    private val _selectedDelta = MutableStateFlow<ScanDelta?>(null)
    val selectedDelta: StateFlow<ScanDelta?> = _selectedDelta.asStateFlow()

    fun computeDelta(scanId: String) = viewModelScope.launch {
        val allScans = scanRepository.getAllScansOnce()
        val sorted = allScans.sortedByDescending { it.timestamp }
        val idx = sorted.indexOfFirst { it.id == scanId }
        if (idx >= 0 && idx < sorted.size - 1) {
            val current = scanRepository.getScanWithDetails(scanId) ?: return@launch
            val previous = scanRepository.getScanWithDetails(sorted[idx + 1].id) ?: return@launch
            _selectedDelta.value = current.compareTo(previous)
        } else {
            _selectedDelta.value = null
        }
    }

    fun clearDelta() { _selectedDelta.value = null }

    fun deleteScan(scanId: String) {
        viewModelScope.launch {
            _deletingId.value = scanId
            runCatching { scanRepository.deleteScan(scanId) }
            _deletingId.value = null
        }
    }

    fun getScoreTrend(scans: List<ScanResult>): String {
        if (scans.size < 2) return "Stabil"
        val latest = scans.first().overallScore
        val previous = scans[1].overallScore
        return when {
            latest > previous -> "Verbesserung"
            latest < previous -> "Verschlechterung"
            else -> "Stabil"
        }
    }
}
