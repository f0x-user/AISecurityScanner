package com.aisecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.domain.model.ScanResult
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
