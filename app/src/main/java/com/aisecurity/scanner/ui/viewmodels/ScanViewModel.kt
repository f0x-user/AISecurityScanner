package com.aisecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.domain.model.ScanDepth
import com.aisecurity.scanner.domain.model.ScanProgress
import com.aisecurity.scanner.domain.model.ScanResult
import com.aisecurity.scanner.domain.model.ScanStatus
import com.aisecurity.scanner.domain.scanner.SecurityScanManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ScanViewModel @Inject constructor(
    private val scanManager: SecurityScanManager,
    private val scanRepository: ScanRepository
) : ViewModel() {

    val progress: StateFlow<ScanProgress> = scanManager.progress

    private val _scanResult = MutableStateFlow<ScanResult?>(null)
    val scanResult: StateFlow<ScanResult?> = _scanResult.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private var scanJob: Job? = null

    fun startScan(depth: ScanDepth) {
        if (progress.value.status == ScanStatus.RUNNING) return
        scanJob = viewModelScope.launch {
            _error.value = null
            _scanResult.value = null
            runCatching {
                val result = scanManager.startScan(depth)
                scanRepository.saveScan(result)
                _scanResult.value = result
            }.onFailure { e ->
                if (e !is kotlinx.coroutines.CancellationException) {
                    _error.value = e.message ?: "Unbekannter Fehler"
                }
            }
        }
    }

    fun cancelScan() {
        scanJob?.cancel()
        scanManager.cancelScan()
    }

    fun clearError() {
        _error.value = null
    }
}
