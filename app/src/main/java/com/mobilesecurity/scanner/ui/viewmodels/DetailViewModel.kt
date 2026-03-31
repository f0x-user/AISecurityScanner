package com.mobilesecurity.scanner.ui.viewmodels

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mobilesecurity.scanner.data.repository.ScanRepository
import com.mobilesecurity.scanner.domain.model.VulnerabilityEntry
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DetailViewModel @Inject constructor(
    private val scanRepository: ScanRepository,
    savedStateHandle: SavedStateHandle
) : ViewModel() {
    private val scanId: String = savedStateHandle["scanId"] ?: ""
    private val vulnId: String = savedStateHandle["vulnId"] ?: ""

    private val _vulnerability = MutableStateFlow<VulnerabilityEntry?>(null)
    val vulnerability: StateFlow<VulnerabilityEntry?> = _vulnerability.asStateFlow()

    init {
        viewModelScope.launch {
            val scan = scanRepository.getScanWithDetails(scanId)
            _vulnerability.value = scan?.vulnerabilities?.firstOrNull { it.id == vulnId }
        }
    }
}
