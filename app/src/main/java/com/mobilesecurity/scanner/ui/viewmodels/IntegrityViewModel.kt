package com.mobilesecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mobilesecurity.scanner.domain.integrity.IntegrityBaselineManager
import com.mobilesecurity.scanner.domain.integrity.IntegrityDiff
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class IntegrityUiState(
    val isLoading: Boolean = true,
    val hasBaseline: Boolean = false,
    val diff: IntegrityDiff? = null,
    val justCaptured: Boolean = false
)

@HiltViewModel
class IntegrityViewModel @Inject constructor(
    private val baselineManager: IntegrityBaselineManager
) : ViewModel() {

    private val _uiState = MutableStateFlow(IntegrityUiState())
    val uiState: StateFlow<IntegrityUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    /** Re-captures the current state and compares it against the stored baseline. */
    fun refresh() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, justCaptured = false)
            val diff = baselineManager.compareWithBaseline()
            _uiState.value = IntegrityUiState(
                isLoading = false,
                hasBaseline = diff.hasBaseline,
                diff = diff
            )
        }
    }

    /** Stores the current state as the new trusted baseline (Soll). */
    fun captureBaseline() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)
            baselineManager.captureAndStoreBaseline()
            val diff = baselineManager.compareWithBaseline()
            _uiState.value = IntegrityUiState(
                isLoading = false,
                hasBaseline = true,
                diff = diff,
                justCaptured = true
            )
        }
    }
}
