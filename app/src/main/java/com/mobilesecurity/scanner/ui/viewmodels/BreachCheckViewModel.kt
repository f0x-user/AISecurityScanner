package com.mobilesecurity.scanner.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mobilesecurity.scanner.di.HibpKeyProvider
import com.mobilesecurity.scanner.domain.scanner.BreachCheckResult
import com.mobilesecurity.scanner.domain.scanner.BreachCheckScanner
import com.mobilesecurity.scanner.domain.scanner.PasswordPwnedResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class BreachCheckUiState(
    val isLoading: Boolean = false,
    val emailResult: BreachCheckResult? = null,
    val passwordResult: PasswordPwnedResult? = null,
    val error: String? = null
)

@HiltViewModel
class BreachCheckViewModel @Inject constructor(
    private val breachCheckScanner: BreachCheckScanner,
    private val hibpKeyProvider: HibpKeyProvider
) : ViewModel() {

    private val _uiState = MutableStateFlow(BreachCheckUiState())
    val uiState: StateFlow<BreachCheckUiState> = _uiState.asStateFlow()

    fun checkEmail(email: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, emailResult = null, error = null)
            val result = breachCheckScanner.checkEmailForBreaches(email.trim(), hibpKeyProvider.getApiKey())
            _uiState.value = _uiState.value.copy(isLoading = false, emailResult = result)
        }
    }

    fun checkPassword(password: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, passwordResult = null, error = null)
            val result = breachCheckScanner.checkPasswordPwned(password)
            _uiState.value = _uiState.value.copy(isLoading = false, passwordResult = result)
        }
    }

    fun clearResults() {
        _uiState.value = BreachCheckUiState()
    }
}
