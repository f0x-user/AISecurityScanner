package com.aisecurity.scanner.ui.viewmodels

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@HiltViewModel
class AboutViewModel @Inject constructor(
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _changelog = MutableStateFlow("")
    val changelog: StateFlow<String> = _changelog.asStateFlow()

    init {
        viewModelScope.launch {
            _changelog.value = withContext(Dispatchers.IO) {
                runCatching {
                    context.assets.open("CHANGELOG.md").bufferedReader().readText()
                }.getOrElse { "Changelog nicht verfügbar." }
            }
        }
    }
}
