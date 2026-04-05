package com.mobilesecurity.scanner.ui.viewmodels

import android.app.DownloadManager
import android.content.Context
import android.net.Uri
import android.os.Environment
import androidx.core.net.toUri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mobilesecurity.scanner.domain.update.UpdateCheckResult
import com.mobilesecurity.scanner.domain.update.UpdateChecker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class UpdateViewModel @Inject constructor(
    private val updateChecker: UpdateChecker,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _state = MutableStateFlow<UpdateCheckResult>(UpdateCheckResult.Checking)
    val state: StateFlow<UpdateCheckResult> = _state.asStateFlow()

    private val _downloadId = MutableStateFlow<Long?>(null)
    val downloadId: StateFlow<Long?> = _downloadId.asStateFlow()

    init {
        checkForUpdate()
    }

    fun checkForUpdate() {
        viewModelScope.launch {
            _state.value = UpdateCheckResult.Checking
            _state.value = runCatching { updateChecker.checkForUpdate() }
                .getOrElse { UpdateCheckResult.Error(it.message ?: "Fehler") }
        }
    }

    fun dismiss() {
        _state.value = UpdateCheckResult.Dismissed
    }

    fun startDownload(downloadUrl: String, version: String) {
        val fileName = "SecurityScanner-v$version.apk"
        val request = DownloadManager.Request(downloadUrl.toUri()).apply {
            setTitle("SecurityScanner $version")
            setDescription("Update wird heruntergeladen…")
            setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName)
            setMimeType("application/vnd.android.package-archive")
        }
        val dm = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
        _downloadId.value = dm.enqueue(request)
    }
}
