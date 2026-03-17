package com.aisecurity.scanner.data.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.domain.scanner.SecurityScanManager
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

@HiltWorker
class AutoScanWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters,
    private val scanManager: SecurityScanManager,
    private val scanRepository: ScanRepository
) : CoroutineWorker(context, workerParams) {

    override suspend fun doWork(): Result {
        return runCatching {
            val result = scanManager.startScan()
            scanRepository.saveScan(result)
            Result.success()
        }.getOrElse {
            Result.retry()
        }
    }
}
