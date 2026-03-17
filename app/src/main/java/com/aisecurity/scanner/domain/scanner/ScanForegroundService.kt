package com.aisecurity.scanner.domain.scanner

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.aisecurity.scanner.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import javax.inject.Inject

@AndroidEntryPoint
class ScanForegroundService : Service() {

    @Inject
    lateinit var scanManager: SecurityScanManager

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    companion object {
        const val CHANNEL_ID = "scan_channel"
        const val NOTIFICATION_ID = 1001
        const val ACTION_START = "START_SCAN"
        const val ACTION_STOP = "STOP_SCAN"
        const val EXTRA_SCAN_DEPTH = "scan_depth"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                scanManager.cancelScan()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Sicherheits-Scan",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Benachrichtigungen während des Sicherheitsscans"
            }
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(message: String): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, ScanForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AI Security Scanner")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_media_pause, "Abbrechen", stopIntent)
            .setOngoing(true)
            .build()
    }
}
