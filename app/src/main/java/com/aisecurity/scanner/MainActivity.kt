package com.aisecurity.scanner

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.ui.navigation.AppNavGraph
import com.aisecurity.scanner.ui.navigation.Screen
import com.aisecurity.scanner.ui.theme.AISecurityTheme
import com.aisecurity.scanner.ui.theme.AppTheme
import com.aisecurity.scanner.util.BiometricAuthManager
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {

    @Inject
    lateinit var settingsRepository: SettingsRepository

    @Inject
    lateinit var biometricAuthManager: BiometricAuthManager

    private val isAuthenticated = mutableStateOf(false)
    private var currentBiometricLock = false

    override fun onStop() {
        super.onStop()
        if (currentBiometricLock) {
            isAuthenticated.value = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Screenshot-Schutz standardmäßig aktivieren
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        enableEdgeToEdge()

        setContent {
            val settings by settingsRepository.settings.collectAsStateWithLifecycle(
                initialValue = com.aisecurity.scanner.data.repository.AppSettings()
            )

            // Reaktiver Screenshot-Schutz basierend auf Einstellung
            SideEffect {
                if (settings.screenshotAllowed) {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                } else {
                    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }

            val appTheme = when (settings.theme) {
                "Hell" -> AppTheme.LIGHT
                "Dunkel" -> AppTheme.DARK
                "AMOLED" -> AppTheme.AMOLED
                else -> AppTheme.SYSTEM
            }

            val startDestination = if (settings.onboardingCompleted)
                Screen.Home.route
            else
                Screen.Onboarding.route

            LaunchedEffect(settings.biometricLock) {
                currentBiometricLock = settings.biometricLock
                if (!settings.biometricLock) {
                    isAuthenticated.value = true
                } else if (!isAuthenticated.value) {
                    biometricAuthManager.authenticate(
                        activity = this@MainActivity,
                        onSuccess = { isAuthenticated.value = true },
                        onFailure = { finish() }
                    )
                }
            }

            AISecurityTheme(
                appTheme = appTheme,
                dynamicColor = settings.dynamicColor,
                fontSize = settings.fontSize
            ) {
                if (isAuthenticated.value) {
                    AppNavGraph(startDestination = startDestination)
                }
            }
        }
    }
}
