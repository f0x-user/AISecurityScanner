package com.aisecurity.scanner

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.data.repository.AppSettings
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.ui.navigation.AppNavGraph
import com.aisecurity.scanner.ui.navigation.Screen
import com.aisecurity.scanner.ui.theme.AISecurityTheme
import com.aisecurity.scanner.ui.theme.AppTheme
import com.aisecurity.scanner.util.BiometricAuthManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.map
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

    override fun onResume() {
        super.onResume()
        if (currentBiometricLock && !isAuthenticated.value) {
            biometricAuthManager.authenticate(
                activity = this,
                onSuccess = { isAuthenticated.value = true },
                onFailure = { finish() }
            )
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Screenshot-Schutz standardmäßig aktivieren
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        enableEdgeToEdge()

        setContent {
            // null = DataStore noch nicht geladen; non-null = echte Settings verfügbar
            val nullableSettingsFlow = remember { settingsRepository.settings.map { it as AppSettings? } }
            val settings: AppSettings? by nullableSettingsFlow.collectAsStateWithLifecycle(initialValue = null)

            // Reaktiver Screenshot-Schutz basierend auf Einstellung
            SideEffect {
                if (settings?.screenshotAllowed == true) {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                } else {
                    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }

            val appTheme = when (settings?.theme) {
                "Hell" -> AppTheme.LIGHT
                "Dunkel" -> AppTheme.DARK
                "AMOLED" -> AppTheme.AMOLED
                else -> AppTheme.SYSTEM
            }

            AISecurityTheme(
                appTheme = appTheme,
                dynamicColor = settings?.dynamicColor ?: true,
                fontSize = settings?.fontSize ?: "Standard"
            ) {
                // DataStore noch nicht geladen → nichts rendern (verhindert Auth-Bypass)
                if (settings == null) return@AISecurityTheme

                val realSettings = settings!!

                val startDestination = if (realSettings.onboardingCompleted)
                    Screen.Home.route
                else
                    Screen.Onboarding.route

                LaunchedEffect(realSettings.biometricLock) {
                    currentBiometricLock = realSettings.biometricLock
                    if (!realSettings.biometricLock) {
                        isAuthenticated.value = true
                    } else if (!isAuthenticated.value) {
                        biometricAuthManager.authenticate(
                            activity = this@MainActivity,
                            onSuccess = { isAuthenticated.value = true },
                            onFailure = { finish() }
                        )
                    }
                }

                if (isAuthenticated.value) {
                    AppNavGraph(startDestination = startDestination)
                }
            }
        }
    }
}
