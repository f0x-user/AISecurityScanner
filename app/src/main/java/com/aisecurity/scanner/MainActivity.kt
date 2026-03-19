package com.aisecurity.scanner

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import androidx.compose.runtime.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
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

            var isAuthenticated by remember { mutableStateOf(!settings.biometricLock) }

            LaunchedEffect(settings.biometricLock) {
                if (!settings.biometricLock) {
                    isAuthenticated = true
                } else if (!isAuthenticated) {
                    biometricAuthManager.authenticate(
                        activity = this@MainActivity,
                        onSuccess = { isAuthenticated = true },
                        onFailure = { finish() }
                    )
                }
            }

            AISecurityTheme(
                appTheme = appTheme,
                dynamicColor = settings.dynamicColor,
                fontSize = settings.fontSize
            ) {
                if (isAuthenticated) {
                    AppNavGraph(startDestination = startDestination)
                }
            }
        }
    }
}
