package com.aisecurity.scanner

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.ui.navigation.AppNavGraph
import com.aisecurity.scanner.ui.navigation.Screen
import com.aisecurity.scanner.ui.theme.AISecurityTheme
import com.aisecurity.scanner.ui.theme.AppTheme
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject
    lateinit var settingsRepository: SettingsRepository

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

            AISecurityTheme(
                appTheme = appTheme,
                dynamicColor = settings.dynamicColor,
                fontSize = settings.fontSize
            ) {
                AppNavGraph(startDestination = startDestination)
            }
        }
    }
}
