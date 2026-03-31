package com.mobilesecurity.scanner.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat

private val LightColorScheme = lightColorScheme(
    primary = PrimaryLight,
    onPrimary = OnPrimaryLight,
    primaryContainer = PrimaryContainerLight,
    onPrimaryContainer = OnPrimaryContainerLight,
    secondary = SecondaryLight,
    onSecondary = OnSecondaryLight,
    surface = SurfaceLight,
    background = BackgroundLight,
    error = ErrorLight
)

private val DarkColorScheme = darkColorScheme(
    primary = PrimaryDark,
    onPrimary = OnPrimaryDark,
    primaryContainer = PrimaryContainerDark,
    onPrimaryContainer = OnPrimaryContainerDark,
    secondary = SecondaryDark,
    onSecondary = OnSecondaryDark,
    surface = SurfaceDark,
    background = BackgroundDark,
    error = ErrorDark
)

private val AmoledColorScheme = darkColorScheme(
    primary = PrimaryDark,
    onPrimary = OnPrimaryDark,
    primaryContainer = PrimaryContainerDark,
    onPrimaryContainer = OnPrimaryContainerDark,
    secondary = SecondaryDark,
    onSecondary = OnSecondaryDark,
    surface = SurfaceAmoled,
    background = BackgroundAmoled,
    error = ErrorDark
)

enum class AppTheme { SYSTEM, LIGHT, DARK, AMOLED }

private fun scaleTypography(scale: Float): Typography {
    fun TextStyle.scaled() = copy(
        fontSize = (fontSize.value * scale).sp,
        lineHeight = (lineHeight.value * scale).sp
    )
    return Typography(
        displayLarge  = AppTypography.displayLarge.scaled(),
        displayMedium = AppTypography.displayMedium.scaled(),
        displaySmall  = AppTypography.displaySmall.scaled(),
        headlineLarge = AppTypography.headlineLarge.scaled(),
        headlineMedium= AppTypography.headlineMedium.scaled(),
        headlineSmall = AppTypography.headlineSmall.scaled(),
        titleLarge    = AppTypography.titleLarge.scaled(),
        titleMedium   = AppTypography.titleMedium.scaled(),
        titleSmall    = AppTypography.titleSmall.scaled(),
        bodyLarge     = AppTypography.bodyLarge.scaled(),
        bodyMedium    = AppTypography.bodyMedium.scaled(),
        bodySmall     = AppTypography.bodySmall.scaled(),
        labelLarge    = AppTypography.labelLarge.scaled(),
        labelMedium   = AppTypography.labelMedium.scaled(),
        labelSmall    = AppTypography.labelSmall.scaled()
    )
}

@Composable
fun AISecurityTheme(
    appTheme: AppTheme = AppTheme.SYSTEM,
    dynamicColor: Boolean = true,
    fontSize: String = "Standard",
    content: @Composable () -> Unit
) {
    val isDark = when (appTheme) {
        AppTheme.DARK, AppTheme.AMOLED -> true
        AppTheme.LIGHT -> false
        AppTheme.SYSTEM -> isSystemInDarkTheme()
    }

    val colorScheme = when {
        appTheme == AppTheme.AMOLED -> AmoledColorScheme
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (isDark) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        }
        isDark -> DarkColorScheme
        else -> LightColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primary.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !isDark
        }
    }

    val scaleFactor = when (fontSize) {
        "Klein"     -> 0.85f
        "Groß"      -> 1.15f
        "Sehr Groß" -> 1.30f
        else        -> 1.0f
    }
    val typography = if (scaleFactor == 1.0f) AppTypography else scaleTypography(scaleFactor)

    MaterialTheme(
        colorScheme = colorScheme,
        typography = typography,
        content = content
    )
}
