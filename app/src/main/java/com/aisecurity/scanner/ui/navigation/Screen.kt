package com.aisecurity.scanner.ui.navigation

sealed class Screen(val route: String) {
    object Onboarding : Screen("onboarding")
    object Home : Screen("home")
    object Scan : Screen("scan")
    object Results : Screen("results/{scanId}") {
        fun createRoute(scanId: String) = "results/$scanId"
    }
    object Detail : Screen("detail/{scanId}/{vulnId}") {
        fun createRoute(scanId: String, vulnId: String) = "detail/$scanId/$vulnId"
    }
    object History : Screen("history")
    object Settings : Screen("settings")
}
