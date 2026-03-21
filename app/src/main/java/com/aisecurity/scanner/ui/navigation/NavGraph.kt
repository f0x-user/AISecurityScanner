package com.aisecurity.scanner.ui.navigation

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument

import com.aisecurity.scanner.ui.screens.*

@Composable
fun AppNavGraph(startDestination: String = Screen.Onboarding.route) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route
    val bottomBarRoutes = setOf(Screen.Home.route, Screen.History.route, Screen.Settings.route)

    Scaffold(
        bottomBar = {
            AnimatedVisibility(visible = currentRoute in bottomBarRoutes) {
                NavigationBar {
                    NavigationBarItem(
                        selected = currentRoute == Screen.Home.route,
                        onClick = { navigateBottomBar(navController, Screen.Home.route) },
                        icon = { Icon(Icons.Default.Dashboard, contentDescription = "Dashboard") },
                        label = { Text("Dashboard") }
                    )
                    NavigationBarItem(
                        selected = currentRoute == Screen.History.route,
                        onClick = { navigateBottomBar(navController, Screen.History.route) },
                        icon = { Icon(Icons.Default.History, contentDescription = "Verlauf") },
                        label = { Text("Verlauf") }
                    )
                    NavigationBarItem(
                        selected = currentRoute == Screen.Settings.route,
                        onClick = { navigateBottomBar(navController, Screen.Settings.route) },
                        icon = { Icon(Icons.Default.Settings, contentDescription = "Einstellungen") },
                        label = { Text("Einstellungen") }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = startDestination,
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {

            composable(Screen.Onboarding.route) {
                OnboardingScreen(
                    onOnboardingComplete = {
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Onboarding.route) { inclusive = true }
                        }
                    }
                )
            }

            composable(Screen.Home.route) {
                HomeScreen(
                    onNavigateToScan = {
                        navController.navigate(Screen.Scan.route)
                    },
                    onNavigateToResults = { scanId ->
                        navController.navigate(Screen.Results.createRoute(scanId))
                    }
                )
            }

            composable(route = Screen.Scan.route) {
                ScanScreen(
                    onScanComplete = { scanId ->
                        navController.navigate(Screen.Results.createRoute(scanId)) {
                            popUpTo(Screen.Home.route)
                        }
                    },
                    onNavigateBack = { navController.popBackStack() }
                )
            }

            composable(
                route = Screen.Results.route,
                arguments = listOf(navArgument("scanId") { type = NavType.StringType })
            ) { backStackEntry ->
                val scanId = backStackEntry.arguments?.getString("scanId") ?: ""
                ResultsScreen(
                    onNavigateBack = { navController.popBackStack() },
                    onNavigateToDetail = { vulnId ->
                        val encoded = java.net.URLEncoder.encode(vulnId, "UTF-8")
                        navController.navigate(Screen.Detail.createRoute(scanId, encoded))
                    }
                )
            }

            composable(
                route = Screen.Detail.route,
                arguments = listOf(
                    navArgument("scanId") { type = NavType.StringType },
                    navArgument("vulnId") { type = NavType.StringType }
                )
            ) {
                DetailScreen(onNavigateBack = { navController.popBackStack() })
            }

            composable(Screen.History.route) {
                HistoryScreen(
                    onNavigateBack = { navController.popBackStack() },
                    onNavigateToResults = { scanId ->
                        navController.navigate(Screen.Results.createRoute(scanId))
                    }
                )
            }

            composable(Screen.Settings.route) {
                SettingsScreen(
                    onNavigateBack = { navController.popBackStack() },
                    onNavigateToAbout = { navController.navigate(Screen.About.route) }
                )
            }

            composable(Screen.About.route) {
                AboutScreen(onNavigateBack = { navController.popBackStack() })
            }
        }
    }
}

private fun navigateBottomBar(navController: NavController, route: String) {
    navController.navigate(route) {
        popUpTo(navController.graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}
