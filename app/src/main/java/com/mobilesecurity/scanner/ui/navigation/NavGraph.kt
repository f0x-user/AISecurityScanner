package com.mobilesecurity.scanner.ui.navigation

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.mobilesecurity.scanner.ui.screens.*
import kotlinx.coroutines.launch

private val TAB_ROUTES = listOf(
    Screen.Home.route,
    Screen.History.route,
    Screen.BreachCheck.route,
    Screen.Settings.route
)

@Composable
fun AppNavGraph(startDestination: String = Screen.Onboarding.route) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    val pagerState = rememberPagerState(initialPage = 0) { TAB_ROUTES.size }
    val coroutineScope = rememberCoroutineScope()

    val isMainScreen = currentRoute == Screen.Main.route

    Scaffold(
        bottomBar = {
            AnimatedVisibility(visible = isMainScreen) {
                NavigationBar {
                    NavigationBarItem(
                        selected = pagerState.currentPage == 0,
                        onClick = { coroutineScope.launch { pagerState.animateScrollToPage(0) } },
                        icon = { Icon(Icons.Default.Dashboard, contentDescription = "Dashboard") },
                        label = { Text("Dashboard") }
                    )
                    NavigationBarItem(
                        selected = pagerState.currentPage == 1,
                        onClick = { coroutineScope.launch { pagerState.animateScrollToPage(1) } },
                        icon = { Icon(Icons.Default.History, contentDescription = "Verlauf") },
                        label = { Text("Verlauf") }
                    )
                    NavigationBarItem(
                        selected = pagerState.currentPage == 2,
                        onClick = { coroutineScope.launch { pagerState.animateScrollToPage(2) } },
                        icon = { Icon(Icons.Default.Security, contentDescription = "Datenleck") },
                        label = { Text("Datenleck") }
                    )
                    NavigationBarItem(
                        selected = pagerState.currentPage == 3,
                        onClick = { coroutineScope.launch { pagerState.animateScrollToPage(3) } },
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
                        navController.navigate(Screen.Main.route) {
                            popUpTo(Screen.Onboarding.route) { inclusive = true }
                        }
                    }
                )
            }

            composable(Screen.Main.route) {
                HorizontalPager(
                    state = pagerState,
                    modifier = Modifier.fillMaxSize(),
                    beyondViewportPageCount = 1
                ) { page ->
                    when (page) {
                        0 -> HomeScreen(
                            onNavigateToScan = { navController.navigate(Screen.Scan.route) },
                            onNavigateToResults = { scanId ->
                                navController.navigate(Screen.Results.createRoute(scanId))
                            }
                        )
                        1 -> HistoryScreen(
                            onNavigateBack = { navController.popBackStack() },
                            onNavigateToResults = { scanId ->
                                navController.navigate(Screen.Results.createRoute(scanId))
                            }
                        )
                        2 -> BreachCheckScreen(
                            onNavigateBack = { navController.popBackStack() }
                        )
                        3 -> SettingsScreen(
                            onNavigateBack = { navController.popBackStack() },
                            onNavigateToAbout = { navController.navigate(Screen.About.route) }
                        )
                    }
                }
            }

            composable(route = Screen.Scan.route) {
                ScanScreen(
                    onScanComplete = { scanId ->
                        navController.navigate(Screen.Results.createRoute(scanId)) {
                            popUpTo(Screen.Main.route)
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

            composable(Screen.About.route) {
                AboutScreen(onNavigateBack = { navController.popBackStack() })
            }
        }
    }
}

