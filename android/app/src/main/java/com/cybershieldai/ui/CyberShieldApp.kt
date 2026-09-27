package com.cybershieldai.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.cybershieldai.ui.theme.ScreenGradient
import com.cybershieldai.ui.alerts.AlertsScreen
import com.cybershieldai.ui.apps.AppsScreen
import com.cybershieldai.ui.assistant.AssistantScreen
import com.cybershieldai.ui.home.HomeScreen
import com.cybershieldai.ui.more.MoreScreen
import com.cybershieldai.ui.protection.ProtectionScreen
import com.cybershieldai.ui.threat.ThreatAlertScreen
import com.cybershieldai.ui.incidents.IncidentScreen
import com.cybershieldai.ui.network.NetworkScreen
import com.cybershieldai.ui.privacy.PrivacyScreen
import com.cybershieldai.ui.scan.ScanScreen
import com.cybershieldai.ui.apps.AppDetailScreen
import com.cybershieldai.ui.settings.ProtectionSetupScreen
import com.cybershieldai.ui.settings.SettingsScreen
import com.cybershieldai.ui.timeline.TimelineScreen

data class BottomNavItem(val route: String, val label: String, val icon: ImageVector)

@Composable
fun CyberShieldApp(initialSharedText: String? = null, startScreen: String? = null) {
    val navController = rememberNavController()

    // Notification deep links (Alerts / Incidents / Privacy / Apps / Threat detail)
    LaunchedEffect(startScreen) {
        startScreen?.let { screen ->
            // "threat:<eventId>" opens the Threat Alert detail for that event.
            when {
                screen.startsWith("threat:") -> {
                    val id = screen.removePrefix("threat:").toLongOrNull() ?: -1L
                    if (id > 0) navController.navigate("threat/$id") { launchSingleTop = true }
                }
                // "scam"/"report" screens were removed (Scam Protection / Report
                // Scam); route legacy deep links to a live screen so stale
                // notifications cannot crash navigation.
                screen == "scam" -> navController.navigate("alerts") { launchSingleTop = true }
                screen == "report" -> navController.navigate("reports") { launchSingleTop = true }
                else -> navController.navigate(screen) { launchSingleTop = true }
            }
        }
    }

    // Bottom navigation (spec §15): HOME · SCANNERS · ALERTS · REPORTS
    val items = listOf(
        BottomNavItem("home", "Home", Icons.Filled.Home),
        BottomNavItem("scanners", "Scanners", Icons.Filled.Search),
        BottomNavItem("alerts", "Alerts", Icons.Filled.Notifications),
        BottomNavItem("reports", "Reports", Icons.Filled.Assessment)
    )
    val backStack by navController.currentBackStackEntryAsState()
    val currentRoute = backStack?.destination?.route

    Scaffold(
        modifier = Modifier.background(ScreenGradient),
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        bottomBar = {
            NavigationBar(containerColor = com.cybershieldai.ui.theme.Surface) {
                items.forEach { item ->
                    NavigationBarItem(
                        selected = currentRoute == item.route,
                        onClick = {
                            navController.navigate(item.route) {
                                popUpTo(navController.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(item.icon, contentDescription = item.label) },
                        label = { Text(item.label, style = com.cybershieldai.ui.theme.CS.Nav) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = com.cybershieldai.ui.theme.Primary,
                            selectedTextColor = com.cybershieldai.ui.theme.Primary,
                            indicatorColor = com.cybershieldai.ui.theme.Primary.copy(alpha = 0.15f)
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = "home",
            modifier = Modifier.padding(innerPadding)
        ) {
            composable("home") { HomeScreen(navController, initialSharedText) }
            composable("apps") { AppsScreen(navController) }
            composable("privacy") { PrivacyScreen() }
            composable("scan") { ScanScreen(initialSharedText) }
            composable("alerts") { AlertsScreen(navController) }
            composable("protection") { ProtectionScreen(navController) }
            composable("more") { MoreScreen(navController) }
            composable("scanners") { com.cybershieldai.ui.scanners.ScannersScreen(navController) }
            composable("reports") { com.cybershieldai.ui.reports.ReportsScreen(navController) }
            composable("totalscan") {
                com.cybershieldai.ui.totalscan.TotalScanScreen(navController)
            }
            composable(
                route = "threat/{eventId}",
                arguments = listOf(
                    androidx.navigation.navArgument("eventId") {
                        type = androidx.navigation.NavType.LongType
                    }
                )
            ) { entry ->
                ThreatAlertScreen(
                    navController,
                    entry.arguments?.getLong("eventId") ?: -1L)
            }


            // App detail: {packageName} argument (URL-encoded for the route)
            composable(
                route = "appdetail/{pkg}",
                arguments = listOf(
                    androidx.navigation.navArgument("pkg") {
                        type = androidx.navigation.NavType.StringType
                    }
                )
            ) { entry ->
                val pkg = entry.arguments?.getString("pkg").orEmpty()
                AppDetailScreen(
                    packageName = java.net.URLDecoder.decode(pkg, "UTF-8"),
                    onBack = { navController.popBackStack() }
                )
            }

            // Secondary screens reachable from Home / Alerts / Settings
            composable("timeline") { TimelineScreen(navController) }
            composable("incidents") { IncidentScreen(navController) }
            composable("assistant") {
                AssistantScreen(aiModelSettings = { navController.navigate("ai_model_settings") })
            }
            composable("ai_model_settings") {
                com.cybershieldai.ui.ai.AiModelSettingsScreen(onBack = { navController.popBackStack() })
            }
            composable("network") { NetworkScreen() }
            composable("setup") { ProtectionSetupScreen() }
            composable("settings") { SettingsScreen() }
            composable("diagnostics") { com.cybershieldai.ui.diagnostics.DiagnosticsScreen(navController) }
        }
    }
}

/** Navigation helper used by screens via the passed controller. */
fun navigateTo(navController: NavHostController, route: String) {
    navController.navigate(route) { launchSingleTop = true }
}
