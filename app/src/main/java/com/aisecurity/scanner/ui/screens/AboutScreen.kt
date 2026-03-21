package com.aisecurity.scanner.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.BuildConfig
import com.aisecurity.scanner.ui.viewmodels.AboutViewModel

private data class LibraryEntry(val name: String, val license: String)

private val libraries = listOf(
    LibraryEntry("Jetpack Compose / AndroidX", "Apache 2.0"),
    LibraryEntry("Hilt (Dagger)", "Apache 2.0"),
    LibraryEntry("Room", "Apache 2.0"),
    LibraryEntry("Retrofit / OkHttp", "Apache 2.0"),
    LibraryEntry("Moshi", "Apache 2.0"),
    LibraryEntry("Coil", "Apache 2.0"),
    LibraryEntry("SQLCipher for Android", "BSL 1.1"),
    LibraryEntry("Jsoup", "MIT")
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(
    onNavigateBack: () -> Unit,
    viewModel: AboutViewModel = hiltViewModel()
) {
    val changelog by viewModel.changelog.collectAsStateWithLifecycle()
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("App", "Changelog", "Lizenzen")

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Über die App") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Zurück")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            TabRow(selectedTabIndex = selectedTab) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        text = { Text(title) }
                    )
                }
            }

            when (selectedTab) {
                0 -> AppTab()
                1 -> ChangelogTab(changelog)
                2 -> LicensesTab()
            }
        }
    }
}

@Composable
private fun AppTab() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Icon(
            Icons.Default.Shield,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Text(
            text = "AI Security Scanner",
            style = MaterialTheme.typography.headlineMedium
        )
        Text(
            text = "Version ${BuildConfig.VERSION_NAME}",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = "Umfassende Sicherheitsanalyse für Android-Geräte mit 11 Scan-Modulen.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Haftungsausschluss",
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                Text(
                    text = "Diese App dient ausschließlich zu Informationszwecken. " +
                            "Die Ergebnisse ersetzen keine professionelle Sicherheitsberatung. " +
                            "Die Entwickler übernehmen keine Haftung für Schäden, die aus der " +
                            "Nutzung dieser App entstehen.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun ChangelogTab(changelog: String) {
    if (changelog.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        val lines = changelog.lines()
        items(lines) { line ->
            if (line.startsWith("## ")) {
                Text(
                    text = line.removePrefix("## "),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 12.dp, bottom = 4.dp)
                )
            } else if (line.isNotBlank()) {
                Text(
                    text = line,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        item { Spacer(Modifier.height(16.dp)) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LicensesTab() {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        items(libraries) { lib ->
            ListItem(
                headlineContent = { Text(lib.name) },
                supportingContent = {
                    Text(
                        lib.license,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            )
            HorizontalDivider()
        }
        item { Spacer(Modifier.height(16.dp)) }
    }
}
