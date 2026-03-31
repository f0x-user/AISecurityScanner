package com.mobilesecurity.scanner.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mobilesecurity.scanner.R
import com.mobilesecurity.scanner.domain.model.Severity
import com.mobilesecurity.scanner.domain.model.VulnerabilityEntry
import com.mobilesecurity.scanner.ui.components.SeverityBadge
import com.mobilesecurity.scanner.ui.viewmodels.ResultsViewModel
import com.mobilesecurity.scanner.ui.viewmodels.SortOrder

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultsScreen(
    onNavigateBack: () -> Unit,
    onNavigateToDetail: (String) -> Unit,
    viewModel: ResultsViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var selectedTab by remember { mutableIntStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.results_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_back_button))
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.exportCurrentScanAsJson(context) }) {
                        Icon(Icons.Default.Share, contentDescription = "Als JSON exportieren")
                    }
                    if (selectedTab == 0) {
                        var sortMenuExpanded by remember { mutableStateOf(false) }
                        IconButton(onClick = { sortMenuExpanded = true }) {
                            Icon(Icons.Default.Sort, contentDescription = "Sortierung")
                        }
                        DropdownMenu(
                            expanded = sortMenuExpanded,
                            onDismissRequest = { sortMenuExpanded = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text("Nach Schweregrad") },
                                onClick = {
                                    viewModel.setSortOrder(SortOrder.SEVERITY)
                                    sortMenuExpanded = false
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Nach CVSS-Score") },
                                onClick = {
                                    viewModel.setSortOrder(SortOrder.CVSS)
                                    sortMenuExpanded = false
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Nach Datum") },
                                onClick = {
                                    viewModel.setSortOrder(SortOrder.DATE)
                                    sortMenuExpanded = false
                                }
                            )
                        }
                    }
                }
            )
        }
    ) { padding ->
        if (uiState.isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // Scan-Score Übersicht
            uiState.scanResult?.let { scan ->
                Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Score: ${scan.overallScore}/100",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "${uiState.filteredVulnerabilities.size} Befunde",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // Tabs: Befunde | Betroffene Apps | Scan-Log
            val allVulnerabilities = uiState.scanResult?.vulnerabilities ?: emptyList()
            val affectedAppsMap = remember(allVulnerabilities) {
                buildAffectedAppsMap(allVulnerabilities)
            }

            TabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Befunde") },
                    icon = { Icon(Icons.Default.BugReport, null, Modifier.size(18.dp)) }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = {
                        val appCount = affectedAppsMap.size
                        Text(if (appCount > 0) "Apps ($appCount)" else "Apps")
                    },
                    icon = { Icon(Icons.Default.Apps, null, Modifier.size(18.dp)) }
                )
                Tab(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    text = { Text("Scan-Log") },
                    icon = { Icon(Icons.Default.List, null, Modifier.size(18.dp)) }
                )
            }

            when (selectedTab) {
                0 -> FindingsTab(uiState, viewModel, onNavigateToDetail)
                1 -> AffectedAppsTab(affectedAppsMap, onNavigateToDetail)
                2 -> ScanLogTab(uiState.scanLogLines)
            }
        }
    }
}

@Composable
private fun ScanLogTab(logLines: List<String>) {
    if (logLines.isEmpty()) {
        Box(Modifier.fillMaxSize(), Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Default.List,
                    contentDescription = null,
                    modifier = Modifier.size(48.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Kein Scan-Log verfügbar.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "Log ist nur nach einem frisch durchgeführten Scan sichtbar.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        return
    }

    val listState = rememberLazyListState()
    LazyColumn(
        state = listState,
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        items(logLines) { line ->
            Text(
                text = line,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = if (line.startsWith("===") || line.startsWith("  Android") || line.startsWith("  Sicherheit"))
                    MaterialTheme.colorScheme.primary
                else
                    MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun FindingsTab(
    uiState: com.mobilesecurity.scanner.ui.viewmodels.ResultsUiState,
    viewModel: ResultsViewModel,
    onNavigateToDetail: (String) -> Unit
) {
    Column(modifier = Modifier.fillMaxSize()) {
        // Severity-Filter
        LazyRow(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                FilterChip(
                    selected = uiState.selectedSeverity == null,
                    onClick = { viewModel.filterBySeverity(null) },
                    label = { Text("Alle") },
                    modifier = Modifier.semantics { contentDescription = "Filter: Alle" }
                )
            }
            items(Severity.entries) { severity ->
                FilterChip(
                    selected = uiState.selectedSeverity == severity,
                    onClick = { viewModel.filterBySeverity(severity) },
                    label = { Text(severity.label) },
                    modifier = Modifier.semantics { contentDescription = "Filter: ${severity.label}" }
                )
            }
        }

        if (uiState.filteredVulnerabilities.isEmpty()) {
            Box(Modifier.fillMaxSize(), Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.height(16.dp))
                    Text(
                        stringResource(R.string.results_no_issues),
                        style = MaterialTheme.typography.bodyLarge
                    )
                }
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(uiState.filteredVulnerabilities, key = { it.id }) { vuln ->
                    VulnerabilityCard(
                        vulnerability = vuln,
                        onClick = { onNavigateToDetail(vuln.id) }
                    )
                }
            }
        }
    }
}

@Composable
private fun AffectedAppsTab(
    affectedAppsMap: Map<String, List<VulnerabilityEntry>>,
    onNavigateToDetail: (String) -> Unit
) {
    if (affectedAppsMap.isEmpty()) {
        Box(Modifier.fillMaxSize(), Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = null,
                    modifier = Modifier.size(64.dp),
                    tint = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    "Keine auffälligen Apps gefunden",
                    style = MaterialTheme.typography.bodyLarge
                )
            }
        }
        return
    }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(affectedAppsMap.entries.toList(), key = { it.key }) { (appName, vulns) ->
            AffectedAppCard(
                appName = appName,
                vulnerabilities = vulns,
                onVulnClick = onNavigateToDetail
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AffectedAppCard(
    appName: String,
    vulnerabilities: List<VulnerabilityEntry>,
    onVulnClick: (String) -> Unit
) {
    val worstSeverity = vulnerabilities.minByOrNull { it.severity.order }?.severity

    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            // App-Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    Icons.Default.Android,
                    contentDescription = null,
                    modifier = Modifier.size(32.dp),
                    tint = MaterialTheme.colorScheme.primary
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = appName,
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        text = "${vulnerabilities.size} Problem${if (vulnerabilities.size != 1) "e" else ""}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                worstSeverity?.let { SeverityBadge(it) }
            }

            // Trennlinie + Liste der Probleme
            Spacer(Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                vulnerabilities.forEach { vuln ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            when (vuln.severity) {
                                Severity.CRITICAL, Severity.HIGH -> Icons.Default.Error
                                Severity.MEDIUM -> Icons.Default.Warning
                                else -> Icons.Default.Info
                            },
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = when (vuln.severity) {
                                Severity.CRITICAL -> MaterialTheme.colorScheme.error
                                Severity.HIGH -> MaterialTheme.colorScheme.error.copy(alpha = 0.7f)
                                Severity.MEDIUM -> MaterialTheme.colorScheme.tertiary
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            }
                        )
                        TextButton(
                            onClick = { onVulnClick(vuln.id) },
                            contentPadding = PaddingValues(0.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = vuln.title,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                        Text(
                            text = "CVSS ${vuln.cvssScore}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

/** Erstellt eine nach Schweregrad sortierte Map: App-Name → betroffene Schwachstellen */
private fun buildAffectedAppsMap(
    vulnerabilities: List<VulnerabilityEntry>
): Map<String, List<VulnerabilityEntry>> {
    val map = mutableMapOf<String, MutableList<VulnerabilityEntry>>()
    for (vuln in vulnerabilities) {
        for (app in vuln.affectedApps) {
            map.getOrPut(app) { mutableListOf() }.add(vuln)
        }
    }
    // Sortierung: Apps mit schlimmsten Problemen zuerst
    return map
        .mapValues { (_, vulns) -> vulns.sortedBy { it.severity.order } }
        .entries
        .sortedWith(compareBy(
            { it.value.minOf { v -> v.severity.order } },
            { -it.value.size }
        ))
        .associate { it.key to it.value }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VulnerabilityCard(
    vulnerability: VulnerabilityEntry,
    onClick: () -> Unit
) {
    val context = LocalContext.current
    ElevatedCard(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = vulnerability.title,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 2
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = vulnerability.affectedComponent,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Column(
                    horizontalAlignment = Alignment.End,
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    SeverityBadge(vulnerability.severity)
                    Text(
                        text = "CVSS ${vulnerability.cvssScore}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (vulnerability.isActivelyExploited || vulnerability.isZeroDay) {
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (vulnerability.isZeroDay) {
                        AssistChip(
                            onClick = onClick,
                            label = { Text("Zero-Day", style = MaterialTheme.typography.labelSmall) },
                            leadingIcon = {
                                Icon(Icons.Default.BugReport, null, Modifier.size(14.dp))
                            }
                        )
                    }
                    if (vulnerability.isActivelyExploited) {
                        AssistChip(
                            onClick = onClick,
                            label = { Text("Aktiv ausgenutzt", style = MaterialTheme.typography.labelSmall) },
                            leadingIcon = {
                                Icon(Icons.Default.Warning, null, Modifier.size(14.dp))
                            }
                        )
                    }
                }
            }

            // Betroffene Apps als Chips anzeigen
            if (vulnerability.affectedApps.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Apps,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    vulnerability.affectedApps.take(3).forEach { appName ->
                        SuggestionChip(
                            onClick = {
                                // Direkt zur App navigieren via Packagename-Suche
                                val pkg = resolvePackageName(context, appName)
                                if (pkg != null) {
                                    runCatching {
                                        context.startActivity(
                                            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                                Uri.parse("package:$pkg"))
                                                .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                                        )
                                    }
                                } else {
                                    onClick()
                                }
                            },
                            label = { Text(appName, style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                    if (vulnerability.affectedApps.size > 3) {
                        Text(
                            "+${vulnerability.affectedApps.size - 3} weitere",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))
            Text(
                text = vulnerability.description,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // Quick-Fix Button wenn ein Settings-Link vorhanden ist
            vulnerability.remediation.deepLinkSettings?.let { settingsAction ->
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = {
                        runCatching {
                            context.startActivity(
                                Intent(settingsAction).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                            )
                        }.onFailure {
                            // Fallback auf Sicherheitseinstellungen
                            runCatching {
                                context.startActivity(
                                    Intent(Settings.ACTION_SECURITY_SETTINGS)
                                        .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                                )
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Icon(Icons.Default.Build, null, Modifier.size(14.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Jetzt beheben", style = MaterialTheme.typography.labelMedium)
                }
            }
        }
    }
}

/** Versucht, anhand des Anzeigenamens den Paketnamen einer App zu finden */
private fun resolvePackageName(context: android.content.Context, appName: String): String? {
    return try {
        val pm = context.packageManager
        pm.getInstalledApplications(0).firstOrNull { appInfo ->
            pm.getApplicationLabel(appInfo).toString().equals(appName, ignoreCase = true)
        }?.packageName
    } catch (_: Exception) { null }
}
