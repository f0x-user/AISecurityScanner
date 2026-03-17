package com.aisecurity.scanner.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.R
import com.aisecurity.scanner.domain.model.Severity
import com.aisecurity.scanner.domain.model.VulnerabilityEntry
import com.aisecurity.scanner.ui.components.SeverityBadge
import com.aisecurity.scanner.ui.viewmodels.ResultsViewModel
import com.aisecurity.scanner.ui.viewmodels.SortOrder

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultsScreen(
    onNavigateBack: () -> Unit,
    onNavigateToDetail: (String) -> Unit,
    viewModel: ResultsViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

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
                        modifier = Modifier.semantics {
                            contentDescription = "Filter: Alle"
                        }
                    )
                }
                items(Severity.entries) { severity ->
                    FilterChip(
                        selected = uiState.selectedSeverity == severity,
                        onClick = { viewModel.filterBySeverity(severity) },
                        label = { Text(severity.label) },
                        modifier = Modifier.semantics {
                            contentDescription = "Filter: ${severity.label}"
                        }
                    )
                }
            }

            // Ergebnisliste
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
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VulnerabilityCard(
    vulnerability: VulnerabilityEntry,
    onClick: () -> Unit
) {
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
                            onClick = onClick,
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
        }
    }
}
