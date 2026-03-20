package com.aisecurity.scanner.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.R
import com.aisecurity.scanner.ui.components.ScoreGauge
import com.aisecurity.scanner.ui.viewmodels.HomeViewModel
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onNavigateToScan: () -> Unit,
    onNavigateToResults: (String) -> Unit,
    onNavigateToHistory: () -> Unit,
    onNavigateToSettings: () -> Unit,
    viewModel: HomeViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.home_title)) },
                actions = {
                    IconButton(onClick = onNavigateToHistory) {
                        Icon(Icons.Default.History, contentDescription = "Scan-Verlauf")
                    }
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Einstellungen")
                    }
                }
            )
        }
    ) { padding ->
        if (uiState.isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Security Score Card
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = stringResource(R.string.home_security_score),
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(Modifier.height(16.dp))
                    val score = uiState.latestScan?.overallScore ?: 0
                    ScoreGauge(score = if (uiState.latestScan != null) score else 0)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = if (uiState.latestScan == null)
                            stringResource(R.string.home_never_scanned)
                        else {
                            val formatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)
                            "${stringResource(R.string.home_last_scan)}: ${
                                uiState.latestScan!!.timestamp.atZone(java.time.ZoneId.systemDefault())
                                    .format(formatter)
                            }"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                }
            }

            // Scan-Zusammenfassung (wenn vorhanden)
            uiState.latestScan?.let { scan ->
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Letzte Scan-Zusammenfassung",
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(bottom = 12.dp)
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            ScanSummaryItem("Kritisch", scan.criticalCount, isCritical = true)
                            ScanSummaryItem("Hoch", scan.highCount)
                            ScanSummaryItem("Mittel", scan.mediumCount)
                            ScanSummaryItem("Niedrig", scan.lowCount)
                        }
                        if (scan.zeroDayCount > 0 || scan.activelyExploitedCount > 0) {
                            Spacer(Modifier.height(8.dp))
                            HorizontalDivider()
                            Spacer(Modifier.height(8.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (scan.zeroDayCount > 0) {
                                    AssistChip(
                                        onClick = { onNavigateToResults(scan.id) },
                                        label = { Text("${scan.zeroDayCount} Zero-Day") },
                                        leadingIcon = {
                                            Icon(Icons.Default.BugReport, null, Modifier.size(16.dp))
                                        }
                                    )
                                }
                                if (scan.activelyExploitedCount > 0) {
                                    AssistChip(
                                        onClick = { onNavigateToResults(scan.id) },
                                        label = { Text("${scan.activelyExploitedCount} aktiv ausgenutzt") },
                                        leadingIcon = {
                                            Icon(Icons.Default.Warning, null, Modifier.size(16.dp))
                                        }
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(12.dp))
                        OutlinedButton(
                            onClick = { onNavigateToResults(scan.id) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.List, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Ergebnisse anzeigen")
                        }
                    }
                }
            }

            // Scan starten
            Button(
                onClick = onNavigateToScan,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
            ) {
                Icon(Icons.Default.Shield, null, Modifier.size(22.dp))
                Spacer(Modifier.width(10.dp))
                Text(
                    "Vollständigen Scan starten",
                    style = MaterialTheme.typography.titleSmall
                )
            }
            Text(
                text = "Prüft alle 10 Module: System, Apps, Netzwerk, Gerätehärtung, Speicher, Zero-Days, Malware, Privacy, Passwort-Leaks & Play Integrity",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // Datenbank-Update
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.CloudDownload,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text("Vulnerability-Datenbank", style = MaterialTheme.typography.titleSmall)
                        Text(
                            "NVD (NIST), CISA KEV",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (uiState.isDbUpdating) {
                        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                    } else {
                        TextButton(onClick = viewModel::updateVulnerabilityDatabase) {
                            Text("Aktualisieren")
                        }
                    }
                }
                uiState.dbUpdateSuccess?.let { msg ->
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp).padding(bottom = 12.dp),
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = msg,
                            color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                uiState.dbUpdateError?.let { error ->
                    Text(
                        text = "Fehler: $error",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(horizontal = 16.dp).padding(bottom = 12.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanSummaryItem(label: String, count: Int, isCritical: Boolean = false) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.headlineMedium,
            color = if (isCritical && count > 0)
                MaterialTheme.colorScheme.error
            else
                MaterialTheme.colorScheme.onSurface
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
