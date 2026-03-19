package com.aisecurity.scanner.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.R
import com.aisecurity.scanner.domain.model.ScanResult
import com.aisecurity.scanner.domain.model.Severity
import com.aisecurity.scanner.ui.components.SeverityBadge
import com.aisecurity.scanner.ui.viewmodels.HistoryViewModel
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(
    onNavigateBack: () -> Unit,
    onNavigateToResults: (String) -> Unit,
    viewModel: HistoryViewModel = hiltViewModel()
) {
    val scans by viewModel.scans.collectAsStateWithLifecycle()
    val deletingId by viewModel.deletingId.collectAsStateWithLifecycle()
    var deleteConfirmId by remember { mutableStateOf<String?>(null) }

    // Lösch-Dialog
    deleteConfirmId?.let { id ->
        AlertDialog(
            onDismissRequest = { deleteConfirmId = null },
            title = { Text("Scan löschen?") },
            text = { Text(stringResource(R.string.history_delete_confirm)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.deleteScan(id)
                    deleteConfirmId = null
                }) {
                    Text(stringResource(R.string.history_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirmId = null }) {
                    Text(stringResource(R.string.btn_cancel))
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.history_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_back_button))
                    }
                }
            )
        }
    ) { padding ->
        if (scans.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.History, null, Modifier.size(64.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(16.dp))
                    Text(stringResource(R.string.history_no_scans), style = MaterialTheme.typography.bodyLarge)
                }
            }
        } else {
            Column(modifier = Modifier.fillMaxSize().padding(padding)) {
                // Trend-Anzeige
                if (scans.size >= 2) {
                    val trend = viewModel.getScoreTrend(scans)
                    val trendIcon = when (trend) {
                        "Verbesserung" -> Icons.Default.TrendingUp
                        "Verschlechterung" -> Icons.Default.TrendingDown
                        else -> Icons.Default.TrendingFlat
                    }
                    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(trendIcon, null, tint = MaterialTheme.colorScheme.primary)
                            Text(
                                "Trend: $trend (${scans.first().overallScore} vs. ${scans[1].overallScore})",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                }

                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(scans, key = { it.id }) { scan ->
                        ScanHistoryCard(
                            scan = scan,
                            isDeleting = deletingId == scan.id,
                            onClick = { onNavigateToResults(scan.id) },
                            onDelete = { deleteConfirmId = scan.id }
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanHistoryCard(
    scan: ScanResult,
    isDeleting: Boolean,
    onClick: () -> Unit,
    onDelete: () -> Unit
) {
    val formatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
    val dateStr = scan.timestamp.atZone(java.time.ZoneId.systemDefault()).format(formatter)

    ElevatedCard(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Score
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.width(56.dp)
            ) {
                val scoreColor = when {
                    scan.overallScore >= 80 -> MaterialTheme.colorScheme.primary
                    scan.overallScore >= 50 -> MaterialTheme.colorScheme.tertiary
                    else -> MaterialTheme.colorScheme.error
                }
                Text(
                    text = scan.overallScore.toString(),
                    style = MaterialTheme.typography.headlineMedium,
                    color = scoreColor
                )
                Text(
                    text = "Score",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(Modifier.width(12.dp))
            VerticalDivider(modifier = Modifier.height(48.dp))
            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(dateStr, style = MaterialTheme.typography.titleSmall)
                Text(
                    text = "${scan.scanDepth} • ${scan.durationMs / 1000}s",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (scan.criticalCount > 0) {
                        SeverityBadge(Severity.CRITICAL, showLabel = false)
                        Text("${scan.criticalCount}", style = MaterialTheme.typography.labelSmall)
                    }
                    if (scan.highCount > 0) {
                        SeverityBadge(Severity.HIGH, showLabel = false)
                        Text("${scan.highCount}", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }

            if (isDeleting) {
                CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            } else {
                IconButton(onClick = onDelete) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = "Scan löschen",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}
