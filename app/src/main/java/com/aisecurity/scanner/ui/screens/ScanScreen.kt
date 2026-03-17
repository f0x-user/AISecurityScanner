package com.aisecurity.scanner.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.R
import com.aisecurity.scanner.domain.model.ScanStatus
import com.aisecurity.scanner.ui.viewmodels.ScanViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(
    onScanComplete: (String) -> Unit,
    onNavigateBack: () -> Unit,
    viewModel: ScanViewModel = hiltViewModel()
) {
    val progress by viewModel.progress.collectAsStateWithLifecycle()
    val scanResult by viewModel.scanResult.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()

    // Scan starten sobald Screen geladen
    LaunchedEffect(Unit) {
        viewModel.startScan()
    }

    // Navigation nach Abschluss
    LaunchedEffect(scanResult) {
        scanResult?.id?.let { onScanComplete(it) }
    }

    val rotationAnim = rememberInfiniteTransition(label = "spin")
    val rotation by rotationAnim.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1500, easing = LinearEasing)),
        label = "scan_rotation"
    )

    val logListState = rememberLazyListState()
    LaunchedEffect(progress.logLines.size) {
        if (progress.logLines.isNotEmpty()) {
            logListState.animateScrollToItem(progress.logLines.size - 1)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scan_title)) },
                navigationIcon = {
                    if (progress.status != ScanStatus.RUNNING) {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_back_button))
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Scan-Fortschritt
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(24.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        if (progress.status == ScanStatus.RUNNING) {
                            Icon(
                                Icons.Default.Shield,
                                contentDescription = null,
                                modifier = Modifier.size(40.dp).rotate(rotation),
                                tint = MaterialTheme.colorScheme.primary
                            )
                        } else {
                            Icon(
                                when (progress.status) {
                                    ScanStatus.COMPLETED -> Icons.Default.CheckCircle
                                    ScanStatus.FAILED -> Icons.Default.Error
                                    ScanStatus.CANCELLED -> Icons.Default.Cancel
                                    else -> Icons.Default.Shield
                                },
                                contentDescription = null,
                                modifier = Modifier.size(40.dp),
                                tint = when (progress.status) {
                                    ScanStatus.COMPLETED -> MaterialTheme.colorScheme.primary
                                    ScanStatus.FAILED -> MaterialTheme.colorScheme.error
                                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                                }
                            )
                        }
                        Column {
                            Text(
                                text = when (progress.status) {
                                    ScanStatus.COMPLETED -> stringResource(R.string.scan_complete)
                                    ScanStatus.FAILED -> "Scan fehlgeschlagen"
                                    ScanStatus.CANCELLED -> "Scan abgebrochen"
                                    else -> progress.currentModule.ifEmpty {
                                        stringResource(R.string.scan_initializing)
                                    }
                                },
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = "Vollständige Analyse – alle 8 Module",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    LinearProgressIndicator(
                        progress = { progress.progressPercent / 100f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics {
                                contentDescription = "Scan-Fortschritt: ${progress.progressPercent} Prozent"
                            }
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "${progress.progressPercent}%",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // Fehleranzeige
            error?.let { err ->
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(Icons.Default.Error, null, tint = MaterialTheme.colorScheme.error)
                        Text(err, color = MaterialTheme.colorScheme.onErrorContainer)
                    }
                }
            }

            // Abbrechen-Button
            if (progress.status == ScanStatus.RUNNING) {
                OutlinedButton(
                    onClick = viewModel::cancelScan,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Icon(Icons.Default.Stop, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.scan_cancel))
                }
            }

            // Live-Log
            if (progress.logLines.isNotEmpty()) {
                Text("Scan-Log", style = MaterialTheme.typography.titleSmall)
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                ) {
                    LazyColumn(
                        state = logListState,
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        items(progress.logLines) { line ->
                            Text(
                                text = line,
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace
                                ),
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}
