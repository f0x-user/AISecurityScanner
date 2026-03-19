package com.aisecurity.scanner.ui.screens

import android.content.Intent
import android.os.Build
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aisecurity.scanner.R
import com.aisecurity.scanner.ui.viewmodels.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateBack: () -> Unit,
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val lastDebugLogFile by viewModel.lastDebugLogFile.collectAsStateWithLifecycle()
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_back_button))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
        ) {
            // === Darstellung ===
            SettingsSectionHeader("Darstellung", Icons.Default.Palette)

            var themeMenuExpanded by remember { mutableStateOf(false) }
            SettingsItem(
                title = stringResource(R.string.settings_theme),
                subtitle = settings.theme,
                onClick = { themeMenuExpanded = true }
            ) {
                DropdownMenu(expanded = themeMenuExpanded, onDismissRequest = { themeMenuExpanded = false }) {
                    listOf("System", "Hell", "Dunkel", "AMOLED").forEach { theme ->
                        DropdownMenuItem(
                            text = { Text(theme) },
                            onClick = { viewModel.updateTheme(theme); themeMenuExpanded = false }
                        )
                    }
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                SettingsToggle(
                    title = stringResource(R.string.settings_dynamic_color),
                    subtitle = "Material You Farben (Android 12+)",
                    checked = settings.dynamicColor,
                    onCheckedChange = viewModel::updateDynamicColor
                )
            }

            var fontMenuExpanded by remember { mutableStateOf(false) }
            SettingsItem(
                title = "Schriftgröße",
                subtitle = settings.fontSize,
                onClick = { fontMenuExpanded = true }
            ) {
                DropdownMenu(expanded = fontMenuExpanded, onDismissRequest = { fontMenuExpanded = false }) {
                    listOf("Klein", "Standard", "Groß", "Sehr Groß").forEach { size ->
                        DropdownMenuItem(
                            text = { Text(size) },
                            onClick = { viewModel.updateFontSize(size); fontMenuExpanded = false }
                        )
                    }
                }
            }

            SettingsToggle(
                title = "Screenshots erlauben",
                subtitle = if (settings.screenshotAllowed)
                    "Screenshots sind erlaubt (Sicherheitshinweis: Scan-Daten können geteilt werden)"
                else
                    "Screenshots gesperrt (empfohlen – schützt sensible Scan-Daten)",
                checked = settings.screenshotAllowed,
                onCheckedChange = viewModel::updateScreenshotAllowed
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // === Datenbank ===
            SettingsSectionHeader("Datenbank", Icons.Default.Storage)

            SettingsToggle(
                title = stringResource(R.string.settings_auto_update),
                subtitle = "Schwachstellendaten automatisch aktualisieren",
                checked = settings.autoUpdateDb,
                onCheckedChange = viewModel::updateAutoUpdateDb
            )
            SettingsToggle(
                title = stringResource(R.string.settings_offline_mode),
                subtitle = "Nur lokale Prüfungen – keine Internet-Abfragen",
                checked = settings.offlineMode,
                onCheckedChange = viewModel::updateOfflineMode
            )

            var retentionMenuExpanded by remember { mutableStateOf(false) }
            SettingsItem(
                title = "Datenspeicherung",
                subtitle = "${settings.dataRetentionDays} Tage",
                onClick = { retentionMenuExpanded = true }
            ) {
                DropdownMenu(expanded = retentionMenuExpanded, onDismissRequest = { retentionMenuExpanded = false }) {
                    listOf(7, 30, 90, 365).forEach { days ->
                        DropdownMenuItem(
                            text = { Text("$days Tage") },
                            onClick = { viewModel.updateDataRetentionDays(days); retentionMenuExpanded = false }
                        )
                    }
                }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // === Datenschutz ===
            SettingsSectionHeader("Datenschutz", Icons.Default.PrivacyTip)

            SettingsToggle(
                title = stringResource(R.string.settings_local_only),
                subtitle = "Keine Daten werden das Gerät verlassen",
                checked = settings.localOnlyMode,
                onCheckedChange = viewModel::updateLocalOnlyMode
            )
            SettingsToggle(
                title = stringResource(R.string.settings_encrypt_local),
                subtitle = "Scan-Ergebnisse mit SQLCipher verschlüsseln",
                checked = settings.encryptLocalData,
                onCheckedChange = viewModel::updateEncryptLocalData
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // === Export ===
            SettingsSectionHeader("Export", Icons.Default.FileDownload)

            Button(
                onClick = { viewModel.exportLastScan(context) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp)
            ) {
                Icon(Icons.Default.FileDownload, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Letzten Scan exportieren")
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // === Debug-Logging ===
            SettingsSectionHeader("Entwickler & Debug", Icons.Default.Code)

            SettingsToggle(
                title = "Debug-Logging aktivieren",
                subtitle = if (settings.debugMode)
                    "Aktiv – alle Scan-Aktivitaeten werden protokolliert"
                else
                    "Deaktiviert – kein Performance-Overhead",
                checked = settings.debugMode,
                onCheckedChange = { viewModel.updateDebugMode(it) }
            )

            if (settings.debugMode) {
                // Hinweis-Card während Logging aktiv
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    colors = CardDefaults.elevatedCardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                Icons.Default.FiberManualRecord,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(10.dp)
                            )
                            Text(
                                "Logging laeuft",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSecondaryContainer
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                        val activeFile = viewModel.activeLogFile
                        Text(
                            text = if (activeFile != null)
                                "Datei: ${activeFile.name}\nGroesse: ${"%.1f".format(activeFile.length() / 1024f)} KB"
                            else
                                "Log-Datei wird beim naechsten Scan-Start erstellt",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "Starte einen Scan, um Daten zu erfassen. Deaktiviere dann den " +
                                    "Schalter, um die Datei zu sichern.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.7f)
                        )
                    }
                }
            }

            // Fertige Log-Datei anzeigen (nachdem Debug-Modus deaktiviert wurde)
            if (!settings.debugMode && lastDebugLogFile != null) {
                val logFile = lastDebugLogFile!!
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                            Text(
                                "Debug-Log fertig",
                                style = MaterialTheme.typography.titleSmall
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = logFile.name,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "Groesse: ${"%.1f".format(logFile.length() / 1024f)} KB  |  " +
                                    "Pfad: ${logFile.parentFile?.name ?: ""}/${logFile.name}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    runCatching {
                                        val uri = FileProvider.getUriForFile(
                                            context,
                                            "${context.packageName}.fileprovider",
                                            logFile
                                        )
                                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                            type = "text/plain"
                                            putExtra(Intent.EXTRA_STREAM, uri)
                                            putExtra(Intent.EXTRA_SUBJECT, "SecurityScanner Debug-Log")
                                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                        }
                                        context.startActivity(
                                            Intent.createChooser(shareIntent, "Debug-Log teilen")
                                        )
                                    }
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Share, null, Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Teilen")
                            }
                            OutlinedButton(
                                onClick = { viewModel.deleteAllDebugLogs() },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.outlinedButtonColors(
                                    contentColor = MaterialTheme.colorScheme.error
                                )
                            ) {
                                Icon(Icons.Default.Delete, null, Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Loeschen")
                            }
                        }
                    }
                }
            }

            // Alle vorhandenen Log-Dateien anzeigen
            val allLogFiles = remember(settings.debugMode, lastDebugLogFile) {
                viewModel.getAllDebugLogFiles()
            }
            if (allLogFiles.size > 1 || (allLogFiles.isNotEmpty() && lastDebugLogFile == null)) {
                ListItem(
                    headlineContent = { Text("Gespeicherte Log-Dateien") },
                    supportingContent = {
                        Text(
                            "${allLogFiles.size} Datei(en) | " +
                                    "${"%.1f".format(allLogFiles.sumOf { it.length() } / 1024f)} KB gesamt",
                            style = MaterialTheme.typography.bodySmall
                        )
                    },
                    trailingContent = {
                        TextButton(onClick = { viewModel.deleteAllDebugLogs() }) {
                            Text("Alle loeschen", color = MaterialTheme.colorScheme.error)
                        }
                    },
                    modifier = Modifier.padding(horizontal = 4.dp)
                )
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun SettingsSectionHeader(title: String, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
        Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsItem(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    trailingContent: @Composable () -> Unit = {}
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(subtitle, style = MaterialTheme.typography.bodySmall) },
        trailingContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary
                )
                Icon(Icons.Default.ChevronRight, null)
                trailingContent()
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(horizontal = 4.dp)
    )
}

@Composable
private fun SettingsToggle(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = {
            Text(subtitle, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        },
        trailingContent = {
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange
            )
        },
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp)
    )
}
