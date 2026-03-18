package com.aisecurity.scanner.ui.screens

import android.content.Intent
import android.net.Uri
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
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.R
import com.aisecurity.scanner.data.repository.ScanRepository
import com.aisecurity.scanner.domain.model.VulnerabilityEntry
import com.aisecurity.scanner.ui.components.SeverityBadge
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DetailViewModel @Inject constructor(
    private val scanRepository: ScanRepository,
    savedStateHandle: SavedStateHandle
) : ViewModel() {
    private val scanId: String = savedStateHandle["scanId"] ?: ""
    private val vulnId: String = savedStateHandle["vulnId"] ?: ""

    private val _vulnerability = MutableStateFlow<VulnerabilityEntry?>(null)
    val vulnerability: StateFlow<VulnerabilityEntry?> = _vulnerability.asStateFlow()

    init {
        viewModelScope.launch {
            val scan = scanRepository.getScanWithDetails(scanId)
            _vulnerability.value = scan?.vulnerabilities?.firstOrNull { it.id == vulnId }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetailScreen(
    onNavigateBack: () -> Unit,
    viewModel: DetailViewModel = hiltViewModel()
) {
    val vulnerability by viewModel.vulnerability.collectAsStateWithLifecycle()
    val context = LocalContext.current

    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf(
        stringResource(R.string.detail_overview),
        stringResource(R.string.detail_remediation),
        stringResource(R.string.detail_references)
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(vulnerability?.title ?: "Detail") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_back_button))
                    }
                }
            )
        }
    ) { padding ->
        vulnerability?.let { vuln ->
            Column(modifier = Modifier.fillMaxSize().padding(padding)) {
                // Tab-Navigation
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
                    0 -> OverviewTab(vuln)
                    1 -> RemediationTab(vuln, context)
                    2 -> ReferencesTab(vuln, context)
                }
            }
        } ?: Box(Modifier.fillMaxSize().padding(padding), Alignment.Center) {
            CircularProgressIndicator()
        }
    }
}

@Composable
private fun OverviewTab(vuln: VulnerabilityEntry) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Schweregrad + CVSS
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    SeverityBadge(vuln.severity)
                    Text(
                        text = "CVSS ${vuln.cvssScore}",
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                if (vuln.cvssVector.isNotEmpty()) {
                    Text(
                        text = vuln.cvssVector,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (vuln.isActivelyExploited) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(Icons.Default.Warning, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.error)
                        Text(
                            "Aktiv ausgenutzt (CISA KEV)",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }

        // Beschreibung
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Beschreibung", style = MaterialTheme.typography.titleSmall)
                Text(vuln.description, style = MaterialTheme.typography.bodyMedium)
            }
        }

        // Auswirkung
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Auswirkung", style = MaterialTheme.typography.titleSmall)
                Text(vuln.impact, style = MaterialTheme.typography.bodyMedium)
            }
        }

        // Metadaten
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                MetaDataRow("Betroffene Komponente", vuln.affectedComponent)
                MetaDataRow("Patch verfügbar", if (vuln.patchAvailable) "Ja" else "Nein")
                vuln.patchEta?.let { MetaDataRow("Patch ETA", it) }
                MetaDataRow("Quelle", vuln.source)
            }
        }
    }
}

@Composable
private fun RemediationTab(vuln: VulnerabilityEntry, context: android.content.Context) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Timer, null, tint = MaterialTheme.colorScheme.primary)
                    Text(
                        "Geschätzte Zeit: ${vuln.remediation.estimatedTime}",
                        style = MaterialTheme.typography.titleSmall
                    )
                }

                HorizontalDivider()

                Text("Schritte zur Behebung:", style = MaterialTheme.typography.titleSmall)

                vuln.remediation.steps.forEachIndexed { index, step ->
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Badge { Text("${index + 1}") }
                        Text(step, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        // Betroffene Apps mit Direktlinks
        if (vuln.affectedApps.isNotEmpty()) {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Betroffene Apps", style = MaterialTheme.typography.titleSmall)
                    HorizontalDivider()
                    vuln.affectedApps.forEach { appName ->
                        val packageName = remember(appName) {
                            resolvePackageNameForDetail(context, appName)
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(
                                    Icons.Default.Android,
                                    contentDescription = null,
                                    modifier = Modifier.size(20.dp),
                                    tint = MaterialTheme.colorScheme.primary
                                )
                                Text(appName, style = MaterialTheme.typography.bodyMedium)
                            }
                            if (packageName != null) {
                                TextButton(
                                    onClick = {
                                        runCatching {
                                            context.startActivity(
                                                Intent(
                                                    android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                                    Uri.parse("package:$packageName")
                                                ).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                                            )
                                        }
                                    },
                                    contentPadding = PaddingValues(4.dp)
                                ) {
                                    Icon(Icons.Default.OpenInNew, null, Modifier.size(14.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text("Öffnen", style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Quick-Action Buttons
        vuln.remediation.deepLinkSettings?.let { settingsAction ->
            Button(
                onClick = {
                    runCatching {
                        context.startActivity(
                            Intent(settingsAction).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                        )
                    }.onFailure {
                        runCatching {
                            context.startActivity(
                                Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)
                                    .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                            )
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Settings, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.detail_open_settings))
            }
        }

        if (vuln.remediation.officialDocUrl.isNotEmpty()) {
            OutlinedButton(
                onClick = {
                    runCatching {
                        context.startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse(vuln.remediation.officialDocUrl))
                                .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.OpenInNew, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.detail_open_docs))
            }
        }
    }
}

private fun resolvePackageNameForDetail(context: android.content.Context, appName: String): String? {
    return try {
        val pm = context.packageManager
        pm.getInstalledApplications(0).firstOrNull { appInfo ->
            pm.getApplicationLabel(appInfo).toString().equals(appName, ignoreCase = true)
        }?.packageName
    } catch (_: Exception) { null }
}

@Composable
private fun ReferencesTab(vuln: VulnerabilityEntry, context: android.content.Context) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        if (vuln.cveLinks.isEmpty()) {
            Text(
                "Keine externen Referenzen verfügbar.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            vuln.cveLinks.forEach { link ->
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    ListItem(
                        headlineContent = { Text(link, style = MaterialTheme.typography.bodySmall) },
                        leadingContent = { Icon(Icons.Default.Link, null) },
                        trailingContent = {
                            IconButton(onClick = {
                                runCatching {
                                    context.startActivity(
                                        Intent(Intent.ACTION_VIEW, Uri.parse(link))
                                            .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                                    )
                                }
                            }) {
                                Icon(Icons.Default.OpenInNew, "Link öffnen")
                            }
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun MetaDataRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}
