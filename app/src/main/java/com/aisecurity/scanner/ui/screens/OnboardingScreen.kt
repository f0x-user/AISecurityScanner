package com.aisecurity.scanner.ui.screens

import android.content.Intent
import android.provider.Settings
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aisecurity.scanner.R
import com.aisecurity.scanner.data.repository.SettingsRepository
import com.aisecurity.scanner.data.repository.VulnerabilityRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

data class DbDownloadState(
    val isRunning: Boolean = false,
    val isDone: Boolean = false,
    val nvdCount: Int = 0,
    val cisaCount: Int = 0,
    val cachedTotal: Int = 0,
    val error: String? = null
)

@HiltViewModel
class OnboardingViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
    private val vulnRepository: VulnerabilityRepository
) : ViewModel() {

    private val _dbState = MutableStateFlow(DbDownloadState())
    val dbState: StateFlow<DbDownloadState> = _dbState.asStateFlow()

    fun completeOnboarding() = viewModelScope.launch {
        settingsRepository.updateOnboardingCompleted(true)
    }

    fun startDatabaseDownload() {
        if (_dbState.value.isRunning || _dbState.value.isDone) return
        viewModelScope.launch {
            _dbState.update { it.copy(isRunning = true, error = null) }
            val result = runCatching { vulnRepository.updateAndCacheDatabase() }
            _dbState.update {
                if (result.isSuccess) {
                    val r = result.getOrThrow()
                    it.copy(isRunning = false, isDone = true, nvdCount = r.nvdCount, cisaCount = r.cisaCount, cachedTotal = r.cachedTotal)
                } else {
                    it.copy(isRunning = false, error = result.exceptionOrNull()?.message ?: "Unbekannter Fehler")
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OnboardingScreen(
    onOnboardingComplete: () -> Unit,
    viewModel: OnboardingViewModel = hiltViewModel()
) {
    var currentStep by remember { mutableIntStateOf(0) }
    val context = LocalContext.current
    val totalSteps = 5
    val dbState by viewModel.dbState.collectAsState()

    // DB-Download automatisch starten wenn Schritt 3 angezeigt wird
    LaunchedEffect(currentStep) {
        if (currentStep == 3) viewModel.startDatabaseDownload()
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            LinearProgressIndicator(
                progress = { (currentStep + 1) / totalSteps.toFloat() },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(24.dp))

            AnimatedContent(
                targetState = currentStep,
                transitionSpec = {
                    slideInHorizontally { it } togetherWith slideOutHorizontally { -it }
                },
                label = "onboarding_step"
            ) { step ->
                when (step) {
                    0 -> WelcomeStep()
                    1 -> RootCheckStep()
                    2 -> PermissionStep(
                        icon = Icons.Default.BarChart,
                        title = stringResource(R.string.onboarding_usage_stats_title),
                        reason = stringResource(R.string.onboarding_usage_stats_reason),
                        denyConsequence = stringResource(R.string.onboarding_usage_stats_deny),
                        onGrant = {
                            context.startActivity(
                                Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                                    .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                            )
                        }
                    )
                    3 -> DatabaseUpdateStep(dbState = dbState)
                    4 -> ReadyStep()
                }
            }

            Spacer(Modifier.height(24.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                if (currentStep > 0) {
                    OutlinedButton(onClick = { currentStep-- }) {
                        Icon(Icons.Default.ArrowBack, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Zurück")
                    }
                } else {
                    Spacer(Modifier.width(100.dp))
                }

                Button(
                    onClick = {
                        if (currentStep < totalSteps - 1) {
                            currentStep++
                        } else {
                            viewModel.completeOnboarding()
                            onOnboardingComplete()
                        }
                    }
                ) {
                    Text(
                        if (currentStep == totalSteps - 1)
                            stringResource(R.string.onboarding_btn_start_scan)
                        else
                            stringResource(R.string.onboarding_btn_next)
                    )
                    Spacer(Modifier.width(4.dp))
                    Icon(Icons.Default.ArrowForward, null, Modifier.size(18.dp))
                }
            }
        }
    }
}

@Composable
private fun RootCheckStep() {
    var isChecking by remember { mutableStateOf(true) }
    var isRooted by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        isRooted = withContext(Dispatchers.IO) { checkRootAccess() }
        isChecking = false
    }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Icon(
            if (isChecking) Icons.Default.Search
            else if (isRooted) Icons.Default.Warning
            else Icons.Default.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = if (isChecking) MaterialTheme.colorScheme.onSurfaceVariant
            else if (isRooted) MaterialTheme.colorScheme.error
            else MaterialTheme.colorScheme.primary
        )
        Text(
            text = "Root-Erkennung",
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center
        )
        if (isChecking) {
            CircularProgressIndicator()
            Text(
                "Prüfe Root-Zugang…",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            if (isRooted) Icons.Default.Warning else Icons.Default.CheckCircle,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                            tint = if (isRooted) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = if (isRooted) "Root-Zugang erkannt" else "Kein Root erkannt",
                            style = MaterialTheme.typography.titleSmall
                        )
                    }
                    HorizontalDivider()
                    Text(
                        text = if (isRooted)
                            "Das Gerät hat Root-Zugang. Scanner-Ergebnisse können abweichen, da Root erweiterte Systemzugriffe ermöglicht. Du kannst trotzdem fortfahren."
                        else
                            "Das Gerät hat keinen Root-Zugang. Der Scanner arbeitet im normalen Modus.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

private fun checkRootAccess(): Boolean {
    val paths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su")
    if (paths.any { File(it).exists() }) return true
    return runCatching {
        ProcessBuilder("which", "su").redirectErrorStream(true).start()
            .inputStream.bufferedReader().readText().trim().isNotEmpty()
    }.getOrElse { false }
}

@Composable
private fun WelcomeStep() {
    Column(
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
            stringResource(R.string.onboarding_welcome_title),
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center
        )
        Text(
            stringResource(R.string.onboarding_welcome_subtitle),
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Diese App analysiert:", style = MaterialTheme.typography.titleSmall)
                listOf(
                    "Android-Version & Sicherheitspatches",
                    "App-Berechtigungen & Risiken",
                    "Netzwerksicherheit & Verbindungen",
                    "Gerätekonfiguration & Sicherheitseinstellungen",
                    "Zero-Day-Schwachstellen (via NVD, CISA KEV)",
                    "Malware-Indikatoren"
                ).forEach { item ->
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.CheckCircle, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.primary)
                        Text(item, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        Text(
            "Diese App benötigt KEINE Root-Rechte und sendet keine sensiblen Daten.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun PermissionStep(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    reason: String,
    denyConsequence: String,
    onGrant: (() -> Unit)?,
    secondaryAction: (() -> Unit)? = null
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Icon(icon, null, Modifier.size(64.dp), tint = MaterialTheme.colorScheme.primary)
        Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Info, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.primary)
                    Text(reason, style = MaterialTheme.typography.bodyMedium)
                }
                HorizontalDivider()
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Block, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(
                        denyConsequence,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        if (onGrant != null) {
            Button(onClick = onGrant, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.OpenInNew, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.onboarding_btn_grant))
            }
        }
        if (secondaryAction != null) {
            OutlinedButton(onClick = secondaryAction, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Settings, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("In Android-Einstellungen öffnen")
            }
        }
        TextButton(onClick = {}) {
            Text(stringResource(R.string.onboarding_btn_skip))
        }
    }
}

@Composable
private fun DatabaseUpdateStep(dbState: DbDownloadState) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Icon(
            if (dbState.isDone) Icons.Default.CloudDone else Icons.Default.CloudDownload,
            null,
            Modifier.size(64.dp),
            tint = if (dbState.isDone) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            if (dbState.isDone) "Datenbank aktualisiert" else "Datenbank wird aktualisiert…",
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center
        )
        Text(
            "Lädt aktuelle Schwachstellendaten von NVD (NIST) und CISA KEV herunter.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (dbState.isRunning) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Text(
                "Verbinde mit NVD & CISA KEV…",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        if (dbState.isDone) {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.CheckCircle, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.primary)
                        Text("Erfolgreich gespeichert", style = MaterialTheme.typography.titleSmall)
                    }
                    HorizontalDivider()
                    DbStatRow(label = "NVD-CVEs heruntergeladen", value = "${dbState.nvdCount}")
                    DbStatRow(label = "CISA KEV Einträge", value = "${dbState.cisaCount}")
                    DbStatRow(label = "Gesamt im Cache", value = "${dbState.cachedTotal} CVEs")
                }
            }
        }

        dbState.error?.let { error ->
            ElevatedCard(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.elevatedCardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Warning, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.onErrorContainer)
                    Column {
                        Text(
                            "Download fehlgeschlagen – du kannst trotzdem fortfahren.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Text(
                            error,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DbStatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ReadyStep() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Icon(Icons.Default.CheckCircle, null, Modifier.size(80.dp), tint = MaterialTheme.colorScheme.primary)
        Text("Bereit für den ersten Scan!", style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
        Text(
            "Das Setup ist abgeschlossen. Starte jetzt deinen ersten Schnell-Scan.",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
