package com.mobilesecurity.scanner.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mobilesecurity.scanner.domain.integrity.IntegrityChange
import com.mobilesecurity.scanner.domain.integrity.IntegrityState
import com.mobilesecurity.scanner.ui.components.SeverityBadge
import com.mobilesecurity.scanner.ui.viewmodels.IntegrityViewModel
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IntegrityScreen(
    onNavigateBack: () -> Unit,
    viewModel: IntegrityViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Integrity (Ist / Soll)") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (uiState.isLoading) {
            Box(
                Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) { CircularProgressIndicator() }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            ExplanationCard()

            val diff = uiState.diff
            if (!uiState.hasBaseline) {
                NoBaselineCard(onCapture = viewModel::captureBaseline)
            } else if (diff != null) {
                BaselineInfoCard(
                    capturedAt = diff.baselineCapturedAt,
                    justCaptured = uiState.justCaptured
                )

                if (diff.changes.isEmpty()) {
                    CleanStateCard()
                } else {
                    Text(
                        "${diff.changes.size} deviation(s) from baseline",
                        style = MaterialTheme.typography.titleMedium
                    )
                    diff.changes
                        .sortedBy { it.severity.order }
                        .forEach { ChangeCard(it) }
                }

                CurrentStateCard(diff.current)

                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton(
                        onClick = viewModel::refresh,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Refresh, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Re-compare")
                    }
                    Button(
                        onClick = viewModel::captureBaseline,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Fingerprint, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Update baseline")
                    }
                }
            }
        }
    }
}

@Composable
private fun ExplanationCard() {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("What this does", style = MaterialTheme.typography.titleSmall)
            Text(
                "A baseline is a trusted snapshot of your device's security state: patch level, " +
                    "verified boot, bootloader lock, root status, device admins, accessibility services, " +
                    "notification listeners and installed apps. Every scan compares the current state (Ist) " +
                    "against this baseline (Soll) and flags any change – this is how an unknown compromise " +
                    "is caught even when the malware itself cannot be named.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Capture the baseline while you believe the device is clean, and re-capture it after " +
                    "every legitimate system update.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun NoBaselineCard(onCapture: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(
            Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                Icons.Default.Fingerprint,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Text("No baseline yet", style = MaterialTheme.typography.titleMedium)
            Text(
                "Capture a baseline now to enable drift detection.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
            Button(onClick = onCapture) {
                Icon(Icons.Default.Fingerprint, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Capture baseline")
            }
        }
    }
}

@Composable
private fun BaselineInfoCard(capturedAt: Long?, justCaptured: Boolean) {
    val df = remember { DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT) }
    ElevatedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Fingerprint, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(
                    if (justCaptured) "Baseline updated" else "Baseline active",
                    style = MaterialTheme.typography.titleSmall
                )
                Text(
                    "Captured: " + (capturedAt?.let { df.format(Date(it)) } ?: "unknown"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun CleanStateCard() {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.CheckCircle, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(12.dp))
            Text(
                "No deviations. The current state matches the trusted baseline.",
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun ChangeCard(change: IntegrityChange) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityBadge(change.severity)
                Spacer(Modifier.width(8.dp))
                Text(change.category, style = MaterialTheme.typography.titleSmall)
            }
            Text(change.detail, style = MaterialTheme.typography.bodyMedium)
            Text(
                change.advice,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun CurrentStateCard(state: IntegrityState) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Current state (Ist)", style = MaterialTheme.typography.titleSmall)
            StateRow("Android", "${state.androidRelease} (API ${state.sdkInt})")
            StateRow("Security patch", state.securityPatch)
            StateRow("Verified boot", state.verifiedBootState)
            StateRow("Bootloader locked", state.bootloaderLocked)
            StateRow("Root indicators", if (state.rooted) "present" else "none")
            StateRow("Device admins", state.deviceAdmins.size.toString())
            StateRow("Accessibility services", state.accessibilityServices.size.toString())
            StateRow("Notification listeners", state.notificationListeners.size.toString())
            StateRow("Installed apps", state.installedPackages.size.toString())
        }
    }
}

@Composable
private fun StateRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}
