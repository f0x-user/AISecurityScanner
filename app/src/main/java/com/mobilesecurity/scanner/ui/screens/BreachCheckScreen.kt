package com.mobilesecurity.scanner.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mobilesecurity.scanner.domain.scanner.BreachCheckResult
import com.mobilesecurity.scanner.domain.scanner.BreachInfo
import com.mobilesecurity.scanner.domain.scanner.PasswordPwnedResult
import com.mobilesecurity.scanner.ui.viewmodels.BreachCheckViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BreachCheckScreen(
    onNavigateBack: () -> Unit,
    viewModel: BreachCheckViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("E-Mail pruefen", "Passwort pruefen")

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Datenleck-Checker") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Zurueck")
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
                        onClick = {
                            selectedTab = index
                            viewModel.clearResults()
                        },
                        text = { Text(title) }
                    )
                }
            }
            when (selectedTab) {
                0 -> EmailCheckTab(uiState, viewModel)
                1 -> PasswordCheckTab(uiState, viewModel)
            }
        }
    }
}

@Composable
private fun EmailCheckTab(
    uiState: com.mobilesecurity.scanner.ui.viewmodels.BreachCheckUiState,
    viewModel: BreachCheckViewModel
) {
    var email by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ElevatedCard {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Email, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(8.dp))
                        Text("E-Mail auf Datenlecks pruefen", style = MaterialTheme.typography.titleMedium)
                    }
                    Text(
                        "Prueft ob deine E-Mail-Adresse in bekannten Datenlecks aufgetaucht ist. " +
                            "Daten werden direkt an HaveIBeenPwned.com gesendet.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        item {
            OutlinedTextField(
                value = email,
                onValueChange = { email = it },
                label = { Text("E-Mail-Adresse") },
                leadingIcon = { Icon(Icons.Default.Email, null) },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Email,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = {
                    if (email.isNotBlank()) viewModel.checkEmail(email)
                }),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }
        item {
            Button(
                onClick = { viewModel.checkEmail(email) },
                enabled = email.isNotBlank() && !uiState.isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (uiState.isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.width(8.dp))
                }
                Text("Auf Datenlecks pruefen")
            }
        }
        item { EmailResultSection(uiState.emailResult) }
    }
}

@Composable
private fun EmailResultSection(result: BreachCheckResult?) {
    when (result) {
        is BreachCheckResult.NotFound -> {
            ElevatedCard {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(Icons.Default.CheckCircle, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                    Column {
                        Text("Kein Datenleck gefunden!", style = MaterialTheme.typography.titleSmall)
                        Text(
                            "${result.email} wurde in keinem bekannten Datenleck gefunden.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
        is BreachCheckResult.Found -> {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ElevatedCard {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(32.dp))
                        Column {
                            Text(
                                "${result.breaches.size} Datenleck(s) gefunden!",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.error
                            )
                            Text(
                                "${result.email} ist in ${result.breaches.size} bekannten Datenpannen enthalten.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                result.breaches.forEach { breach -> BreachCard(breach) }
            }
        }
        is BreachCheckResult.ApiKeyRequired -> {
            ElevatedCard {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Default.Key, null, tint = MaterialTheme.colorScheme.secondary)
                        Text("API-Key erforderlich", style = MaterialTheme.typography.titleSmall)
                    }
                    Text(
                        "Fuer die E-Mail-Pruefung wird ein HIBP API-Key benoetigt. " +
                            "Kostenlos erhaeltlich unter haveibeenpwned.com/API/Key",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        is BreachCheckResult.RateLimited -> {
            ElevatedCard {
                Row(modifier = Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Timer, null, tint = MaterialTheme.colorScheme.secondary)
                    Text("Rate-Limit erreicht. Bitte kurz warten.", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        is BreachCheckResult.Error -> {
            ElevatedCard {
                Row(modifier = Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Error, null, tint = MaterialTheme.colorScheme.error)
                    Column {
                        Text("Fehler", style = MaterialTheme.typography.titleSmall)
                        Text(result.message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
        null -> {}
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun BreachCard(breach: BreachInfo) {
    ElevatedCard {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                Text(breach.name, style = MaterialTheme.typography.titleSmall)
                if (breach.isVerified) {
                    AssistChip(onClick = {}, label = { Text("Verifiziert", style = MaterialTheme.typography.labelSmall) })
                }
            }
            if (breach.domain.isNotEmpty()) {
                Text("Domain: ${breach.domain}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text("Datum: ${breach.breachDate}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Betroffene Datensaetze: ${"%,d".format(breach.pwnCount)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (breach.dataClasses.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(top = 4.dp)) {
                    breach.dataClasses.take(6).forEach { dataClass ->
                        SuggestionChip(onClick = {}, label = { Text(dataClass, style = MaterialTheme.typography.labelSmall) })
                    }
                    if (breach.dataClasses.size > 6) {
                        SuggestionChip(onClick = {}, label = { Text("+${breach.dataClasses.size - 6} weitere", style = MaterialTheme.typography.labelSmall) })
                    }
                }
            }
        }
    }
}

@Composable
private fun PasswordCheckTab(
    uiState: com.mobilesecurity.scanner.ui.viewmodels.BreachCheckUiState,
    viewModel: BreachCheckViewModel
) {
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ElevatedCard {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(8.dp))
                        Text("Passwort-Sicherheitspruefung", style = MaterialTheme.typography.titleMedium)
                    }
                    Text(
                        "Prueft ob dein Passwort in bekannten Datenlecks aufgetaucht ist. " +
                            "Dein Passwort wird NIEMALS ubertragen. Es wird nur ein anonymisierter " +
                            "Hash-Praefix gesendet (k-Anonymity).",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    ElevatedCard(colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
                        Row(modifier = Modifier.padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(Icons.Default.Shield, null, tint = MaterialTheme.colorScheme.onPrimaryContainer, modifier = Modifier.size(16.dp))
                            Text(
                                "Datenschutz garantiert: Nur die ersten 5 Zeichen des SHA-1-Hashes " +
                                    "werden an pwned passwords API gesendet.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                    }
                }
            }
        }
        item {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Passwort eingeben") },
                leadingIcon = { Icon(Icons.Default.Lock, null) },
                trailingIcon = {
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility, "Passwort anzeigen")
                    }
                },
                visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = {
                    if (password.isNotBlank()) viewModel.checkPassword(password)
                }),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }
        item {
            Button(
                onClick = { viewModel.checkPassword(password) },
                enabled = password.isNotBlank() && !uiState.isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (uiState.isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.width(8.dp))
                }
                Text("Passwort anonym pruefen")
            }
        }
        item { PasswordResultSection(uiState.passwordResult) }
    }
}

@Composable
private fun PasswordResultSection(result: PasswordPwnedResult?) {
    when (result) {
        is PasswordPwnedResult.Safe -> {
            ElevatedCard {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(Icons.Default.CheckCircle, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                    Column {
                        Text("Passwort nicht kompromittiert!", style = MaterialTheme.typography.titleSmall)
                        Text(
                            "Dieses Passwort wurde in keinem bekannten Datenleck gefunden.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
        is PasswordPwnedResult.Pwned -> {
            ElevatedCard {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(32.dp))
                        Column {
                            Text(
                                "Passwort kompromittiert!",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.error
                            )
                            Text(
                                "Dieses Passwort wurde ${"%,d".format(result.count)} Mal in Datenlecks gefunden.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    Text(
                        "Empfehlung: Aendere dieses Passwort sofort bei allen Diensten " +
                            "wo es verwendet wird. Nutze einen Passwort-Manager fuer " +
                            "einzigartige, starke Passwoerter.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        is PasswordPwnedResult.Error -> {
            ElevatedCard {
                Row(modifier = Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Error, null, tint = MaterialTheme.colorScheme.error)
                    Column {
                        Text("Fehler", style = MaterialTheme.typography.titleSmall)
                        Text(result.message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
        null -> {}
    }
}
