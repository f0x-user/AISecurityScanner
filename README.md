# AI Security Scanner

Eine produktionsreife Android Security Scanner App in Kotlin + Jetpack Compose, die Android-Geräte ohne Root-Rechte auf Sicherheitslücken analysiert.

---

## Architektur

```
Clean Architecture + MVVM + Repository Pattern

┌─────────────────────────────────────────────────┐
│                   UI Layer                      │
│  Screens (Compose) + ViewModels (Hilt)          │
├─────────────────────────────────────────────────┤
│                 Domain Layer                    │
│  7 Scanner-Module + SecurityScanManager         │
│  Domain Models (VulnerabilityEntry, ScanResult) │
├─────────────────────────────────────────────────┤
│                  Data Layer                     │
│  Repositories + Room DB + Retrofit APIs         │
│  NVD | CISA KEV | OSV.dev                       │
└─────────────────────────────────────────────────┘
```

## Tech Stack

| Bereich | Technologie |
|---------|-------------|
| Sprache | Kotlin 2.1 |
| UI | Jetpack Compose + Material 3 |
| Architektur | MVVM + Clean Architecture |
| DI | Hilt/Dagger2 |
| Async | Kotlin Coroutines + Flow |
| Netzwerk | Retrofit2 + OkHttp3 + Moshi |
| Datenbank | Room + SQLCipher |
| Security | Android Keystore + EncryptedSharedPreferences |
| Background | WorkManager |
| Min SDK | API 26 (Android 8.0) |
| Target SDK | API 35 (Android 15) |

---

## Projektstruktur

```
app/src/main/java/com/aisecurity/scanner/
├── AISecurityApp.kt               # Hilt Application + WorkManager
├── MainActivity.kt                # Einstiegspunkt + FLAG_SECURE
├── di/
│   ├── AppModule.kt               # DataStore
│   ├── DatabaseModule.kt          # Room + SQLCipher
│   ├── NetworkModule.kt           # Retrofit (NVD, CISA, OSV)
│   └── ScannerModule.kt           # Scanner-DI
├── data/
│   ├── db/
│   │   ├── AppDatabase.kt
│   │   ├── dao/                   # ScanResult, Vulnerability, CVECache, AppAudit
│   │   └── entities/              # Room-Entities
│   ├── network/
│   │   ├── NvdApiService.kt
│   │   ├── CisaApiService.kt
│   │   ├── OsvApiService.kt
│   │   └── dto/                   # Moshi-DTOs
│   ├── repository/
│   │   ├── ScanRepository.kt
│   │   ├── VulnerabilityRepository.kt
│   │   └── SettingsRepository.kt
│   ├── worker/
│   │   └── AutoScanWorker.kt      # WorkManager Auto-Scan
│   └── receiver/
│       └── BootReceiver.kt        # Boot-Empfänger
├── domain/
│   ├── model/                     # VulnerabilityEntry, ScanResult, AppAudit, etc.
│   └── scanner/
│       ├── SystemInfoScanner.kt   # Modul 1
│       ├── AppPermissionAuditor.kt# Modul 2
│       ├── NetworkSecurityScanner.kt # Modul 3
│       ├── DeviceHardeningChecker.kt # Modul 4
│       ├── StorageSecurityScanner.kt # Modul 5
│       ├── ZeroDayCorrelator.kt   # Modul 6 (NVD + CISA KEV)
│       ├── MalwareIndicatorScanner.kt # Modul 7
│       ├── SecurityScanManager.kt # Koordination aller Module
│       └── ScanForegroundService.kt
└── ui/
    ├── theme/                     # AppTheme, Color, Typography
    ├── components/                # SeverityBadge, ScoreGauge
    ├── screens/
    │   ├── HomeScreen.kt
    │   ├── ScanScreen.kt
    │   ├── ResultsScreen.kt
    │   ├── DetailScreen.kt
    │   ├── HistoryScreen.kt
    │   ├── SettingsScreen.kt
    │   └── OnboardingScreen.kt
    ├── viewmodels/                # HomeVM, ScanVM, ResultsVM, HistoryVM, SettingsVM
    └── navigation/
        ├── Screen.kt
        └── NavGraph.kt
```

---

## Setup-Anleitung

### Voraussetzungen
- Android Studio Ladybug (2024.2.1) oder neuer
- JDK 17
- Android SDK 35

### Schritte

1. **Repository klonen / öffnen**
   ```bash
   cd AISecurityScanner
   ```

2. **In Android Studio öffnen**
   - File → Open → Ordner `AISecurityScanner` auswählen
   - Gradle Sync abwarten

3. **Gradle Wrapper herunterladen**
   ```bash
   gradle wrapper --gradle-version 8.10.2
   ```

4. **Build**
   ```bash
   ./gradlew assembleDebug
   ```

5. **Release Build** (benötigt Keystore)
   ```bash
   ./gradlew assembleRelease
   ```

---

## Scanner-Module

| # | Modul | Prüft |
|---|-------|-------|
| 1 | SystemInfoScanner | Android-Version, Patch-Level, SELinux, Verschlüsselung, Verified Boot |
| 2 | AppPermissionAuditor | Berechtigungen, Sideloaded-Apps, Device-Admin, Accessibility |
| 3 | NetworkSecurityScanner | WLAN-Sicherheit, VPN, Proxy, offene Ports, DoH |
| 4 | DeviceHardeningChecker | Bildschirmsperre, USB-Debugging, Developer Options, Backup |
| 5 | StorageSecurityScanner | Geräteverschlüsselung, Benutzerzertifikate, externe Log-Dateien |
| 6 | ZeroDayCorrelator | NVD-CVEs, CISA KEV, CVSS v3.1 Scoring |
| 7 | MalwareIndicatorScanner | Bekannte Malware-Packages, Accessibility-Missbrauch |

---

## Externe Datenquellen

| Quelle | URL | Typ |
|--------|-----|-----|
| NVD (NIST) | services.nvd.nist.gov | REST API |
| CISA KEV | cisa.gov/...known_exploited_vulnerabilities.json | REST API |
| OSV.dev | api.osv.dev | REST API |

---

## Sicherheitsfeatures der App selbst

- **FLAG_SECURE** auf allen Screens (kein Screenshot/Screen-Recording)
- **SQLCipher** für verschlüsselte Room-Datenbank
- **TLS 1.2+** erzwungen, kein HTTP-Traffic (`network_security_config.xml`)
- **ProGuard/R8** Obfuskierung im Release-Build
- **allowBackup=false** – keine Cloud-Backups sensibler Daten
- **DataStore** für verschlüsselte Einstellungen

---

## Berechtigungen

| Berechtigung | Zweck |
|-------------|-------|
| INTERNET | CVE-Datenbank-Abfragen |
| ACCESS_NETWORK_STATE | Netzwerkstatus-Prüfung |
| ACCESS_WIFI_STATE | WLAN-Sicherheitsprotokoll |
| QUERY_ALL_PACKAGES | App-Berechtigungs-Audit |
| PACKAGE_USAGE_STATS | Hintergrundaktivitäts-Analyse (manuell zu gewähren) |
| POST_NOTIFICATIONS | Kritische Sicherheitswarnungen |
| FOREGROUND_SERVICE | Scan-Service |

---

## Qualitätsprüfliste

- [x] Kein hardcodierter Text (alle Strings in `strings.xml`)
- [x] Kein sensitiver Wert im Klartext
- [x] `network_security_config.xml` verhindert HTTP
- [x] Kein Memory Leak (keine Activity-Referenzen in ViewModels)
- [x] Alle Permissions erklärt im Onboarding
- [x] Graceful Degradation bei fehlenden Permissions
- [x] CVSS-Score nach Standard v3.1
- [x] Dark Mode + AMOLED auf allen Screens
- [x] TalkBack: Alle interaktiven Elemente haben `contentDescription`
- [x] FLAG_SECURE gegen Screenshot-Angriffe
