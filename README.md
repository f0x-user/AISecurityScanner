# SecurityScanner

Eine produktionsreife Android-Sicherheitsscanner-App in Kotlin + Jetpack Compose, die Android-Geräte ohne Root-Rechte auf Sicherheitslücken analysiert.

---

## Architektur

```
Clean Architecture + MVVM + Repository Pattern

┌─────────────────────────────────────────────────┐
│                   UI Layer                      │
│  Screens (Compose) + ViewModels (Hilt)          │
├─────────────────────────────────────────────────┤
│                 Domain Layer                    │
│  8 Scanner-Module + SecurityScanManager         │
│  Domain Models (VulnerabilityEntry, ScanResult) │
├─────────────────────────────────────────────────┤
│                  Data Layer                     │
│  Repositories + Room DB + Retrofit APIs         │
│  NVD | CISA KEV | OSV.dev                       │
└─────────────────────────────────────────────────┘
```

## Tech Stack

| Bereich        | Technologie                              |
|----------------|------------------------------------------|
| Sprache        | Kotlin 2.1                               |
| UI             | Jetpack Compose + Material 3             |
| Architektur    | MVVM + Clean Architecture                |
| DI             | Hilt/Dagger2                             |
| Async          | Kotlin Coroutines + Flow                 |
| Netzwerk       | Retrofit2 + OkHttp3 + Moshi              |
| Datenbank      | Room + SQLCipher                         |
| Security       | Android Keystore + DataStore             |
| Background     | WorkManager                              |
| Min SDK        | API 26 (Android 8.0)                     |
| Target SDK     | API 35 (Android 15)                      |

---

## Scanner-Module

| # | Modul                   | Prüft                                                       |
|---|-------------------------|-------------------------------------------------------------|
| 1 | SystemInfoScanner       | Android-Version, Patch-Level, SELinux, Verified Boot        |
| 2 | AppPermissionAuditor    | Berechtigungen, Sideloaded-Apps, Device-Admin               |
| 3 | NetworkSecurityScanner  | WLAN-Sicherheit (SSID, WPA3/WPA2/offen), VPN, offene Ports  |
| 4 | DeviceHardeningChecker  | Bildschirmsperre, USB-Debugging, Developer Options          |
| 5 | StorageSecurityScanner  | Geräteverschlüsselung, Benutzerzertifikate                  |
| 6 | ZeroDayCorrelator       | NVD-CVEs, CISA KEV, CVSS v3.1, Patch-Level-Abgleich        |
| 7 | MalwareIndicatorScanner | Bekannte Malware-Packages, Stalkerware, Accessibility-Missbrauch |
| 8 | PrivacyHardwareScanner  | Root-Indikatoren, Frida, Boot-Receiver, Kamera/Mikrofon-Zugriff |

---

## Projektstruktur

```
app/src/main/java/com/aisecurity/scanner/
├── AISecurityApp.kt               # Hilt Application + WorkManager
├── MainActivity.kt                # Einstiegspunkt + FLAG_SECURE (reaktiv)
├── di/
│   ├── AppModule.kt               # DataStore
│   ├── DatabaseModule.kt          # Room + SQLCipher
│   ├── NetworkModule.kt           # Retrofit (NVD, CISA, OSV)
│   └── ScannerModule.kt           # Scanner-DI
├── data/
│   ├── db/                        # Room-Datenbank, DAOs, Entities
│   ├── network/                   # NVD, CISA, OSV API Services + DTOs
│   ├── repository/                # ScanRepository, VulnerabilityRepository, SettingsRepository
│   ├── worker/                    # AutoScanWorker (WorkManager)
│   └── receiver/                  # BootReceiver
├── domain/
│   ├── model/                     # VulnerabilityEntry, ScanResult, AppAudit, etc.
│   └── scanner/                   # 8 Scanner-Module + SecurityScanManager
└── ui/
    ├── theme/                     # AppTheme, Color, Typography (Dark/AMOLED)
    ├── components/                # SeverityBadge, ScoreGauge
    ├── screens/                   # Home, Scan, Results, Detail, History, Settings, Onboarding
    ├── viewmodels/                # HomeVM, ScanVM, ResultsVM, HistoryVM, SettingsVM
    └── navigation/                # AppNavGraph, Screen
```

---

## Setup

### Voraussetzungen
- Android Studio Ladybug (2024.2.1) oder neuer
- JDK 17
- Android SDK 35

### Build

```bash
# Debug
./gradlew assembleDebug

# Release (benötigt Keystore-Konfiguration)
./gradlew assembleRelease
```

---

## Externe Datenquellen

| Quelle     | Typ      | Zweck                                    |
|------------|----------|------------------------------------------|
| NVD (NIST) | REST API | Android-CVEs mit CVSS v3.1 Scoring       |
| CISA KEV   | REST API | Aktiv ausgenutzte Schwachstellen         |
| OSV.dev    | REST API | Open-Source Vulnerability Database       |

---

## Sicherheitsfeatures der App

- **FLAG_SECURE** – reaktiv konfigurierbar; verhindert Screenshots/Screen-Recording
- **SQLCipher** – verschlüsselte Room-Datenbank
- **TLS 1.2+** erzwungen, kein HTTP (`network_security_config.xml`)
- **ProGuard/R8** Obfuskierung im Release-Build
- **allowBackup=false** – keine Cloud-Backups
- **Keine Telemetrie** – alle Daten bleiben auf dem Gerät

---

## Score-Berechnung

Der Sicherheits-Score (0–100) verwendet **Diminishing Returns**:
- Jede Schwachstelle reduziert den Score um einen Prozentsatz des *verbleibenden* Scores
- Dadurch bleibt der Score bei vielen mittleren Befunden realistisch (z. B. 17× MITTEL ≈ 50/100)
- Der Score aktualisiert sich automatisch nach jedem Scan auf dem Dashboard

| Schweregrad | Basis-Reduktion | mit aktiver Ausnutzung |
|-------------|-----------------|------------------------|
| KRITISCH    | 11 %            | 14 %                   |
| HOCH        | 6 %             | 8 %                    |
| MITTEL      | 4 %             | 4 %                    |
| NIEDRIG     | 1,5 %           | 1,5 %                  |

---

## Release-Signing

Für signierte Release-APKs über GitHub Actions müssen folgende
Repository-Secrets gesetzt sein (Settings → Secrets and variables → Actions):

| Secret | Inhalt |
|---|---|
| `KEYSTORE_BASE64` | Base64-kodierter Keystore: `base64 -w 0 keystore.jks` |
| `KEYSTORE_PASSWORD` | Passwort des Keystores |
| `KEY_ALIAS` | Alias des Signing-Keys |
| `KEY_PASSWORD` | Passwort des Keys |

Ohne diese Secrets baut der Workflow trotzdem durch, signiert die APK
aber mit dem Debug-Keystore (nicht für Distribution geeignet).

## Berechtigungen

| Berechtigung         | Zweck                                        |
|----------------------|----------------------------------------------|
| INTERNET             | CVE-Datenbank-Abfragen                       |
| ACCESS_NETWORK_STATE | Netzwerkstatus-Prüfung                       |
| ACCESS_WIFI_STATE    | WLAN-Sicherheitsprotokoll (SSID, WPA3 etc.)  |
| QUERY_ALL_PACKAGES   | App-Berechtigungs-Audit                      |
| PACKAGE_USAGE_STATS  | Hintergrundaktivitäts-Analyse                |
| POST_NOTIFICATIONS   | Kritische Sicherheitswarnungen               |
| FOREGROUND_SERVICE   | Scan-Service                                 |
