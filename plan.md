# Aufgabenplan – v2.2.0
## Status: IN ARBEIT  |  Zuletzt: 2026-03-31

---

## Aufgabe 1: AI-Referenzen entfernen
- [x] 1a. bulk-sed: com.aisecurity.scanner -> com.mobilesecurity.scanner in allen .kt-Dateien
- [x] 1b. Verzeichnis kopieren + umbenennen (aisecurity -> mobilesecurity)
- [x] 1c. AISecurityApp.kt -> SecurityApp.kt + Klasse umbenennen
- [x] 1d. AndroidManifest.xml: .AISecurityApp -> .SecurityApp, Theme-Ref
- [x] 1e. build.gradle.kts: namespace + applicationId ändern
- [x] 1f. themes.xml: Theme.AISecurityScanner -> Theme.SecurityScanner
- [x] 1g. strings.xml: "AI Security Scanner" -> "Security Scanner"
- [x] 1h. AboutScreen.kt: Text "AI Security Scanner" -> "Security Scanner"
- [x] 1i. Altes Verzeichnis (aisecurity) löschen

## Aufgabe 2: Backdoor/Open-Port/Remote-Access Scanner (Modul 12)
- [ ] 2a. BackdoorScanner.kt erstellen in domain/scanner/
- [ ] 2b. SecurityScanManager.kt Modul 12 registrieren
- [ ] 2c. ScannerModule.kt (Hilt) aktualisieren

## Aufgabe 3: Datenleck-Check / HaveIBeenPwned (neuer Screen + Modul 13)
- [ ] 3a. BreachCheckApiService.kt in data/network/
- [ ] 3b. DTOs fuer HIBP Response
- [ ] 3c. BreachCheckScanner.kt in domain/scanner/
- [ ] 3d. BreachCheckScreen.kt in ui/screens/
- [ ] 3e. BreachCheckViewModel.kt in ui/viewmodels/
- [ ] 3f. Navigation: Screen.BreachCheck + Route in NavGraph
- [ ] 3g. Hilt NetworkModule aktualisieren
- [ ] 3h. SecurityScanManager: Modul 13 registrieren

## Aufgabe 4: Build + Fehlerkorrektur
- [ ] 4a. ./gradlew assembleDebug -> Fehler beheben bis gruen
- [ ] 4b. ./gradlew lint -> Fehler beheben

## Aufgabe 5: Version + Changelog + README
- [ ] 5a. build.gradle.kts: versionCode 5, versionName "2.2.0"
- [ ] 5b. CHANGELOG.md aktualisieren
- [ ] 5c. README.md aktualisieren

## Aufgabe 6: Commit + Push + GitHub Release
- [ ] 6a. git add + commit
- [ ] 6b. git push origin master
- [ ] 6c. gh release create v2.2.0 mit Release Notes

---
## Wiederaufnahme: git log --oneline -5 + git status, dann plan.md einlesen
