## Version 2.2.0
- Rename: "AI Security Scanner" -> "Security Scanner" (package com.mobilesecurity.scanner)
- Neu: Modul 12 – BackdoorScanner (offene Ports, ADB-over-TCP, Remote-Access-Apps, SSH-Server, Reverse-Shell-Tools)
- Neu: Modul 13 – BreachCheckScanner (Datenleck-Hinweise, HaveIBeenPwned-Integration)
- Neu: Datenleck-Checker Screen (E-Mail & Passwort anonym prüfen via HIBP + Pwned Passwords API)
- Neu: BottomNav-Tab "Datenleck" (Security-Icon) für direkten Zugriff auf den Datenleck-Checker
- Fix: Alle Scan-Modul-Anzeigen von "X/11" auf "X/13" aktualisiert

## Version 2.1.0
- Neu: BottomNavigationBar (Dashboard / Verlauf / Einstellungen)
- Neu: About-Screen mit 3 Tabs (App-Info, Changelog, Lizenzen)
- Neu: JSON-Export für Scan-Ergebnisse (Settings & Results-Share-Button)
- Neu: Root-Erkennungs-Schritt im Onboarding (Schritt 2, nicht blockierend)
- Neu: Trend-Chip & Top-3-Befunde-Karte auf dem Dashboard
- Neu: Scanner-Sektion in Einstellungen (Auto-Remediation, Root-Tiefenscan)
- Fix: Windows-spezifischer JDK-Pfad aus gradle.properties entfernt (CI-Fix)

## Version 2.0.1
- Fix: URL-Encoding bei Detail-Navigation
- Fix: Duplikater ADB-Port im PrivacyHardwareScanner

## Version 2.0.0
- 11 Scanner-Module (inkl. KernelVisibilityScanner)
- Auto-Remediation Engine & Snapshot-Manager
- AppArmor-Profil (assets/security/)
- History mit Delta-Vergleich & Trend-Anzeige
- PDF- und TXT-Export

## Version 1.0.0
- Initiales Release
- 10 Scanner-Module: System, Apps, Netzwerk, Gerät, Speicher,
  Zero-Day, Malware, Hardware, Passwort-Leak, Play Integrity
- Biometrische App-Sperre
- NVD + CISA KEV Datenbank
