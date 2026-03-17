# Einstellungen – Technische Transparenz

## Anonyme Telemetrie

**Wird wirklich etwas gesammelt?** Nein.

Die Einstellung existiert als UI-Toggle, aber es ist **kein Telemetrie-Code implementiert**.
Es sind keine Bibliotheken wie Firebase Analytics, Mixpanel oder Amplitude eingebunden.
Das Ein-/Ausschalten des Toggles hat aktuell keinerlei Effekt.

**Was würde gesammelt, wenn implementiert?**
Geplant (aber noch nicht gebaut) wäre z. B. die anonymisierte Scan-Häufigkeit oder
welche Module Fehler erzeugen – keine personenbezogenen Daten, keine Gerätekennungen.

**Status:** UI-Only – es werden keine Daten gesendet.

---

## Offline-Modus

**Funktioniert es wirklich?** Ja (seit Fix).

Wenn aktiviert, überspringt `ZeroDayCorrelator` alle Netzwerkabrufe (NVD, CISA KEV, OSV.dev).
Stattdessen werden nur bereits im lokalen Room-Cache vorhandene CVE-Daten verwendet.

**Welche Netzwerkabrufe werden blockiert:**
- `GET https://services.nvd.nist.gov/rest/json/cves/2.0` (Android-CVEs)
- `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- `POST https://api.osv.dev/v1/query`

**Achtung:** Der manuelle "Datenbank aktualisieren"-Button im Home-Screen ist im
Offline-Modus deaktiviert, da er eine Netzwerkverbindung benötigt.

**Was passiert ohne gecachte Daten?**
Zero-Day-Korrelation (Modul 6) liefert keine Ergebnisse – alle anderen 7 Module
arbeiten rein lokal und werden nicht beeinflusst.

---

## Nur lokale Prüfungen

**Ist der Unterschied zu „Offline-Modus" relevant?**
Beide Einstellungen blockieren dieselben Netzwerkzugriffe. „Nur lokale Prüfungen" ist
semantisch als dauerhafte Datenschutzeinstellung gedacht, während „Offline-Modus" für
temporäre Nutzung ohne Internet gedacht ist. Technisch haben beide identische Auswirkungen.

**Was wird versendet, wenn die Funktion AUSGESCHALTET ist (normaler Betrieb):**

| Ziel | Anfrage | Inhalt |
|------|---------|--------|
| `services.nvd.nist.gov` | GET | Suchbegriff: `"android"`, keine Geräte-ID |
| `www.cisa.gov` | GET | Keine Parameter – öffentliche JSON-Datei |
| `api.osv.dev` | POST | JSON-Body: `{"package": {"name": "android", "ecosystem": "Android"}}` |

**Was niemals gesendet wird:**
- IMEI, Android-ID, SSAID oder andere Gerätekennungen
- Installierte App-Liste (wird nur lokal analysiert)
- Standort
- Benutzername oder Konten
- Inhalte von Dateien oder Nachrichten

Die Netzwerkabrufe holen ausschließlich **öffentliche Schwachstellendatenbanken** ab –
vergleichbar mit dem Aufruf einer Webseite. Kein Server erfährt dabei, welches Gerät die
Anfrage stellt (außer IP-Adresse wie bei jedem HTTP-Request).

---

## Weitere Einstellungen – Implementierungsstatus

| Einstellung | Gespeichert | Funktioniert | Anmerkung |
|-------------|:-----------:|:------------:|-----------|
| Farbschema | ✓ | ✓ | Vollständig implementiert |
| Dynamische Farben | ✓ | ✓ | Android 12+ |
| Scan-Tiefe | ✓ | ✓ | Bestimmt aktive Module |
| Datenspeicherung (Tage) | ✓ | ✓ | Alte Scans werden gelöscht |
| Offline-Modus | ✓ | ✓ | Blockiert Netzwerkzugriffe |
| Nur lokale Prüfungen | ✓ | ✓ | Identisch zu Offline-Modus |
| Anonyme Telemetrie | ✓ | ✗ | Kein Telemetrie-Code vorhanden |
| Automatischer Scan | ✓ | ✗ | WorkManager-Job fehlt noch |
| Scan beim Laden | ✓ | ✗ | Keine BatteryManager-Integration |
| Kritische Warnungen | ✓ | ✗ | Notification-Kanal fehlt noch |
| Wöchentlicher Bericht | ✓ | ✗ | Noch nicht implementiert |
| Neue CVE-Warnungen | ✓ | ✗ | Noch nicht implementiert |
| Auto-Update Datenbank | ✓ | ✗ | WorkManager-Job fehlt noch |
| Schriftgröße | ✓ | ✗ | Wird in UI nicht angewendet |
| Lokale Verschlüsselung | ✓ | ✓ | SQLCipher ist aktiv (immer) |
| Export-Format | ✓ | ✗ | Export-Funktion fehlt noch |
