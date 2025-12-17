# Benötigte Dateien für Hetzner DNS Zone Tool

Diese Dokumentation listet alle Dateien auf, die die Anwendung benötigt oder erstellt.

## Speicherorte

Die Anwendung verwendet folgende Priorität für Dateispeicherorte:

1. **Umgebungsvariablen** (höchste Priorität)
2. **`/config`** (Docker-Container)
3. **`~/.hetzner-dns/`** (lokale Installation)

## Erforderliche Dateien

### 1. Konfigurationsdateien

#### `config.yaml`
- **Pfad (Docker):** `/config/config.yaml`
- **Pfad (lokal):** `~/.hetzner-dns/config.yaml`
- **Umgebungsvariable:** `CONFIG_PATH`
- **Beschreibung:** Hauptkonfigurationsdatei mit allen App-Einstellungen
- **Inhalt:**
  - API-Tokens (verschlüsselt)
  - Server-Einstellungen (Host, Port, Machine Name, Session Secret)
  - Security-Einstellungen (Brute-Force, IP-Whitelist/Blacklist, SMTP)
  - Audit-Log-Einstellungen
- **Erstellt bei:** Erstem Start (wenn nicht vorhanden)
- **Berechtigungen:** 600 (nur Besitzer lesen/schreiben)

#### `auth.yaml`
- **Pfad (Docker):** `/config/auth.yaml`
- **Pfad (lokal):** `~/.hetzner-dns/auth.yaml`
- **Umgebungsvariable:** `AUTH_FILE`
- **Beschreibung:** Authentifizierungsdaten (Benutzer, Passwörter, 2FA)
- **Inhalt:**
  - Benutzernamen und Passwort-Hashes (bcrypt)
  - 2FA-Secrets (verschlüsselt)
  - Backup-Codes (verschlüsselt)
- **Erstellt bei:** Initial Setup
- **Berechtigungen:** 600 (nur Besitzer lesen/schreiben)
- **Wichtig:** Diese Datei wird beim ersten Start NICHT automatisch erstellt - Initial Setup erforderlich!

### 2. Verschlüsselungsdateien

#### `.encryption_key`
- **Pfad (Docker):** `/config/.encryption_key`
- **Pfad (lokal):** `~/.hetzner-dns/.encryption_key`
- **Umgebungsvariable:** `ENCRYPTION_KEY_PATH`
- **Beschreibung:** Fernet-Verschlüsselungsschlüssel für sensible Daten
- **Inhalt:** Binärer Verschlüsselungsschlüssel (Fernet/AES-128)
- **Erstellt bei:** Erstem Zugriff auf Verschlüsselungsfunktionen
- **Berechtigungen:** 600 (nur Besitzer lesen/schreiben)
- **Wichtig:** Diese Datei muss gesichert werden! Ohne sie können verschlüsselte Daten nicht entschlüsselt werden.

### 3. Log-Dateien

#### `audit.log`
- **Pfad (Docker):** `/config/audit.log`
- **Pfad (lokal):** `~/.hetzner-dns/audit.log`
- **Umgebungsvariable:** `AUDIT_LOG_FILE`
- **Beschreibung:** Audit-Log mit allen wichtigen Aktionen
- **Inhalt:** JSON-Zeilen mit Timestamp, Aktion, Benutzer, IP, Erfolg/Fehler
- **Erstellt bei:** Erstem Audit-Log-Eintrag
- **Berechtigungen:** 600 (nur Besitzer lesen/schreiben)
- **Rotation:** Automatisch basierend auf Größe und Alter (konfigurierbar)

### 4. Weitere Konfigurationsdateien (optional)

#### `local_ips.yaml`
- **Pfad (Docker):** `/config/local_ips.yaml` (oder via `LOCAL_IP_STORAGE_PATH`)
- **Pfad (lokal):** `~/.hetzner-dns/local_ips.yaml` (oder via `LOCAL_IP_STORAGE_PATH`)
- **Umgebungsvariable:** `LOCAL_IP_STORAGE_PATH`
- **Beschreibung:** Speichert lokale IP-Adressen, Auto-Update-Einstellungen, TTLs und Kommentare für DNS-Records
- **Inhalt:** 
  - Lokale IP-Adressen pro Zone/Record
  - Auto-Update-Einstellungen (enabled/disabled)
  - TTL-Werte
  - Kommentare
  - Monitor-IP-Status
- **Erstellt bei:** Erster Konfiguration eines Records
- **Optional:** Ja (wird automatisch erstellt, wenn benötigt)

#### `auto_update.yaml`
- **Pfad (Docker):** `/config/auto_update.yaml` (oder via `AUTO_UPDATE_CONFIG_PATH`)
- **Pfad (lokal):** `~/.hetzner-dns/auto_update.yaml` (oder via `AUTO_UPDATE_CONFIG_PATH`)
- **Umgebungsvariable:** `AUTO_UPDATE_CONFIG_PATH`
- **Beschreibung:** Speichert Auto-Update-Einstellungen für DNS-Records
- **Inhalt:** Zone- und Record-spezifische Auto-Update-Konfigurationen
- **Erstellt bei:** Erster Auto-Update-Konfiguration
- **Optional:** Ja

## Dateistruktur (Docker)

```
/config/
├── config.yaml          # Hauptkonfiguration
├── auth.yaml            # Authentifizierung (wird beim Setup erstellt)
├── .encryption_key      # Verschlüsselungsschlüssel
├── audit.log            # Audit-Log
├── local_ips.yaml       # Lokale IPs, Auto-Update, TTLs (optional)
└── auto_update.yaml     # Auto-Update-Einstellungen (optional)
```

## Dateistruktur (lokal)

```
~/.hetzner-dns/
├── config.yaml          # Hauptkonfiguration
├── auth.yaml            # Authentifizierung (wird beim Setup erstellt)
├── .encryption_key      # Verschlüsselungsschlüssel
├── audit.log            # Audit-Log
├── local_ips.yaml       # Lokale IPs, Auto-Update, TTLs (optional)
└── auto_update.yaml     # Auto-Update-Einstellungen (optional)
```

## Wichtige Dateien für Backup

### Kritisch (müssen gesichert werden):
1. **`.encryption_key`** - Ohne diese Datei können verschlüsselte Daten nicht entschlüsselt werden
2. **`auth.yaml`** - Enthält alle Benutzer-Accounts
3. **`config.yaml`** - Enthält alle Konfigurationen und API-Tokens (verschlüsselt)

### Wichtig (sollten gesichert werden):
4. **`local_ips.yaml`** - Lokale IPs, Auto-Update-Einstellungen, TTLs (kann neu erstellt werden)
5. **`audit.log`** - Historische Logs (kann neu erstellt werden)
6. **`auto_update.yaml`** - Auto-Update-Konfigurationen (kann neu erstellt werden)

## Initial Setup

Beim ersten Start der Anwendung:

1. **`config.yaml`** wird automatisch erstellt (mit Standardwerten)
2. **`.encryption_key`** wird automatisch erstellt (bei erstem Zugriff)
3. **`auth.yaml`** wird NICHT automatisch erstellt - Initial Setup erforderlich!

Nach dem Initial Setup:
- Benutzer wird in `auth.yaml` erstellt
- Anwendung ist bereit zur Nutzung

## Umgebungsvariablen

Die folgenden Umgebungsvariablen können gesetzt werden, um die Pfade zu überschreiben:

```bash
CONFIG_PATH=/custom/path/config.yaml
AUTH_FILE=/custom/path/auth.yaml
ENCRYPTION_KEY_PATH=/custom/path/.encryption_key
AUDIT_LOG_FILE=/custom/path/audit.log
LOCAL_IP_STORAGE_PATH=/custom/path/local_ips.yaml
AUTO_UPDATE_CONFIG_PATH=/custom/path/auto_update.yaml
```

## Docker-Volumes

Für Docker-Deployments sollten folgende Volumes gemountet werden:

```yaml
volumes:
  - /host/path/config:/config
```

Oder mit benannten Volumes:

```yaml
volumes:
  - hetzner-dns-config:/config
```

## Dateiberechtigungen

Alle sensiblen Dateien sollten mit **600** (nur Besitzer) geschützt werden:
- `config.yaml`
- `auth.yaml`
- `.encryption_key`
- `audit.log`

Die Anwendung setzt diese Berechtigungen automatisch, wenn möglich.

## Fehlende Dateien

- **`config.yaml`**: Wird automatisch mit Standardwerten erstellt
- **`.encryption_key`**: Wird automatisch generiert, wenn nicht vorhanden
- **`auth.yaml`**: Muss durch Initial Setup erstellt werden (kein automatischer Standard-Admin mehr)
- **`audit.log`**: Wird automatisch erstellt, wenn erste Log-Einträge geschrieben werden
- **`local_ips.yaml`**: Wird automatisch erstellt, wenn erste Record-Konfiguration gespeichert wird
- **`auto_update.yaml`**: Wird nur erstellt, wenn Auto-Update konfiguriert wird

## Migration von lokaler zu Docker-Installation

1. Kopiere alle Dateien von `~/.hetzner-dns/` nach `/config/` im Container
2. Stelle sicher, dass Berechtigungen korrekt sind (600)
3. Starte den Container mit gemountetem `/config` Volume

## Sicherheitshinweise

1. **`.encryption_key`** niemals verlieren - ohne sie sind alle verschlüsselten Daten unbrauchbar
2. **`auth.yaml`** enthält Passwort-Hashes - sollte gesichert werden
3. **`config.yaml`** enthält verschlüsselte API-Tokens - sollte gesichert werden
4. Alle Dateien sollten nur für den Benutzer lesbar/schreibbar sein (600)
5. Bei Docker: Volume sollte nur für den Container zugänglich sein

