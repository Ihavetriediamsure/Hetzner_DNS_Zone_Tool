# Docker Image auf GitHub hochladen - Anleitung

## Option 1: Automatisch mit GitHub Actions (Empfohlen)

Das Repository enthält bereits einen GitHub Actions Workflow (`.github/workflows/docker-publish.yml`), der automatisch das Docker-Image baut und zu GitHub Container Registry pusht.

### Voraussetzungen:
1. Repository auf GitHub erstellen
2. Code zu GitHub pushen
3. Workflow läuft automatisch bei jedem Push zu `main`/`master`

### Workflow aktivieren:
1. Gehe zu deinem GitHub Repository
2. Klicke auf "Actions" Tab
3. Der Workflow wird automatisch bei Push ausgeführt

### Image verwenden:
```bash
docker pull ghcr.io/<dein-username>/<repository-name>:latest
```

## Option 2: Manuell pushen

### Schritt 1: GitHub Personal Access Token erstellen

1. Gehe zu GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Klicke auf "Generate new token (classic)"
3. Wähle folgende Berechtigungen:
   - `write:packages` (für Push)
   - `read:packages` (für Pull)
4. Kopiere den Token (wird nur einmal angezeigt!)

### Schritt 2: Bei GitHub Container Registry anmelden

```bash
# Token als Umgebungsvariable setzen
export GITHUB_TOKEN="dein-token-hier"

# Bei ghcr.io anmelden
echo $GITHUB_TOKEN | docker login ghcr.io -u <dein-username> --password-stdin
```

### Schritt 3: Image bauen und taggen

```bash
cd "/home/admin/Applications/Hetzner DNS Managment/hetzner-dns-client"

# Image bauen
docker build -t ghcr.io/<dein-username>/hetzner-dns-zone-tool:latest .

# Optional: Weitere Tags hinzufügen
docker tag ghcr.io/<dein-username>/hetzner-dns-zone-tool:latest \
           ghcr.io/<dein-username>/hetzner-dns-zone-tool:v1.0.0
```

### Schritt 4: Image pushen

```bash
# Latest Tag pushen
docker push ghcr.io/<dein-username>/hetzner-dns-zone-tool:latest

# Version Tag pushen (optional)
docker push ghcr.io/<dein-username>/hetzner-dns-zone-tool:v1.0.0
```

### Schritt 5: Image öffentlich machen (optional)

Standardmäßig sind Images privat. Um sie öffentlich zu machen:

1. Gehe zu GitHub → Dein Repository → "Packages" (rechts)
2. Klicke auf das Package
3. Gehe zu "Package settings"
4. Scrolle nach unten zu "Danger Zone"
5. Klicke auf "Change visibility" → "Public"

## Option 3: Zu Docker Hub pushen

### Schritt 1: Bei Docker Hub anmelden

```bash
docker login
# Benutzername und Passwort eingeben
```

### Schritt 2: Image bauen und taggen

```bash
docker build -t <dein-dockerhub-username>/hetzner-dns-zone-tool:latest .
```

### Schritt 3: Image pushen

```bash
docker push <dein-dockerhub-username>/hetzner-dns-zone-tool:latest
```

## Image verwenden

### Von GitHub Container Registry:

```bash
# Öffentliches Image
docker pull ghcr.io/<dein-username>/hetzner-dns-zone-tool:latest

# Privates Image (benötigt Login)
echo $GITHUB_TOKEN | docker login ghcr.io -u <dein-username> --password-stdin
docker pull ghcr.io/<dein-username>/hetzner-dns-zone-tool:latest
```

### Von Docker Hub:

```bash
docker pull <dein-dockerhub-username>/hetzner-dns-zone-tool:latest
```

### Container starten:

```bash
docker run -d \
  -p 8000:8000 \
  -v /home/admin/Applications/Temp/config:/config \
  --name hetzner-dns-zone-tool \
  ghcr.io/<dein-username>/hetzner-dns-zone-tool:latest
```

## Troubleshooting

### "unauthorized: authentication required"
- Stelle sicher, dass du bei ghcr.io angemeldet bist
- Prüfe, ob dein Token die richtigen Berechtigungen hat
- Bei privaten Images: Stelle sicher, dass du Zugriff auf das Repository hast

### "denied: permission_denied"
- Prüfe, ob der Repository-Name korrekt ist
- Stelle sicher, dass du Owner/Collaborator des Repositories bist

### Image ist nicht öffentlich sichtbar
- Gehe zu Package Settings und ändere die Sichtbarkeit auf "Public"

