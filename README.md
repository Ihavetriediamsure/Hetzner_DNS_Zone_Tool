# Hetzner DNS Zone Tool (Unofficial)

> **⚠️ Unofficial Project**  
> This is an **unofficial, community-driven project** and is **not affiliated with, endorsed by, or supported by Hetzner Online GmbH**.

A source-available web interface for managing **A and AAAA DNS records** in Hetzner DNS zones,
with automated public IP updates, advanced security features, and integrated monitoring.

This tool is designed for self-hosted environments, homelabs, and infrastructure operators
who need reliable DNS IP automation without relying on external SaaS services.

> **Scope note:**  
> This project focuses explicitly on **A/AAAA record automation**.  
> Other DNS record types such as **CNAME, MX, TXT, and NS are not supported**.

---

## Features

### 🌐 DNS Zone & Record Management
- DNS zone selection and overview
- Record Set (RRSet) management for:
  - **A records (IPv4)**
  - **AAAA records (IPv6)**
- Multiple IP addresses per record set (where supported)
- IP address handling:
  - Manual IP assignment
  - Automatic public IP detection
  - Local/internal IP mapping (Monitor IP) with configurable port for reachability checks
  - IP validation and consistency checks

---

### 🔄 Automated DNS Updates
- Automatic DNS updates based on:
  - Public IP address changes
  - Local IP reachability
  - Configurable polling intervals (default: 60 seconds)
- Intelligent update logic:
  - DNS updates only on actual IP changes
  - Support for multiple Hetzner API tokens
  - Error handling with retry and backoff mechanisms
- Local IP monitoring (Monitor IP):
  - Continuous reachability checks on configurable ports (default: 80)
  - Support for custom ports (e.g., 22 for SSH, 8000 for web services)
  - Automatic DNS updates when reachability changes
  - TCP connection-based health checks

---

### 🔐 Security & Authentication
- Multi-factor authentication (2FA):
  - TOTP-based authentication (Google Authenticator, Authy, etc.)
  - QR code provisioning
  - Encrypted backup codes for emergency access
  - Separate brute-force protection for:
    - Login
    - 2FA verification
    - Backup codes
- Advanced security mechanisms:
  - Password authentication using bcrypt
  - Configurable brute-force protection:
    - Independent counters per authentication stage
    - Automatic temporary account lockouts
  - IP allowlist / blocklist support (CIDR-based)
  - Encrypted storage of sensitive data:
    - Hetzner API tokens
    - 2FA secrets
    - Backup codes
  - Encryption using Fernet (AES-128)

---

### 📊 Monitoring & Logging
- Audit logging for:
  - Authentication attempts (successful and failed)
  - DNS record changes
  - Configuration changes
  - Security-related events
- Automatic log rotation
- Health check endpoint for container orchestration and monitoring
- SMTP notifications:
  - Event-based email alerts
  - Configurable SMTP settings
  - Customizable host or instance identifiers

---

### ⚙️ Configuration & Administration
- API token management:
  - Support for multiple Hetzner API tokens
  - Named tokens for easier identification
  - Encrypted token storage
  - Token validation and test functionality
  - Support for legacy and current Hetzner APIs
- Flexible configuration options:
  - YAML-based configuration files
  - Environment variable overrides
  - Docker-optimized configuration with persistent volumes
  - Suitable for local and containerized deployments

---

### 🎨 Web Interface
- Modern, responsive web UI
- Intuitive tab-based navigation
- Real-time status updates
- Secure authentication flow:
  - Clean login interface
  - 2FA and backup code support
  - Clear error messages
  - Session management

---

### 🐳 Docker Support
- Container-ready design:
  - Optimized Dockerfile
  - Docker Compose support
  - Health checks
  - Persistent volumes for configuration and state
  - Automated container builds via GitHub Actions

---

## Technical Overview

- **Backend**: FastAPI (Python 3.11)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Configuration Storage**: YAML files
- **Encryption**: Fernet (AES-128)
- **Authentication**: bcrypt, pyotp
- **Default Port**: 8000

---

## Quick Start with Docker Compose

The easiest way to get started is using Docker Compose:

### 1. Clone the repository

```bash
git clone https://github.com/Ihavetriediamsure/Hetzner_DNS_Zone_Tool.git
cd Hetzner_DNS_Zone_Tool
```

### 2. (Optional) Edit docker-compose.yml

If you want to change the port or config directory, edit `docker-compose.yml`:
- Change port: Edit the `ports` section (default: `8000:8000`)
- Change config path: Edit the `volumes` section (default: `/path/to/config:/config`)

### 3. Start the container

```bash
docker-compose up -d
```

### 4. Access the web interface

Open your browser and navigate to:
- **http://localhost:8000** (or the port you configured)

### 5. Initial Setup

On first access, you'll be prompted to:
1. Create an admin user account
2. Set a password
3. Configure your Hetzner DNS API token

### Useful Commands

```bash
# View logs
docker-compose logs -f

# Stop the container
docker-compose down

# Restart the container
docker-compose restart

# Update to latest version
docker-compose pull
docker-compose up -d
```

---

## Docker Image

### Using the Image (Manual Setup)

If you prefer to run without Docker Compose:

```bash
docker pull ghcr.io/ihavetriediamsure/hetzner_dns_zone_tool:latest

docker run -d \
  -p 8000:8000 \
  -v /path/to/config:/config \
  --name hetzner-dns-zone-tool \
  ghcr.io/ihavetriediamsure/hetzner_dns_zone_tool:latest
```

### Configuration

The `docker-compose.yml` file is pre-configured and ready to use. Key settings:

- **Port**: 8000 (change in `docker-compose.yml` ports section)
- **Config Directory**: `/path/to/config` (change in `docker-compose.yml` volumes section)
- **Auto-restart**: Enabled
- **Health checks**: Enabled

All configuration files, authentication data, and logs are stored in the mounted config directory.

---

## License

This project is source-available and licensed under the
PolyForm Noncommercial License 1.0.0.

✔ Free for private, educational, and non-commercial use  
✖ Commercial use, resale, SaaS offerings, or paid services are not permitted

For commercial licensing, please contact the author.

---

## Disclaimer

This project is not affiliated with, endorsed by, or supported by
Hetzner Online GmbH.

This software is provided as-is, without any warranty, and at your own risk.
The author assumes no liability for damages, misconfigurations, outages, or data loss.

---

## Support

This project is provided without support.
Issues and pull requests may be reviewed on a best-effort basis.
