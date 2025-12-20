# Security Policy

## Supported Versions

Security updates are provided only for the latest stable release. Older versions may not receive security patches.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest| :x:                |

---

## Scope

This project was developed as a **community-driven hobby project** to simplify DNS management and enable flexible IP address management across multiple server locations in distributed environments.

This project is intended for **self-hosted use** in homelabs and private infrastructure.

**No security guarantees are provided.** This is a community-driven project without formal security audits or certifications.

The software is provided without warranty and without formal security guarantees. There are no security certifications, audits, SLAs, penetration tests, or guaranteed fix timelines. **Use at your own risk.**

---

## Threat Model

The following threat scenarios are considered within the intended environment:

### In-Scope Threats

- Unauthorized access due to weak credentials
- Credential theft or session hijacking
- Brute-force and enumeration attacks
- Token/secret disclosure via filesystem compromise
- CSRF attacks
- MITM attacks when HTTPS/TLS is not enforced
- Insider misuse of privileged accounts
- Replay/forgery attacks against peer communication

### Out-of-Scope Threats

- Zero-day vulnerabilities in system dependencies
- Vulnerabilities introduced via insecure deployments
- Compromised host machine or hypervisor
- Supply-chain attacks beyond dependency advisories
- State-level attackers or advanced persistent threats
- Public cloud SaaS multi-tenancy threats

**Note**: This threat model is intentionally limited; the system is not designed for high-assurance security contexts.

---

## Reporting a Vulnerability

If you discover a security vulnerability, please report it **responsibly**:

### Do NOT:
- ❌ Open a public GitHub issue
- ❌ Discuss the vulnerability publicly
- ❌ Share exploit details before a fix is available

### DO:
- ✅ Contact maintainers privately via GitHub or Security Advisories
- ✅ Provide detailed information about the vulnerability
- ✅ Include steps to reproduce (if applicable)
- ✅ Provide results of any testing or proof-of-concept
- ✅ Allow reasonable time for a response before public disclosure

### What to Include

When reporting a vulnerability, please provide:
- Description of the vulnerability
- Affected components/versions
- Potential impact
- Steps to reproduce (if applicable)
- Suggested fix (if you have one)
- CVSS 3.1 score recommendation (if applicable)

---

## Coordinated Disclosure Timeline

The project follows a **best-effort** coordinated disclosure process:

1. **Acknowledgment of receipt**: Target within 7 calendar days (best-effort)
2. **Initial assessment and triage**: Target within 14 days (best-effort)
3. **Fix development and testing**: Target within 90 days (best-effort)
4. **High/Critical issues**: Prioritized ahead of lower severity issues
5. **Public disclosure**: Coordinated after the release of a fixed version

**Important**: Timeline deviation may occur depending on maintainer availability. This is a community-maintained project without a dedicated security team. Response time depends on maintainer availability.

---

## Vulnerability Severity Classification

Severity of reported vulnerabilities is determined through qualitative risk analysis and may be supported by CVSS scoring when provided:

- **Critical** – High likelihood + high impact (e.g., RCE, auth bypass)
- **High** – Exploitable with elevated impact (e.g., privilege escalation)
- **Medium** – Limited exploitability/impact
- **Low** – Minor issues or requiring unrealistic attack preconditions

Submitters are encouraged to include a CVSS 3.1 score recommendation.

---

## Security Features

This project implements the following security measures:

### Authentication & Access Control
- **Password Authentication**: bcrypt hashing with strong password requirements (min. 12 chars, uppercase, number, special character)
- **Multi-Factor Authentication (2FA)**: TOTP-based 2FA with encrypted secrets and backup codes
- **Brute-Force Protection**: Configurable protection with separate counters for login, 2FA, and backup codes
- **IP Access Control**: CIDR-based whitelist/blacklist support
- **Session Management**: Secure session handling with auto-generated secrets
- **CSRF Protection**: Double-Submit Cookie Pattern for CSRF protection

### Data Protection
- **Encryption**: Fernet (AES-128) encryption for:
  - API tokens
  - 2FA secrets
  - Backup codes
  - SMTP passwords
- **File Permissions**: Sensitive files are protected with `600` permissions (owner read/write only)
- **No Hardcoded Secrets**: All sensitive data is stored encrypted or hashed

### Network Security
- **HTTPS/TLS Support**: Built-in HTTPS with self-signed certificate generation
- **Automatic SSL Migration**: SSL configuration automatically enabled on first start
- **Secure Cookies**: Automatic secure cookie flags when HTTPS is enabled
- **Peer-to-Peer Encryption**: X25519 key exchange with AES-256-GCM encryption for peer-sync

### Monitoring & Logging
- **Audit Logging**: Comprehensive logging of security-relevant events
- **Automatic Log Rotation**: Configurable rotation based on size and age
- **SMTP Notifications**: Optional email alerts for security events

---

## Dependency Security

The project's security also depends on upstream components. The following dependency-related security practices apply:

- Regular dependency updates through automated monitoring (Renovate/Dependabot recommended)
- Tracking of security advisories for dependencies
- Patching of vulnerable components when fixes become available
- **No guarantees** if dependency vendors discontinue support
- Containers/images are rebuilt after base image security updates

**User Responsibility**: Users are responsible for ensuring runtime environments (Docker host, OS, container runtime) are patched.

---

## Logging and Retention

Security-related logs generated by the system include, but are not limited to:

- Login attempts
- Failed authentication
- Brute-force protection events
- Peer-sync security negotiations
- Configuration access events

Log retention is configurable by size/age and defaults to rotation on disk exhaustion prevention. **Logs may contain sensitive metadata and must be protected accordingly.**

---

## Security Best Practices

### For Users

1. **Initial Setup**
   - Use a strong, unique password (minimum 12 characters)
   - Enable 2FA immediately after setup
   - Save backup codes in a secure location
   - Enable brute-force protection

2. **Network Security**
   - HTTPS is enabled by default (`ssl_enabled: true`) for encrypted connections
   - Self-signed certificates are automatically generated on first start (browser warnings are normal)
   - **Important**: For external access, always use a reverse proxy (nginx, Traefik) with trusted TLS certificates
     - The self-signed certificate is intended for internal connections only
     - Do not expose the application directly to the internet without a reverse proxy
   - Use IP whitelist/blacklist if exposing to the internet
   - Do not expose the application on `0.0.0.0` without IP restrictions
   - Peer-to-peer sync uses HTTPS by default (SSL is automatically enabled through configuration migration)

3. **File Security**
   - Back up `.encryption_key` securely (without it, encrypted data is unrecoverable)
   - Protect `config.yaml` and `auth.yaml` files (permissions `600`)
   - Never commit sensitive files to version control

4. **API Tokens**
   - Use separate API tokens for different zones/environments
   - Regularly rotate API tokens
   - Use tokens with minimal required permissions

5. **Updates**
   - Keep the application updated to the latest version
   - Monitor security advisories and release notes

### For Docker Deployments

1. **Volume Security**
   - Ensure `/config` volume has proper permissions
   - Do not mount sensitive directories from untrusted sources

2. **Network Isolation**
   - Use Docker networks to isolate the container
   - Do not expose unnecessary ports

3. **Image Security**
   - Use official images from GitHub Container Registry
   - Verify image signatures if possible
   - Regularly update base images

---

## Known Limitations

1. **No Security Audits**: This project has not undergone formal security audits
2. **Self-Hosted Only**: Designed for private use, not for public-facing production services
3. **Limited Scope**: Only A/AAAA DNS records are supported
4. **Community Support**: Security fixes are provided on a best-effort basis
5. **No SLA**: No service level agreement for security updates

---

## Security Considerations

### What This Project Does NOT Provide

- ❌ Formal security certifications
- ❌ Penetration testing
- ❌ Security audits
- ❌ Bug bounty program
- ❌ Guaranteed response time for vulnerabilities
- ❌ Production-grade security guarantees

### What This Project DOES Provide

- ✅ Encryption for sensitive data
- ✅ Strong authentication mechanisms
- ✅ Audit logging
- ✅ Security best practices implementation
- ✅ Community-driven security improvements

**Note**: These mechanisms mitigate but do not eliminate risks.

---

## Legal Disclaimer

This software is provided "as is" without warranties of any kind, explicit or implied, including but not limited to merchantability, fitness for a particular purpose, and non-infringement.

The maintainers shall not be liable for any damage, data loss, security compromise, or operational impact arising from use of this software.

---

## Contact

For security-related issues, contact the repository owner via:
- GitHub private message
- GitHub Security Advisories (if enabled)

**Please do not use public issues or discussions for security vulnerabilities.**

---

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report vulnerabilities in a responsible manner (if desired).

Contributors who responsibly disclose vulnerabilities may be publicly credited if desired.

---

*Last updated: 2025*
