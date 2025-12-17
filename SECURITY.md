# Security Policy

## Supported Versions

Security updates are provided for the latest release version. Older versions may not receive security patches.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest| :x:                |

---

## Scope

This project is intended for **self-hosted use** in homelabs and private infrastructure.

**No security guarantees are provided.** This is a community-driven project without formal security audits or certifications.

---

## Reporting a Vulnerability

If you discover a security vulnerability, please report it **responsibly**:

### Do NOT:
- ❌ Open a public GitHub issue
- ❌ Discuss the vulnerability publicly
- ❌ Share exploit details before a fix is available

### DO:
- ✅ Contact the repository owner privately via GitHub
- ✅ Provide detailed information about the vulnerability
- ✅ Include steps to reproduce (if applicable)
- ✅ Allow reasonable time for a response before public disclosure

### What to Include

When reporting a vulnerability, please provide:
- Description of the vulnerability
- Affected components/versions
- Potential impact
- Steps to reproduce (if applicable)
- Suggested fix (if you have one)

---

## Security Features

This project implements the following security measures:

### Authentication & Access Control
- **Password Authentication**: bcrypt hashing with strong password requirements (min. 12 chars, uppercase, number, special character)
- **Multi-Factor Authentication (2FA)**: TOTP-based 2FA with encrypted secrets and backup codes
- **Brute-Force Protection**: Configurable protection with separate counters for login, 2FA, and backup codes
- **IP Access Control**: CIDR-based whitelist/blacklist support
- **Session Management**: Secure session handling with auto-generated secrets

### Data Protection
- **Encryption**: Fernet (AES-128) encryption for:
  - API tokens
  - 2FA secrets
  - Backup codes
  - SMTP passwords
- **File Permissions**: Sensitive files are protected with `600` permissions (owner read/write only)
- **No Hardcoded Secrets**: All sensitive data is stored encrypted or hashed

### Monitoring & Logging
- **Audit Logging**: Comprehensive logging of security-relevant events
- **Automatic Log Rotation**: Configurable rotation based on size and age
- **SMTP Notifications**: Optional email alerts for security events

---

## Security Best Practices

### For Users

1. **Initial Setup**
   - Use a strong, unique password (minimum 12 characters)
   - Enable 2FA immediately after setup
   - Save backup codes in a secure location
   - Enable brute-force protection

2. **Network Security**
   - Use IP whitelist/blacklist if exposing to the internet
   - Consider using a reverse proxy (nginx, Traefik) with TLS
   - Do not expose the application on `0.0.0.0` without IP restrictions

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

---

## Disclosure Policy

1. **Initial Report**: Vulnerability reported privately to maintainer
2. **Acknowledgment**: Maintainer acknowledges receipt (within 7 days)
3. **Assessment**: Vulnerability is assessed and prioritized
4. **Fix Development**: Fix is developed and tested
5. **Release**: Fixed version is released
6. **Public Disclosure**: After fix is available, vulnerability may be disclosed (coordinated disclosure)

**Note**: Response time depends on maintainer availability. This is a community project without dedicated security team.

---

## Contact

For security-related issues, contact the repository owner via:
- GitHub private message
- GitHub Security Advisories (if enabled)

**Please do not use public issues or discussions for security vulnerabilities.**

---

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report vulnerabilities in a responsible manner (if desired).

---

*Last updated: 2025*
