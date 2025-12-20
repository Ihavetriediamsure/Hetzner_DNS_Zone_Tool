FROM python:3.11-slim

# OCI / OpenContainers metadata
LABEL org.opencontainers.image.title="Hetzner DNS A/AAAA IP Manager"
LABEL org.opencontainers.image.description="Automated A/AAAA DNS updates via Hetzner DNS API with secure web UI"
LABEL org.opencontainers.image.source="https://github.com/Ihavetriediamsure/Hetzner_DNS_Zone_Tool"
LABEL org.opencontainers.image.licenses="PolyForm Noncommercial License 1.0.0"
LABEL org.opencontainers.image.vendor="Independent Project"
LABEL org.opencontainers.image.disclaimer="Not affiliated with Hetzner Online GmbH. Use at your own risk."

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (exclude __pycache__)
COPY src/ ./src/
RUN find ./src -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
RUN find ./src -type f -name "*.pyc" -delete 2>/dev/null || true

# Create config directory
RUN mkdir -p /config && chmod 755 /config

# Set environment variables
ENV CONFIG_PATH=/config/config.yaml
ENV AUTH_FILE=/config/auth.yaml
ENV ENCRYPTION_KEY_PATH=/config/.encryption_key
ENV AUDIT_LOG_FILE=/config/audit.log
ENV LOCAL_IP_STORAGE_PATH=/config/local_ips.yaml
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 8000 443

# Health check (try HTTPS first, fallback to HTTP)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, ssl; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; urllib.request.urlopen('https://localhost:443/health', context=ctx)" || \
    python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run the application
# Use custom startup script that handles SSL configuration
CMD ["python", "src/start_server.py"]
