"""SSL Certificate Management for self-signed certificates"""

import os
import logging
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


def generate_self_signed_certificate(
    cert_path: Path,
    key_path: Path,
    hostname: str = "localhost",
    valid_days: int = 365
) -> bool:
    """
    Generate a self-signed SSL certificate
    
    Args:
        cert_path: Path to save the certificate file
        key_path: Path to save the private key file
        hostname: Hostname for the certificate (default: localhost)
        valid_days: Validity period in days (default: 365)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Internal"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Internal"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hetzner DNS Zone Tool"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=valid_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Save certificate
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(cert_path, 0o644)
        
        # Save private key
        key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(key_path, 0o600)
        
        logger.info(f"Generated self-signed certificate: {cert_path} (valid for {valid_days} days)")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate self-signed certificate: {e}")
        return False


def get_or_create_ssl_certificates(
    config_dir: Path,
    hostname: str = "localhost"
) -> tuple[Path | None, Path | None]:
    """
    Get existing SSL certificates or create new ones if they don't exist
    
    Args:
        config_dir: Configuration directory (e.g., /config)
        hostname: Hostname for the certificate
    
    Returns:
        Tuple of (cert_path, key_path) or (None, None) if failed
    """
    cert_path = config_dir / "ssl_cert.pem"
    key_path = config_dir / "ssl_key.pem"
    
    # Check if certificates exist and are valid
    if cert_path.exists() and key_path.exists():
        try:
            # Verify certificate is readable
            with open(cert_path, "rb") as f:
                x509.load_pem_x509_certificate(f.read())
            with open(key_path, "rb") as f:
                serialization.load_pem_private_key(f.read(), password=None)
            logger.info(f"Using existing SSL certificates: {cert_path}")
            return cert_path, key_path
        except Exception as e:
            logger.warning(f"Existing certificates invalid, regenerating: {e}")
    
    # Generate new certificates
    if generate_self_signed_certificate(cert_path, key_path, hostname):
        return cert_path, key_path
    
    return None, None

