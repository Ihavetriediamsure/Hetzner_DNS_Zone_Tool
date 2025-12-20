"""Startup script for Uvicorn with optional SSL support"""

import os
import sys
from pathlib import Path

# Add /app to path (parent directory of src)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import get_config_manager
from src.ssl_cert import get_or_create_ssl_certificates
import uvicorn
import logging
import socket

logger = logging.getLogger(__name__)

def main():
    """Start Uvicorn server with optional SSL"""
    config_manager = get_config_manager()
    config = config_manager.load_config()
    server_config = config.get('server', {})
    
    host = server_config.get('host', '0.0.0.0')
    port = server_config.get('port', 8000)
    ssl_enabled = server_config.get('ssl_enabled', False)
    
    if ssl_enabled:
        # Determine config directory
        config_dir = Path("/config") if os.path.exists("/config") else Path.home() / ".hetzner-dns"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        cert_path = server_config.get('ssl_cert_path') or str(config_dir / "ssl_cert.pem")
        key_path = server_config.get('ssl_key_path') or str(config_dir / "ssl_key.pem")
        ssl_port = server_config.get('ssl_port', 443)
        
        # Get or create SSL certificates
        hostname = socket.gethostname()
        if not hostname or hostname == "localhost":
            hostname = "localhost"
        
        cert_file, key_file = get_or_create_ssl_certificates(Path(config_dir), hostname)
        
        if cert_file and key_file:
            cert_path = str(cert_file)
            key_path = str(key_file)
            
            # Update config with certificate paths if not set
            if not server_config.get('ssl_cert_path'):
                server_config['ssl_cert_path'] = cert_path
            if not server_config.get('ssl_key_path'):
                server_config['ssl_key_path'] = key_path
            config['server'] = server_config
            config_manager._config = config
            config_manager.save_config()
            
            logger.info(f"Starting HTTPS server on port {ssl_port} with SSL certificates")
            uvicorn.run(
                "src.main:app",
                host=host,
                port=ssl_port,
                ssl_keyfile=key_path,
                ssl_certfile=cert_path,
                log_level="info"
            )
        else:
            logger.error(f"SSL enabled but failed to generate certificates")
            logger.info("Falling back to HTTP on port 8000")
            uvicorn.run(
                "src.main:app",
                host=host,
                port=port,
                log_level="info"
            )
    else:
        uvicorn.run(
            "src.main:app",
            host=host,
            port=port,
            log_level="info"
        )

if __name__ == "__main__":
    main()
