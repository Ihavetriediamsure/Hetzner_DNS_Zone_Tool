"""Split-Brain Protection Module for IP Updates"""

import asyncio
import httpx
import logging
import hashlib
import hmac
import base64
from typing import Dict, Any, Optional, List
from pathlib import Path
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from src.encryption import get_encryption_manager

logger = logging.getLogger(__name__)


class SplitBrainProtection:
    """Protects against split-brain situations in IP updates"""
    
    def __init__(self):
        self._enabled = False
        self._peer_nodes: List[str] = []
        self._timeout = 5  # Timeout per peer in seconds
        self._peer_x25519_keys: Dict[str, x25519.X25519PublicKey] = {}  # IP -> X25519PublicKey
        self._peer_names: Dict[str, str] = {}  # IP -> Name mapping
        self._own_x25519_private_key: Optional[x25519.X25519PrivateKey] = None
        self._own_x25519_public_key: Optional[x25519.X25519PublicKey] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._load_config()
        self._load_own_x25519_key()
    
    def _load_config(self):
        """Load configuration from environment or config file"""
        try:
            from src.config_manager import get_config_manager
            config_manager = get_config_manager()
            config = config_manager.load_config()
            
            peer_sync_config = config.get('peer_sync', {})
            self._enabled = peer_sync_config.get('enabled', False)
            self._peer_nodes = peer_sync_config.get('peer_nodes', [])
            self._timeout = peer_sync_config.get('timeout', 5)
            
            # Load peer public keys and names
            peer_public_keys_config = peer_sync_config.get('peer_public_keys', {})
            for peer_ip, peer_data in peer_public_keys_config.items():
                peer_name = peer_data.get('name', peer_ip)
                self._peer_names[peer_ip] = peer_name
                
                # Load X25519 public key (WireGuard format: Base64-encoded 32 bytes raw)
                peer_public_key_b64 = peer_data.get('public_key', '')
                if peer_public_key_b64:
                    try:
                        # Try WireGuard format first (32 bytes raw)
                        try:
                            raw_bytes = base64.b64decode(peer_public_key_b64)
                            if len(raw_bytes) == 32:
                                # WireGuard format: 32 bytes raw
                                peer_public_key = x25519.X25519PublicKey.from_public_bytes(raw_bytes)
                                self._peer_x25519_keys[peer_ip] = peer_public_key
                            else:
                                raise ValueError("Invalid key length")
                        except Exception:
                            # Fallback: Try PEM format (for migration)
                            peer_public_key_bytes = base64.b64decode(peer_public_key_b64)
                            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
                            if isinstance(peer_public_key, x25519.X25519PublicKey):
                                self._peer_x25519_keys[peer_ip] = peer_public_key
                                logger.info(f"Migrated peer {peer_ip} key from PEM to WireGuard format (split-brain)")
                            else:
                                raise ValueError("Invalid X25519 public key type")
                    except Exception as e:
                        logger.warning(f"Failed to load X25519 public key for peer {peer_ip}: {e}")
        except Exception as e:
            logger.error(f"Failed to load split-brain protection config: {e}")
    
    def _load_own_x25519_key(self):
        """Load our own X25519 key pair (encrypted storage)"""
        try:
            config_dir = Path("/config") if os.path.exists("/config") else Path.home() / ".hetzner-dns"
            key_path = config_dir / ".peer_sync_x25519_key"
            if key_path.exists():
                # Read encrypted key file
                with open(key_path, 'rb') as f:
                    encrypted_key_bytes = f.read()
                
                # Decrypt using Fernet (same as API tokens)
                encryption_manager = get_encryption_manager()
                try:
                    # Try to decrypt (new format: encrypted)
                    decrypted_key_bytes = encryption_manager._get_fernet().decrypt(encrypted_key_bytes)
                    self._own_x25519_private_key = serialization.load_pem_private_key(decrypted_key_bytes, password=None)
                except Exception:
                    # Fallback: Try to load as unencrypted PEM (for migration from old format)
                    try:
                        self._own_x25519_private_key = serialization.load_pem_private_key(encrypted_key_bytes, password=None)
                        logger.info("Migrating X25519 key to encrypted format (split-brain)")
                    except Exception as e:
                        logger.error(f"Failed to decrypt or load X25519 key: {e}")
                        self._own_x25519_private_key = None
                        self._own_x25519_public_key = None
                        return
                
                if isinstance(self._own_x25519_private_key, x25519.X25519PrivateKey):
                    self._own_x25519_public_key = self._own_x25519_private_key.public_key()
                else:
                    logger.warning("Invalid X25519 private key type")
                    self._own_x25519_private_key = None
                    self._own_x25519_public_key = None
        except Exception as e:
            logger.error(f"Failed to load own X25519 key: {e}")
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy initialization of httpx.AsyncClient with connection pooling"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10)
            )
        return self._client
    
    def is_enabled(self) -> bool:
        """Check if split-brain protection is enabled"""
        return self._enabled and len(self._peer_nodes) > 0
    
    async def check_split_brain(
        self, 
        monitor_ip: str, 
        port: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Check all peers in parallel for split-brain situation
        
        Args:
            monitor_ip: Monitor IP address to check
            port: Port to check (optional, defaults to 80)
        
        Returns:
            {
                "split_brain_detected": bool,
                "alive_peers": List[str],  # List of peer names that report "alive"
                "total_peers_checked": int,
                "total_peers_responded": int,
                "check_duration_ms": float,
                "reason": str
            }
        """
        if not self.is_enabled():
            return {
                "split_brain_detected": False,
                "alive_peers": [],
                "total_peers_checked": 0,
                "total_peers_responded": 0,
                "check_duration_ms": 0,
                "reason": "Peer-Sync deaktiviert oder keine Peers konfiguriert"
            }
        
        start_time = asyncio.get_event_loop().time()
        alive_peers = []
        
        if not self._own_x25519_private_key or not self._own_x25519_public_key:
            logger.warning("Own X25519 keys not available for signing")
            return {
                "split_brain_detected": False,
                "alive_peers": [],
                "total_peers_checked": len(self._peer_nodes),
                "total_peers_responded": 0,
                "check_duration_ms": 0,
                "reason": "Own X25519 keys not available"
            }
        
        # Get our public key as Base64
        our_public_key_b64 = base64.b64encode(
            self._own_x25519_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
        
        # Create tasks for all peers (PARALLEL)
        async def check_peer(peer: str) -> Optional[Dict]:
            """Check a single peer (called in parallel)"""
            try:
                # Extract peer IP from "IP:Port" format
                peer_ip = peer.split(":")[0]
                
                # Build URL
                url = f"http://{peer}/api/v1/peer-sync/check-monitor-ip"
                params = {"ip": monitor_ip}
                if port:
                    params["port"] = port
                
                # Sign request with HMAC-SHA256 (using our public key)
                query_string = "&".join([f"{k}={v}" for k, v in params.items()])
                full_url = f"{url}?{query_string}" if query_string else url
                request_data = f"GET:{full_url}".encode()
                
                # Sign with our public key bytes (for HMAC)
                our_public_key_bytes = self._own_x25519_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                signature = hmac.new(our_public_key_bytes, request_data, hashlib.sha256).digest()
                signature_b64 = base64.b64encode(signature).decode()
                
                headers = {
                    "X-Peer-Public-Key": our_public_key_b64,
                    "X-Peer-Signature": signature_b64
                }
                
                client = await self._get_client()
                response = await client.get(url, params=params, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("alive", False):
                        peer_name = data.get("peer_name", self._peer_names.get(peer_ip, peer_ip))
                        return {
                            "peer": peer,
                            "peer_name": peer_name,
                            "alive": True
                        }
            except Exception as e:
                logger.debug(f"Peer {peer} nicht erreichbar: {e}")
            return None
        
        # Execute all checks in parallel
        tasks = [check_peer(peer) for peer in self._peer_nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if result and isinstance(result, dict) and result.get("alive", False):
                alive_peers.append(result.get("peer_name", "Unknown"))
        
        check_duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        
        # Split-Brain detection: If ≥2 peers report "alive"
        split_brain_detected = len(alive_peers) >= 2
        
        return {
            "split_brain_detected": split_brain_detected,
            "alive_peers": alive_peers,
            "total_peers_checked": len(self._peer_nodes),
            "total_peers_responded": len([r for r in results if not isinstance(r, Exception) and r]),
            "check_duration_ms": check_duration_ms,
            "reason": (
                f"Split-Brain erkannt: {len(alive_peers)} Peers melden Monitor IP als alive: {', '.join(alive_peers)}"
                if split_brain_detected
                else (
                    f"Kein Split-Brain: {len(alive_peers)} Peer(s) melden Monitor IP als alive. Update wird durchgeführt."
                    if len(alive_peers) > 0
                    else f"Keine Peers erreichbar ({len(self._peer_nodes)} Peers konfiguriert). Update wird durchgeführt (robuster Fallback)."
                )
            )
        }


# Global instance
_split_brain_protection = None


def get_split_brain_protection() -> SplitBrainProtection:
    """Get global split-brain protection instance"""
    global _split_brain_protection
    if _split_brain_protection is None:
        _split_brain_protection = SplitBrainProtection()
    return _split_brain_protection

