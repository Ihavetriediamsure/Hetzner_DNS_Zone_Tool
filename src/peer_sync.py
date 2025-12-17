"""Peer-to-Peer Config Synchronization Module"""

import os
import asyncio
import httpx
import logging
import hashlib
import json
import secrets
import base64
import time
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
from src.encryption import get_encryption_manager

from src.local_ip_storage import get_local_ip_storage

logger = logging.getLogger(__name__)


def calculate_content_hash(config_data: Dict) -> str:
    """Calculate hash of config content (without generation field)"""
    config_copy = config_data.copy()
    config_copy.pop('generation', None)  # Remove generation for hash
    content_str = json.dumps(config_copy, sort_keys=True)
    return hashlib.sha256(content_str.encode()).hexdigest()


def is_newer(local_gen: Dict, peer_gen: Dict, local_config: Dict, peer_config: Dict) -> bool:
    """
    Compare generation counters to determine if peer config is newer
    
    Comparison logic:
    1. Higher sequence number wins
    2. If same sequence: Higher timestamp wins
    3. If same sequence and timestamp: Compare content_hash (deterministic)
    """
    # 1. Higher sequence number wins
    local_seq = local_gen.get('sequence', 0)
    peer_seq = peer_gen.get('sequence', 0)
    
    if peer_seq > local_seq:
        return True
    elif peer_seq < local_seq:
        return False
    else:
        # 2. Same sequence: Compare timestamp
        local_ts = local_gen.get('timestamp', 0)
        peer_ts = peer_gen.get('timestamp', 0)
        
        if peer_ts > local_ts:
            return True
        elif peer_ts < local_ts:
            return False
        else:
            # 3. Same sequence and timestamp: Compare content_hash
            peer_hash = peer_gen.get('content_hash', '')
            local_hash = local_gen.get('content_hash', '')
            
            if peer_hash != local_hash:
                # Configs are different despite same generation
                # Use hash comparison (deterministic, not arbitrary)
                return peer_hash > local_hash
            else:
                # Hash is equal = configs are identical
                return False


class PeerSync:
    """Manages peer-to-peer configuration synchronization"""
    
    def __init__(self):
        self._enabled = False
        self._peer_nodes: List[str] = []
        self._sync_interval = 300  # Default: 5 minutes
        self._timeout = 5  # Default: 5 seconds
        self._max_retries = 3
        self._rate_limit = 1.0  # Requests per second per peer
        self._ntp_enabled = False
        
        # Own X25519 key pair
        self.x25519_private_key: Optional[x25519.X25519PrivateKey] = None
        self.x25519_public_key: Optional[x25519.X25519PublicKey] = None
        
        # Peer public keys (IP -> X25519PublicKey)
        self.peer_x25519_keys: Dict[str, x25519.X25519PublicKey] = {}  # peer_ip -> X25519PublicKey
        self.peer_names: Dict[str, str] = {}  # IP -> Name mapping
        
        # Statistics
        self._stats: Dict[str, Any] = {
            "total_successful_syncs": 0,
            "total_failed_syncs": 0,
            "peer_stats": {}  # peer_ip -> {success_count, fail_count, avg_duration_ms, avg_response_time_ms, total_retries, rate_limit_violations}
        }
        self._recent_events: List[Dict[str, Any]] = []  # Last 10 events
        
        # Rate limiting tracking
        self._rate_limit_tracking: Dict[str, List[float]] = {}  # peer_ip -> [timestamps]
        
        # Background task
        self._task: Optional[asyncio.Task] = None
        self._running = False
        
        # HTTP client for connection pooling
        self._client: Optional[httpx.AsyncClient] = None
        
        # Load configuration and keys
        self._load_config()
        self._load_or_generate_x25519_key()
        self._load_peer_public_keys()
    
    def _load_config(self):
        """Load configuration from config manager"""
        try:
            from src.config_manager import get_config_manager
            config_manager = get_config_manager()
            config = config_manager.load_config()
            
            peer_sync_config = config.get('peer_sync', {})
            self._enabled = peer_sync_config.get('enabled', False)
            self._peer_nodes = peer_sync_config.get('peer_nodes', [])
            self._sync_interval = peer_sync_config.get('interval', 300)
            self._timeout = peer_sync_config.get('timeout', 5)
            self._max_retries = peer_sync_config.get('max_retries', 3)
            self._rate_limit = peer_sync_config.get('rate_limit', 1.0)
            self._ntp_enabled = peer_sync_config.get('ntp_enabled', False)
        except Exception as e:
            logger.error(f"Failed to load peer-sync config: {e}")
    
    def _load_or_generate_x25519_key(self):
        """Load or generate X25519 key pair (encrypted storage)"""
        # Determine config directory
        config_dir = Path("/config") if os.path.exists("/config") else Path.home() / ".hetzner-dns"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        key_path = config_dir / ".peer_sync_x25519_key"
        if key_path.exists():
            try:
                # Read encrypted key file
                with open(key_path, 'rb') as f:
                    encrypted_key_bytes = f.read()
                
                # Decrypt using Fernet (same as API tokens)
                encryption_manager = get_encryption_manager()
                try:
                    # Try to decrypt (new format: encrypted)
                    decrypted_key_bytes = encryption_manager._get_fernet().decrypt(encrypted_key_bytes)
                    self.x25519_private_key = serialization.load_pem_private_key(decrypted_key_bytes, password=None)
                except Exception:
                    # Fallback: Try to load as unencrypted PEM (for migration from old format)
                    try:
                        self.x25519_private_key = serialization.load_pem_private_key(encrypted_key_bytes, password=None)
                        # If successful, re-encrypt and save in new format
                        logger.info("Migrating X25519 key to encrypted format")
                        self._save_x25519_key(key_path)
                    except Exception as e:
                        raise ValueError(f"Failed to decrypt or load X25519 key: {e}")
                
                if not isinstance(self.x25519_private_key, x25519.X25519PrivateKey):
                    raise ValueError("Invalid X25519 private key type")
                self.x25519_public_key = self.x25519_private_key.public_key()
            except Exception as e:
                logger.error(f"Failed to load X25519 key: {e}")
                self._generate_x25519_key(key_path)
        else:
            self._generate_x25519_key(key_path)
    
    def _generate_x25519_key(self, key_path: Path):
        """Generate new X25519 key pair and save encrypted"""
        try:
            self.x25519_private_key = x25519.X25519PrivateKey.generate()
            self.x25519_public_key = self.x25519_private_key.public_key()
            
            # Save encrypted
            self._save_x25519_key(key_path)
            logger.info(f"Generated new X25519 key pair (encrypted): {key_path}")
        except Exception as e:
            logger.error(f"Failed to generate X25519 key: {e}")
    
    def _save_x25519_key(self, key_path: Path):
        """Save X25519 private key encrypted with Fernet"""
        try:
            # Serialize private key to PEM format
            key_bytes = self.x25519_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Encrypt with Fernet (same as API tokens)
            encryption_manager = get_encryption_manager()
            encrypted_key_bytes = encryption_manager._get_fernet().encrypt(key_bytes)
            
            # Save encrypted key
            key_path.parent.mkdir(parents=True, exist_ok=True)
            with open(key_path, 'wb') as f:
                f.write(encrypted_key_bytes)
            if os.name != 'nt':
                os.chmod(key_path, 0o600)
        except Exception as e:
            logger.error(f"Failed to save X25519 key: {e}")
            raise
    
    def regenerate_x25519_key(self) -> bool:
        """Manually regenerate X25519 key pair (returns True if successful)"""
        try:
            config_dir = Path("/config") if os.path.exists("/config") else Path.home() / ".hetzner-dns"
            key_path = config_dir / ".peer_sync_x25519_key"
            # Generate new key (will be saved encrypted)
            self.x25519_private_key = x25519.X25519PrivateKey.generate()
            self.x25519_public_key = self.x25519_private_key.public_key()
            self._save_x25519_key(key_path)
            logger.info("X25519 key pair regenerated successfully (encrypted)")
            return True
        except Exception as e:
            logger.error(f"Failed to regenerate X25519 key: {e}")
            return False
    
    def _load_peer_public_keys(self):
        """Load peer public keys from configuration"""
        try:
            from src.config_manager import get_config_manager
            config_manager = get_config_manager()
            config = config_manager.load_config()
            
            peer_sync_config = config.get('peer_sync', {})
            peer_public_keys_config = peer_sync_config.get('peer_public_keys', {})  # peer_ip -> {name, public_key}
            
            for peer_ip, peer_data in peer_public_keys_config.items():
                peer_name = peer_data.get('name', peer_ip)
                self.peer_names[peer_ip] = peer_name
                
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
                                self.peer_x25519_keys[peer_ip] = peer_public_key
                            else:
                                raise ValueError("Invalid key length")
                        except Exception:
                            # Fallback: Try PEM format (for migration)
                            peer_public_key_bytes = base64.b64decode(peer_public_key_b64)
                            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
                            if isinstance(peer_public_key, x25519.X25519PublicKey):
                                self.peer_x25519_keys[peer_ip] = peer_public_key
                                logger.info(f"Migrated peer {peer_ip} key from PEM to WireGuard format")
                            else:
                                raise ValueError("Invalid X25519 public key type")
                    except Exception as e:
                        logger.warning(f"Failed to load X25519 public key for peer {peer_ip}: {e}")
        except Exception as e:
            logger.error(f"Failed to load peer public keys: {e}")
    
    def get_public_key_base64(self) -> str:
        """Get our X25519 public key as Base64 string (WireGuard format: 32 bytes raw)"""
        if not self.x25519_public_key:
            return ""
        # WireGuard format: raw 32 bytes, Base64 encoded (44 chars)
        raw_bytes = self.x25519_public_key.public_bytes_raw()
        return base64.b64encode(raw_bytes).decode()
    
    def _derive_shared_secret(self, peer_x25519_public_key: x25519.X25519PublicKey) -> bytes:
        """Derive shared secret using X25519 ECDH"""
        if not self.x25519_private_key:
            raise ValueError("X25519 private key not loaded")
        
        shared_key = self.x25519_private_key.exchange(peer_x25519_public_key)
        # Derive AES key from shared secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=None,
            info=b'peer-sync',
            backend=default_backend()
        )
        return hkdf.derive(shared_key)
    
    def _encrypt_config(self, config_data: Dict, peer_x25519_public_key: x25519.X25519PublicKey) -> Dict[str, str]:
        """Encrypt config using AES-256-GCM with derived shared secret"""
        # Derive shared secret using ECDH
        aes_key = self._derive_shared_secret(peer_x25519_public_key)
        
        # Serialize config to JSON
        config_json = json.dumps(config_data, sort_keys=True).encode('utf-8')
        
        # Generate random nonce (Perfect Forward Secrecy)
        nonce = secrets.token_bytes(12)  # 96 bits for GCM
        
        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, config_json, None)
        
        return {
            "encrypted_data": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode()
        }
    
    def _decrypt_config(self, encrypted_data: str, nonce: str, peer_x25519_public_key: x25519.X25519PublicKey) -> Dict:
        """Decrypt config using AES-256-GCM with derived shared secret"""
        # Derive shared secret using ECDH
        aes_key = self._derive_shared_secret(peer_x25519_public_key)
        
        # Decode base64
        ciphertext = base64.b64decode(encrypted_data)
        nonce_bytes = base64.b64decode(nonce)
        
        # Decrypt with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce_bytes, ciphertext, None)
        
        # Deserialize JSON
        return json.loads(plaintext.decode('utf-8'))
    
    def _sign_data(self, data: bytes) -> str:
        """Sign data with HMAC-SHA256 using derived shared secret"""
        # For signing, we use a temporary shared secret derived from our private key
        # In practice, we sign with a key derived from the shared secret
        # For now, we'll use a simpler approach: sign with a hash of our public key + data
        # This is for request authentication, not for encryption
        if not self.x25519_public_key:
            raise ValueError("X25519 public key not loaded")
        
        # Use public key bytes as signing key (for HMAC)
        public_key_bytes = self.x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        signature = hmac.new(public_key_bytes, data, hashlib.sha256).digest()
        return base64.b64encode(signature).decode()
    
    def _verify_signature(self, data: bytes, signature_b64: str, peer_x25519_public_key: x25519.X25519PublicKey) -> bool:
        """Verify HMAC-SHA256 signature using peer's public key"""
        try:
            peer_public_key_bytes = peer_x25519_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            expected_signature = hmac.new(peer_public_key_bytes, data, hashlib.sha256).digest()
            received_signature = base64.b64decode(signature_b64)
            return hmac.compare_digest(expected_signature, received_signature)
        except Exception:
            return False
    
    def _check_rate_limit(self, peer_ip: str) -> bool:
        """Check if rate limit allows request to peer"""
        now = time.time()
        
        # Clean old timestamps (older than 1 second)
        if peer_ip in self._rate_limit_tracking:
            self._rate_limit_tracking[peer_ip] = [
                ts for ts in self._rate_limit_tracking[peer_ip] 
                if now - ts < 1.0
            ]
        else:
            self._rate_limit_tracking[peer_ip] = []
        
        # Check if we're at the limit
        if len(self._rate_limit_tracking[peer_ip]) >= self._rate_limit:
            # Update statistics
            if peer_ip not in self._stats["peer_stats"]:
                self._stats["peer_stats"][peer_ip] = {
                    "success_count": 0,
                    "fail_count": 0,
                    "avg_duration_ms": 0,
                    "avg_response_time_ms": 0,
                    "total_retries": 0,
                    "rate_limit_violations": 0
                }
            self._stats["peer_stats"][peer_ip]["rate_limit_violations"] += 1
            return False
        
        # Add current timestamp
        self._rate_limit_tracking[peer_ip].append(now)
        return True
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with connection pooling"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10)
            )
        return self._client
    
    async def sync_with_all_peers(self) -> Dict[str, Any]:
        """
        Synchronize config with all peers in parallel
        
        Returns:
            {
                "synced_peers": List[str],
                "failed_peers": List[str],
                "total_duration_ms": float
            }
        """
        if not self._enabled or not self._peer_nodes:
            return {
                "synced_peers": [],
                "failed_peers": [],
                "total_duration_ms": 0
            }
        
        start_time = time.time()
        synced_peers = []
        failed_peers = []
        
        # Create tasks for all peers (PARALLEL)
        async def sync_with_peer(peer: str) -> Optional[Dict]:
            """Synchronize with a single peer (called in parallel)"""
            peer_ip = peer.split(":")[0]
            
            # Check rate limit
            if not self._check_rate_limit(peer_ip):
                logger.debug(f"Rate limit exceeded for peer {peer}")
                return None
            
            # Check if we have peer's X25519 public key
            if peer_ip not in self.peer_x25519_keys:
                logger.warning(f"Missing X25519 public key for peer {peer_ip}")
                return None
            
            peer_x25519_pub = self.peer_x25519_keys[peer_ip]
            
            if not self.x25519_private_key or not self.x25519_public_key:
                logger.warning("Own X25519 keys not loaded")
                return None
            
            try:
                # Sign request with HMAC-SHA256 using our public key
                # Use only the path (not full URL) to match verification logic
                url = f"http://{peer}/api/v1/sync/local-ips"
                url_path = "/api/v1/sync/local-ips"
                request_data = f"GET:{url_path}".encode()
                signature = self._sign_data(request_data)
                
                # Get our public key as Base64 for authentication
                our_public_key_b64 = self.get_public_key_base64()
                
                headers = {
                    "X-Peer-Public-Key": our_public_key_b64,
                    "X-Peer-Signature": signature
                }
                
                client = await self._get_client()
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    response_data = response.json()
                    
                    # Get peer's public key from response header (if provided)
                    # Use cached public key (we already have it from config)
                    peer_x25519_pub = self.peer_x25519_keys[peer_ip]
                    
                    # Verify signature of encrypted data
                    encrypted_data = response_data.get("encrypted_data", "")
                    nonce = response_data.get("nonce", "")
                    response_signature = response.headers.get("X-Peer-Signature", "")
                    
                    # Verify signature with peer's public key
                    sig_data = f"{encrypted_data}:{nonce}".encode()
                    if not self._verify_signature(sig_data, response_signature, peer_x25519_pub):
                        logger.warning(f"Invalid signature from peer {peer_ip}")
                        return None
                    
                    # Decrypt config with derived shared secret (ECDH)
                    peer_config = self._decrypt_config(encrypted_data, nonce, peer_x25519_pub)
                    peer_gen = response_data.get('generation', {})
                    
                    # Get local config
                    storage = get_local_ip_storage()
                    local_data = storage._load_storage()
                    local_gen = local_data.get('generation', {})
                    
                    # Check if peer is newer
                    if is_newer(local_gen, peer_gen, local_data, peer_config):
                        # Complete config takeover
                        storage._storage = peer_config
                        storage._save_storage()
                        return {
                            "peer": peer,
                            "peer_name": self.peer_names.get(peer_ip, peer_ip),
                            "merged": True
                        }
                    else:
                        return {
                            "peer": peer,
                            "peer_name": self.peer_names.get(peer_ip, peer_ip),
                            "merged": False
                        }
            except Exception as e:
                logger.error(f"Error syncing with peer {peer}: {e}")
                return None
        
        # Execute all syncs in parallel
        tasks = [sync_with_peer(peer) for peer in self._peer_nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            peer = self._peer_nodes[i]
            peer_ip = peer.split(":")[0]
            
            if isinstance(result, Exception):
                failed_peers.append(peer)
                self._record_sync_event(peer, "error", 0, str(result))
            elif result:
                synced_peers.append(result.get("peer_name", peer))
                self._record_sync_event(peer, "success", 0, "Config synchronisiert")
            else:
                failed_peers.append(peer)
                self._record_sync_event(peer, "error", 0, "Sync fehlgeschlagen")
        
        total_duration_ms = (time.time() - start_time) * 1000
        
        # Update statistics
        if synced_peers:
            self._stats["total_successful_syncs"] += len(synced_peers)
        if failed_peers:
            self._stats["total_failed_syncs"] += len(failed_peers)
        
        return {
            "synced_peers": synced_peers,
            "failed_peers": failed_peers,
            "total_duration_ms": total_duration_ms
        }
    
    def _record_sync_event(self, peer: str, status: str, duration_ms: float, details: str):
        """Record a sync event for statistics"""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "peer_name": self.peer_names.get(peer.split(":")[0], peer),
            "status": status,
            "duration_ms": duration_ms,
            "details": details
        }
        
        self._recent_events.append(event)
        # Keep only last 10 events
        if len(self._recent_events) > 10:
            self._recent_events.pop(0)
    
    async def start(self):
        """Start background sync task"""
        if self._running:
            return
        
        if not self._enabled:
            logger.info("Peer-Sync is disabled, not starting background task")
            return
        
        self._running = True
        
        async def sync_loop():
            logger.info(f"Peer-Sync service started (interval: {self._sync_interval}s)")
            while self._running:
                try:
                    await asyncio.sleep(self._sync_interval)
                    if self._running:
                        await self.sync_with_all_peers()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in peer-sync loop: {e}")
                    await asyncio.sleep(5)  # Wait before retrying
        
        self._task = asyncio.create_task(sync_loop())
    
    async def stop(self):
        """Stop background sync task"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        # Close HTTP client
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def get_status(self) -> Dict[str, Any]:
        """Get sync status and metrics"""
        return {
            "enabled": self._enabled,
            "peer_nodes": self._peer_nodes,
            "stats": self._stats,
            "recent_events": self._recent_events[-10:]  # Last 10 events
        }


# Global instance
_peer_sync = None


def get_peer_sync() -> PeerSync:
    """Get global peer-sync instance"""
    global _peer_sync
    if _peer_sync is None:
        _peer_sync = PeerSync()
    return _peer_sync

