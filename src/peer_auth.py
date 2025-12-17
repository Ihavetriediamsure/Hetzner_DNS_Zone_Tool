"""Peer Authentication with X25519 Public Key (WireGuard-style)"""

import base64
import hashlib
import hmac
import logging
from typing import Optional, Tuple
from fastapi import Request, HTTPException, Header
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


async def verify_peer_signature(
    request: Request,
    peer_public_key_b64: Optional[str] = Header(None, alias="X-Peer-Public-Key"),
    signature_b64: Optional[str] = Header(None, alias="X-Peer-Signature")
) -> Tuple[x25519.X25519PublicKey, str]:
    """
    Verify HMAC-SHA256 signature from peer using X25519 public key
    
    Returns:
        Tuple of (peer_x25519_public_key, peer_ip)
    
    Raises:
        HTTPException if signature verification fails
    """
    if not peer_public_key_b64 or not signature_b64:
        raise HTTPException(status_code=403, detail="Missing peer authentication headers")
    
    try:
        # Decode X25519 public key (WireGuard format: 32 bytes raw)
        try:
            raw_bytes = base64.b64decode(peer_public_key_b64)
            if len(raw_bytes) == 32:
                # WireGuard format: 32 bytes raw
                peer_public_key = x25519.X25519PublicKey.from_public_bytes(raw_bytes)
            else:
                raise ValueError("Invalid key length")
        except Exception:
            # Fallback: Try PEM format (for migration)
            peer_public_key_bytes = base64.b64decode(peer_public_key_b64)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
            if not isinstance(peer_public_key, x25519.X25519PublicKey):
                raise ValueError("Invalid X25519 public key type")
        
        # Get client IP (WireGuard IP)
        client_ip = request.client.host if request.client else None
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        # Build message to verify
        method = request.method
        url_path = str(request.url.path)
        query_string = str(request.url.query)
        full_url = f"{url_path}?{query_string}" if query_string else url_path
        
        # For GET requests, verify signature of URL
        # For POST requests, verify signature of body hash
        if method == "GET":
            message = f"{method}:{full_url}".encode()
        else:
            # For POST, we need to get body hash
            body = b""
            if hasattr(request, '_body'):
                body = request._body
            elif hasattr(request, 'body'):
                try:
                    if not hasattr(request.state, '_body'):
                        body = await request.body()
                        request.state._body = body
                    else:
                        body = request.state._body
                except:
                    body = b""
            
            body_hash = hashlib.sha256(body).hexdigest()
            message = f"{method}:{full_url}:{body_hash}".encode()
        
        # Verify HMAC-SHA256 signature using peer's public key
        try:
            signature = base64.b64decode(signature_b64)
            peer_public_key_bytes_raw = peer_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            expected_signature = hmac.new(peer_public_key_bytes_raw, message, hashlib.sha256).digest()
            
            if not hmac.compare_digest(expected_signature, signature):
                raise HTTPException(status_code=403, detail="Invalid signature")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            raise HTTPException(status_code=403, detail="Invalid signature")
        
        # Verify peer is in our config
        from src.config_manager import get_config_manager
        config_manager = get_config_manager()
        config = config_manager.load_config()
        peer_sync_config = config.get('peer_sync', {})
        peer_public_keys_config = peer_sync_config.get('peer_public_keys', {})
        
        # Check if we have this peer's public key configured
        peer_found = False
        peer_ip = client_ip or "unknown"
        
        for config_peer_ip, peer_data in peer_public_keys_config.items():
            config_peer_public_key_b64 = peer_data.get('public_key', '')
            if config_peer_public_key_b64 == peer_public_key_b64:
                peer_found = True
                peer_ip = config_peer_ip
                break
        
        if not peer_found:
            # Allow if peer is in peer_nodes (for initial setup)
            if client_ip and client_ip in [p.split(":")[0] for p in peer_sync_config.get('peer_nodes', [])]:
                peer_found = True
                peer_ip = client_ip
        
        if not peer_found:
            logger.warning(f"Peer not found in config: {client_ip}")
            raise HTTPException(status_code=403, detail="Peer not authorized")
        
        return peer_public_key, peer_ip
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Peer authentication error: {e}")
        raise HTTPException(status_code=403, detail=f"Authentication failed: {str(e)}")


async def verify_peer_signature_for_body(
    request: Request,
    body_data: bytes,
    peer_public_key: x25519.X25519PublicKey,
    signature_b64: str
) -> bool:
    """
    Verify HMAC-SHA256 signature for request body (for POST requests with encrypted data)
    
    Args:
        request: FastAPI request object
        body_data: Request body bytes
        peer_public_key: Peer's X25519 public key
        signature_b64: Base64-encoded signature
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Build message: encrypted_data:nonce
        body_hash = hashlib.sha256(body_data).hexdigest()
        message = f"POST:{request.url.path}:{body_hash}".encode()
        
        signature = base64.b64decode(signature_b64)
        peer_public_key_bytes_raw = peer_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        expected_signature = hmac.new(peer_public_key_bytes_raw, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected_signature, signature)
    except Exception as e:
        logger.warning(f"Body signature verification failed: {e}")
        return False
