"""Encryption module for API token storage"""

import os
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


class EncryptionManager:
    """Manages encryption/decryption of sensitive data"""
    
    def __init__(self, key_path: Optional[str] = None):
        if key_path is None:
            # Priority: Environment variable > /config (Docker) > ~/.hetzner-dns (local)
            key_path = os.getenv("ENCRYPTION_KEY_PATH")
            if not key_path:
                if os.path.exists('/config'):
                    key_path = '/config/.encryption_key'
                else:
                    key_path = os.path.expanduser('~/.hetzner-dns/.encryption_key')
        self.key_path = Path(key_path)
        self._fernet = None
    
    def _get_or_create_key(self) -> bytes:
        """Get existing key or create a new one"""
        # Try to read existing key
        if self.key_path.exists():
            try:
                with open(self.key_path, 'rb') as f:
                    return f.read()
            except (PermissionError, OSError):
                # Try alternative path
                alt_path = Path.home() / ".hetzner-dns" / ".encryption_key"
                if alt_path.exists():
                    try:
                        with open(alt_path, 'rb') as f:
                            # Update path for future use
                            self.key_path = alt_path
                            return f.read()
                    except Exception:
                        pass
                # If we can't read existing key, switch to alt path for generation
                self.key_path = alt_path
        
        # Generate new key (either doesn't exist or couldn't read)
        key = Fernet.generate_key()
        try:
            # Ensure directory exists
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            # Save key
            with open(self.key_path, 'wb') as f:
                f.write(key)
            # Set restrictive permissions (Unix only)
            if os.name != 'nt':
                os.chmod(self.key_path, 0o600)
        except (PermissionError, OSError):
            # Try alternative path in user's home directory
            alt_path = Path.home() / ".hetzner-dns" / ".encryption_key"
            alt_path.parent.mkdir(parents=True, exist_ok=True)
            with open(alt_path, 'wb') as f:
                f.write(key)
            if os.name != 'nt':
                os.chmod(alt_path, 0o600)
            # Update path for future use
            self.key_path = alt_path
        return key
    
    def _get_fernet(self) -> Fernet:
        """Get Fernet instance with loaded key"""
        if self._fernet is None:
            key = self._get_or_create_key()
            self._fernet = Fernet(key)
        return self._fernet
    
    def encrypt_token(self, token: str) -> str:
        """Encrypt a token string"""
        fernet = self._get_fernet()
        encrypted = fernet.encrypt(token.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt an encrypted token string"""
        fernet = self._get_fernet()
        try:
            encrypted_bytes = base64.b64decode(encrypted_token.encode('utf-8'))
            decrypted = fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decrypt token: {str(e)}")
    
    def generate_key(self) -> bytes:
        """Generate a new encryption key"""
        key = Fernet.generate_key()
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.key_path, 'wb') as f:
            f.write(key)
        if os.name != 'nt':
            os.chmod(self.key_path, 0o600)
        # Reset fernet instance to use new key
        self._fernet = None
        return key
    
    def load_key(self) -> bytes:
        """Load encryption key from file"""
        return self._get_or_create_key()


# Global instance
_encryption_manager = None


def get_encryption_manager(key_path: Optional[str] = None) -> EncryptionManager:
    """Get global encryption manager instance"""
    global _encryption_manager
    if _encryption_manager is None:
        if key_path is None:
            # Priority: Environment variable > /config (Docker) > ~/.hetzner-dns (local)
            key_path = os.getenv("ENCRYPTION_KEY_PATH")
            if not key_path:
                if os.path.exists('/config'):
                    key_path = '/config/.encryption_key'
                else:
                    key_path = os.path.expanduser('~/.hetzner-dns/.encryption_key')
        _encryption_manager = EncryptionManager(key_path)
    return _encryption_manager
