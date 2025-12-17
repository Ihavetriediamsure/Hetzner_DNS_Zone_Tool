"""Two-Factor Authentication (2FA) module using TOTP"""

import os
import pyotp
import qrcode
import io
import base64
import secrets
from typing import Optional, List
from pathlib import Path
import yaml
from src.encryption import get_encryption_manager


class TwoFactorAuth:
    """TOTP-based Two-Factor Authentication"""
    
    def __init__(self, auth_file: Optional[str] = None, issuer: str = "Hetzner DNS Zone Tool"):
        if auth_file is None:
            auth_file = os.getenv("AUTH_FILE", "./config/auth.yaml")
        self.auth_file = Path(auth_file)
        self.issuer = issuer
        self._ensure_auth_file()
    
    def _ensure_auth_file(self):
        """Ensure auth file exists"""
        if not self.auth_file.exists():
            self.auth_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.auth_file, 'w') as f:
                yaml.dump({'users': {}}, f)
    
    def _load_auth_data(self) -> dict:
        """Load authentication data from file"""
        if not self.auth_file.exists():
            return {'users': {}}
        with open(self.auth_file, 'r') as f:
            return yaml.safe_load(f) or {'users': {}}
    
    def _save_auth_data(self, data: dict):
        """Save authentication data to file"""
        self.auth_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.auth_file, 'w') as f:
            yaml.dump(data, f)
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def get_qr_code(self, secret: str, username: str, issuer: Optional[str] = None) -> str:
        """Generate QR code for authenticator app setup"""
        if issuer is None:
            issuer = self.issuer
        
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    def is_2fa_enabled(self, username: str) -> bool:
        """Check if 2FA is enabled for user"""
        data = self._load_auth_data()
        user = data.get('users', {}).get(username, {})
        two_factor = user.get('two_factor', {})
        return two_factor.get('enabled', False)
    
    def setup_2fa_secret(self, username: str, secret: str):
        """Setup 2FA secret (but don't enable it yet - requires verification first)"""
        data = self._load_auth_data()
        if 'users' not in data:
            data['users'] = {}
        if username not in data['users']:
            data['users'][username] = {}
        
        # Encrypt secret
        encryption = get_encryption_manager()
        encrypted_secret = encryption.encrypt_token(secret)
        
        data['users'][username]['two_factor'] = {
            'enabled': False,  # Not enabled until verified
            'secret': f'encrypted:{encrypted_secret}',
            'backup_codes': []
        }
        
        self._save_auth_data(data)
    
    def enable_2fa(self, username: str, secret: str, backup_codes: Optional[List[str]] = None):
        """Enable 2FA for user (backup codes are optional and not auto-generated)"""
        data = self._load_auth_data()
        if 'users' not in data:
            data['users'] = {}
        if username not in data['users']:
            data['users'][username] = {}
        
        # Encrypt secret
        encryption = get_encryption_manager()
        encrypted_secret = encryption.encrypt_token(secret)
        
        # Encrypt backup codes if provided, otherwise use empty list
        # Always store with 'encrypted:' prefix for consistency
        if backup_codes is None:
            encrypted_backup_codes = []
        else:
            encrypted_backup_codes = [f'encrypted:{encryption.encrypt_token(code)}' for code in backup_codes]
        
        data['users'][username]['two_factor'] = {
            'enabled': True,
            'secret': f'encrypted:{encrypted_secret}',
            'backup_codes': encrypted_backup_codes
        }
        
        self._save_auth_data(data)
    
    def disable_2fa(self, username: str):
        """Disable 2FA for user"""
        data = self._load_auth_data()
        if username in data.get('users', {}):
            if 'two_factor' in data['users'][username]:
                data['users'][username]['two_factor']['enabled'] = False
                self._save_auth_data(data)
    
    def get_secret(self, username: str) -> Optional[str]:
        """Get 2FA secret for user (decrypted)"""
        data = self._load_auth_data()
        user = data.get('users', {}).get(username, {})
        two_factor = user.get('two_factor', {})
        secret = two_factor.get('secret')
        
        if not secret:
            return None
        
        # Check if encrypted
        if secret.startswith('encrypted:'):
            try:
                encryption = get_encryption_manager()
                encrypted_part = secret.replace('encrypted:', '')
                return encryption.decrypt_token(encrypted_part)
            except Exception:
                # If decryption fails, try to read as plaintext (backward compatibility)
                return secret
        else:
            # Plaintext (backward compatibility - migrate on next save)
            return secret
    
    def get_backup_codes(self, username: str) -> List[str]:
        """Get backup codes for user (decrypted)"""
        data = self._load_auth_data()
        user = data.get('users', {}).get(username, {})
        two_factor = user.get('two_factor', {})
        backup_codes = two_factor.get('backup_codes', [])
        
        if not backup_codes:
            return []
        
        # Check if encrypted (first code is a string starting with encrypted:)
        if backup_codes and isinstance(backup_codes[0], str) and backup_codes[0].startswith('encrypted:'):
            try:
                encryption = get_encryption_manager()
                decrypted = []
                for code in backup_codes:
                    encrypted_part = code.replace('encrypted:', '')
                    decrypted.append(encryption.decrypt_token(encrypted_part))
                return decrypted
            except Exception:
                # If decryption fails, return as-is (backward compatibility)
                return backup_codes
        else:
            # Plaintext (backward compatibility)
            return backup_codes
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes (32 characters each, mixed case alphanumeric)"""
        codes = []
        # Use alphanumeric characters (a-z, A-Z, 0-9) excluding ambiguous characters (0, O, I, l)
        chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789'
        for _ in range(count):
            # Generate 32-character alphanumeric code with mixed case
            code = ''.join(secrets.choice(chars) for _ in range(32))
            codes.append(code)
        return codes
    
    def verify_backup_code(self, username: str, code: str) -> bool:
        """Verify and consume backup code"""
        data = self._load_auth_data()
        user = data.get('users', {}).get(username, {})
        two_factor = user.get('two_factor', {})
        backup_codes = two_factor.get('backup_codes', [])
        
        if not backup_codes:
            return False
        
        encryption = get_encryption_manager()
        code_normalized = code.strip()  # Remove whitespace, keep case for mixed case codes
        
        # Check encrypted codes
        for i, encrypted_code in enumerate(backup_codes):
            try:
                if encrypted_code.startswith('encrypted:'):
                    # Code has explicit encrypted: prefix
                    decrypted = encryption.decrypt_token(encrypted_code.replace('encrypted:', ''))
                else:
                    # Try to decrypt (codes are stored encrypted without prefix)
                    # If decryption fails, treat as plaintext (backward compatibility)
                    try:
                        decrypted = encryption.decrypt_token(encrypted_code)
                    except Exception:
                        # Decryption failed, assume plaintext
                        decrypted = encrypted_code
                
                # Check if decrypted value is itself encrypted (double encryption - migration issue)
                # If it looks like an encrypted value (base64, long string), try to decrypt again
                if len(decrypted) > 50 and not decrypted.startswith('encrypted:'):
                    try:
                        # Try to decrypt again (might be double encrypted)
                        decrypted = encryption.decrypt_token(decrypted)
                    except Exception:
                        # Not double encrypted, use as-is
                        pass
                
                # Compare case-sensitive (since we now use mixed case)
                if decrypted == code_normalized:
                    # Remove used backup code
                    backup_codes.pop(i)
                    # Re-encrypt remaining codes (always with 'encrypted:' prefix for consistency)
                    # Migrate codes: decrypt if double-encrypted, then re-encrypt properly
                    migrated_codes = []
                    for c in backup_codes:
                        if c.startswith('encrypted:'):
                            # Already has prefix, but might be double-encrypted
                            encrypted_part = c.replace('encrypted:', '')
                            try:
                                decrypted_code = encryption.decrypt_token(encrypted_part)
                                # Check if decrypted value is itself encrypted (double encryption)
                                if len(decrypted_code) > 50:
                                    # Double encrypted - decrypt again to get plaintext
                                    try:
                                        plaintext = encryption.decrypt_token(decrypted_code)
                                        # Re-encrypt properly (single encryption)
                                        migrated_codes.append(f'encrypted:{encryption.encrypt_token(plaintext)}')
                                    except Exception:
                                        # Not double encrypted, re-encrypt as-is
                                        migrated_codes.append(f'encrypted:{encryption.encrypt_token(decrypted_code)}')
                                else:
                                    # Single encrypted, re-encrypt properly
                                    migrated_codes.append(f'encrypted:{encryption.encrypt_token(decrypted_code)}')
                            except Exception:
                                # Can't decrypt, keep as-is
                                migrated_codes.append(c)
                        else:
                            # No prefix - might be plaintext or encrypted without prefix
                            try:
                                # Try to decrypt (might be encrypted without prefix)
                                decrypted_code = encryption.decrypt_token(c)
                                # Check if double encrypted
                                if len(decrypted_code) > 50:
                                    try:
                                        plaintext = encryption.decrypt_token(decrypted_code)
                                        migrated_codes.append(f'encrypted:{encryption.encrypt_token(plaintext)}')
                                    except Exception:
                                        migrated_codes.append(f'encrypted:{encryption.encrypt_token(decrypted_code)}')
                                else:
                                    migrated_codes.append(f'encrypted:{encryption.encrypt_token(decrypted_code)}')
                            except Exception:
                                # Plaintext, encrypt it
                                migrated_codes.append(f'encrypted:{encryption.encrypt_token(c)}')
                    
                    two_factor['backup_codes'] = migrated_codes
                    self._save_auth_data(data)
                    return True
            except Exception:
                continue
        
        return False


# Global instance
_two_factor_auth = None


def get_two_factor_auth(auth_file: Optional[str] = None, issuer: str = "Hetzner DNS Zone Tool") -> TwoFactorAuth:
    """Get global 2FA instance"""
    global _two_factor_auth
    if _two_factor_auth is None:
        if auth_file is None:
            auth_file = os.getenv("AUTH_FILE", "./config/auth.yaml")
        _two_factor_auth = TwoFactorAuth(auth_file, issuer)
    return _two_factor_auth

