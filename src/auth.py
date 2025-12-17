"""Authentication module for WebGUI"""

import os
import bcrypt
import yaml
import re
from pathlib import Path
from typing import Optional
from src.two_factor import get_two_factor_auth


class AuthManager:
    """Manages user authentication and sessions"""
    
    def __init__(self, auth_file: Optional[str] = None):
        if auth_file is None:
            auth_file = os.getenv("AUTH_FILE", "./config/auth.yaml")
        self.auth_file = Path(auth_file)
        self._ensure_auth_file()
    
    def _ensure_auth_file(self):
        """Ensure auth file directory exists, but don't create default user"""
        # Only create directory, don't create default user (setup required)
        if not self.auth_file.parent.exists():
            self.auth_file.parent.mkdir(parents=True, exist_ok=True)
    
    def needs_setup(self) -> bool:
        """Check if initial setup is required (no auth file exists)"""
        return not self.auth_file.exists()
    
    def _validate_username(self, username: str) -> None:
        """Validate username against forbidden names"""
        if not username or not username.strip():
            raise ValueError("Username is required")
        
        username_lower = username.lower().strip()
        
        # Forbidden usernames (case-insensitive)
        forbidden_names = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest',
            'system', 'service', 'daemon', 'nobody', 'www', 'http',
            'mail', 'postmaster', 'noreply', 'support', 'help', 'info'
        ]
        
        # Check exact match
        if username_lower in forbidden_names:
            raise ValueError(f"Username '{username}' is not allowed. Please choose a different username.")
        
        # Check if username contains forbidden names
        for forbidden in forbidden_names:
            if forbidden in username_lower:
                raise ValueError(f"Username cannot contain '{forbidden}'. Please choose a different username.")
    
    def _validate_password(self, password: str) -> None:
        """Validate password strength"""
        if not password:
            raise ValueError("Password is required")
        
        # Minimum length: 12 characters
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long")
        
        # Must contain at least one digit
        if not re.search(r'\d', password):
            raise ValueError("Password must contain at least one number")
        
        # Must contain at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter")
        
        # Must contain at least one special character
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
            raise ValueError("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?)")
    
    def create_initial_user(self, username: str, password: str) -> bool:
        """Create initial admin user during setup"""
        if not self.needs_setup():
            return False  # Setup already completed
        
        # Validate username
        self._validate_username(username)
        
        # Validate password
        self._validate_password(password)
        
        password_hash = self.hash_password(password)
        
        auth_data = {
                    'users': {
                username: {
                    'password_hash': password_hash,
                            'two_factor': {
                                'enabled': False,
                                'secret': None,
                                'backup_codes': []
                            }
                        }
                    }
        }
        
        # Ensure directory exists
        self.auth_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Write auth file
        with open(self.auth_file, 'w') as f:
            yaml.dump(auth_data, f)
        
        # Set restrictive permissions (Unix only)
        try:
            os.chmod(self.auth_file, 0o600)
        except (OSError, AttributeError):
            pass  # Windows doesn't support chmod
        
        return True
    
    def _load_auth_data(self) -> dict:
        """Load authentication data from file"""
        if not self.auth_file.exists():
            raise FileNotFoundError("Auth file does not exist. Initial setup required.")
        
        try:
            with open(self.auth_file, 'r') as f:
                data = yaml.safe_load(f)
                if not data:
                    return {'users': {}}
                if 'users' not in data:
                    data['users'] = {}
                # Ensure all users have proper structure
                for username, user_data in data.get('users', {}).items():
                    if 'two_factor' not in user_data:
                        user_data['two_factor'] = {'enabled': False, 'secret': None, 'backup_codes': []}
                    elif not isinstance(user_data['two_factor'], dict):
                        user_data['two_factor'] = {'enabled': False, 'secret': None, 'backup_codes': []}
                    else:
                        if 'secret' not in user_data['two_factor']:
                            user_data['two_factor']['secret'] = None
                        if 'backup_codes' not in user_data['two_factor']:
                            user_data['two_factor']['backup_codes'] = []
                return data
        except Exception as e:
            # If file is corrupted, recreate it
            self._ensure_auth_file()
        with open(self.auth_file, 'r') as f:
            return yaml.safe_load(f) or {'users': {}}
    
    def _save_auth_data(self, data: dict):
        """Save authentication data to file"""
        self.auth_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Try to write to a temporary file first, then rename (atomic write)
            temp_file = self.auth_file.with_suffix('.yaml.tmp')
            with open(temp_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
            # Atomic rename
            temp_file.replace(self.auth_file)
        except PermissionError as e:
            raise IOError(f"Permission denied: Cannot write to {self.auth_file}. Please check file permissions or use AUTH_FILE environment variable to specify a writable location.")
        except Exception as e:
            raise IOError(f"Failed to save auth data to {self.auth_file}: {str(e)}")
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify password for a user"""
        auth_data = self._load_auth_data()
        user = auth_data.get('users', {}).get(username)
        
        if not user:
            return False
        
        password_hash = user.get('password_hash', '')
        if not password_hash:
            return False
        
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def is_2fa_enabled(self, username: str) -> bool:
        """Check if 2FA is enabled for a user"""
        auth_data = self._load_auth_data()
        user = auth_data.get('users', {}).get(username)
        if not user:
            return False
        
        two_factor = user.get('two_factor', {})
        return two_factor.get('enabled', False)
    
    def verify_2fa(self, username: str, token: str) -> bool:
        """Verify 2FA token for a user"""
        auth_data = self._load_auth_data()
        user = auth_data.get('users', {}).get(username)
        if not user:
            return False
        
        two_factor = user.get('two_factor', {})
        if not two_factor.get('enabled', False):
            return True  # 2FA not enabled, skip verification
        
        secret = two_factor.get('secret')
        if not secret:
            return False
        
        # Decrypt secret if encrypted
        if secret.startswith('encrypted:'):
            try:
                from src.encryption import get_encryption_manager
                encryption = get_encryption_manager()
                encrypted_part = secret.replace('encrypted:', '')
                secret = encryption.decrypt_token(encrypted_part)
            except Exception:
                # If decryption fails, use as-is (backward compatibility)
                pass
        
        two_factor_auth = get_two_factor_auth()
        token_stripped = token.strip()
        
        # Check if token looks like a backup code (32 characters, alphanumeric)
        # Backup codes are 32 characters, TOTP tokens are 6 digits
        is_likely_backup_code = len(token_stripped) == 32 and token_stripped.isalnum()
        is_likely_totp = len(token_stripped) == 6 and token_stripped.isdigit()
        
        # If it's clearly a backup code (32 chars), try backup code directly
        if is_likely_backup_code:
            if two_factor_auth.verify_backup_code(username, token):
                return True
            return False  # Backup code failed, don't try TOTP
        
        # Standard: Always try TOTP first (2FA is the default)
        # This applies to 6-digit codes and unknown formats
        try:
            if two_factor_auth.verify_totp(secret, token):
                return True
        except Exception:
            # If TOTP verification fails with exception, continue to backup code
            pass
        
        # If TOTP fails, try backup code as fallback
        # This allows user to use backup code if 2FA fails
        if two_factor_auth.verify_backup_code(username, token):
            return True
        
        return False
    
    def change_password(self, username: str, new_password: str):
        """Change password for a user"""
        # Validate password strength
        self._validate_password(new_password)
        
        auth_data = self._load_auth_data()
        if not auth_data:
            auth_data = {}
        if not auth_data.get('users'):
            auth_data['users'] = {}
        
        if username not in auth_data.get('users', {}):
            raise ValueError(f"User {username} not found")
        
        # Ensure user has all required fields
        if 'two_factor' not in auth_data['users'][username]:
            auth_data['users'][username]['two_factor'] = {
                'enabled': False,
                'secret': None,
                'backup_codes': []
            }
        
        try:
            new_hash = self.hash_password(new_password)
            auth_data['users'][username]['password_hash'] = new_hash
            self._save_auth_data(auth_data)
        except IOError as e:
            raise IOError(f"Failed to save password: {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to change password: {str(e)}")


# Global instance
_auth_manager = None


def get_auth_manager(auth_file: Optional[str] = None) -> AuthManager:
    """Get global auth manager instance"""
    global _auth_manager
    if _auth_manager is None:
        if auth_file is None:
            auth_file = os.getenv("AUTH_FILE", "./config/auth.yaml")
        _auth_manager = AuthManager(auth_file)
    return _auth_manager

