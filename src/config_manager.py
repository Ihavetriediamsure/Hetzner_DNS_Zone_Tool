"""Configuration Manager for Hetzner DNS Client"""

import os
import yaml
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, List
from src.encryption import get_encryption_manager


class ConfigManager:
    """Manages application configuration"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            # Priority: Environment variable > /config (Docker) > ~/.hetzner-dns (local)
            config_path = os.getenv('CONFIG_PATH')
            if not config_path:
                if os.path.exists('/config'):
                    config_path = '/config/config.yaml'
                else:
                    config_path = os.path.expanduser('~/.hetzner-dns/config.yaml')
        self.config_path = Path(config_path)
        self._config: Optional[Dict[str, Any]] = None
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if self._config is not None:
            return self._config
        
        if self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f) or {}
        else:
            self._config = self._default_config()
            self.save_config()
        
        return self._config
    
    def save_config(self) -> None:
        """Save configuration to YAML file"""
        if self._config is None:
            self._config = self._default_config()
        
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._config, f, default_flow_style=False, allow_unicode=True)
        except PermissionError:
            # Try alternative path in user's home directory
            import os
            home_config = Path.home() / ".hetzner-dns" / "config.yaml"
            home_config.parent.mkdir(parents=True, exist_ok=True)
            with open(home_config, 'w', encoding='utf-8') as f:
                yaml.dump(self._config, f, default_flow_style=False, allow_unicode=True)
            # Update path for future use
            self.config_path = home_config
    
    def get_api_token(self, api_type: str = 'new') -> Optional[str]:
        """Get decrypted API token"""
        config = self.load_config()
        token_encrypted = config.get('api', {}).get(f'{api_type}_api', {}).get('token', '')
        
        if not token_encrypted or not token_encrypted.startswith('encrypted:'):
            return None
        
        encrypted_part = token_encrypted.replace('encrypted:', '')
        encryption = get_encryption_manager()
        try:
            return encryption.decrypt_token(encrypted_part)
        except Exception:
            return None
    
    def set_api_token(self, token: str, api_type: str = 'new', base_url: Optional[str] = None, name: Optional[str] = None) -> None:
        """Set encrypted API token"""
        config = self.load_config()
        
        if 'api' not in config:
            config['api'] = {}
        
        api_key = f'{api_type}_api'
        if api_key not in config['api']:
            config['api'][api_key] = {}
        
        encryption = get_encryption_manager()
        encrypted_token = encryption.encrypt_token(token)
        config['api'][api_key]['token'] = f'encrypted:{encrypted_token}'
        
        if base_url:
            config['api'][api_key]['base_url'] = base_url
        
        if name:
            config['api'][api_key]['name'] = name
        
        self._config = config
        self.save_config()
    
    def delete_api_token(self, api_type: str = 'new') -> None:
        """Delete API token"""
        config = self.load_config()
        
        if 'api' not in config:
            return
        
        api_key = f'{api_type}_api'
        if api_key in config['api']:
            config['api'][api_key]['token'] = ''
            config['api'][api_key].pop('name', None)
        
        self._config = config
        self.save_config()
    
    def get_api_token_info(self, api_type: str = 'new') -> Dict[str, Any]:
        """Get API token information (name, masked token)"""
        config = self.load_config()
        api_config = config.get('api', {}).get(f'{api_type}_api', {})
        
        token_encrypted = api_config.get('token', '')
        token_set = bool(token_encrypted and token_encrypted.startswith('encrypted:'))
        
        result = {
            'token_set': token_set,
            'name': api_config.get('name', ''),
            'base_url': api_config.get('base_url', ''),
            'masked_token': ''
        }
        
        # Mask token if set
        if token_set:
            try:
                token = self.get_api_token(api_type)
                if token:
                    # Show first 4 and last 4 characters, mask the rest
                    if len(token) > 8:
                        masked = token[:4] + '*' * (len(token) - 8) + token[-4:]
                    else:
                        masked = '*' * len(token)
                    result['masked_token'] = masked
                else:
                    result['masked_token'] = '***'
            except Exception as e:
                result['masked_token'] = '***'
        
        return result
    
    def generate_session_secret(self) -> str:
        """
        Generate a secure random session secret.
        
        SECURITY: This method never logs the secret or any part of it.
        The secret is only returned and stored in config.yaml.
        """
        import secrets
        # Generate 64-character hex string (32 bytes = 256 bits)
        # SECURITY: Return value is never logged - only used internally
        return secrets.token_hex(32)
    
    def ensure_session_secret(self) -> str:
        """Ensure a session secret exists in config, generate if missing"""
        config = self.load_config()
        session_secret = config.get('server', {}).get('session_secret', '').strip()
        
        # If no secret in config, generate and save one
        if not session_secret:
            session_secret = self.generate_session_secret()
            if 'server' not in config:
                config['server'] = {}
            config['server']['session_secret'] = session_secret
            self._config = config
            self.save_config()
            # SECURITY: Never log the secret itself, only confirm generation
            logger = __import__('logging').getLogger(__name__)
            logger.info("SESSION_SECRET generated and persisted to config")
        
        return session_secret
    
    def get_session_secret(self) -> str:
        """Get session secret from config or environment variable"""
        # Priority 1: Environment variable (for Docker .env or manual override)
        env_secret = os.getenv('SESSION_SECRET', '').strip()
        if env_secret:
            return env_secret
        
        # Priority 2: Config file (auto-generated if missing)
        config = self.load_config()
        session_secret = config.get('server', {}).get('session_secret', '').strip()
        
        if session_secret:
            return session_secret
        
        # Priority 3: Auto-generate and save to config (first run)
        return self.ensure_session_secret()
    
    def get_api_base_url(self, api_type: str = 'new') -> str:
        """Get API base URL"""
        config = self.load_config()
        base_url = config.get('api', {}).get(f'{api_type}_api', {}).get('base_url', '')
        
        if api_type == 'new' and not base_url:
            return 'https://api.hetzner.cloud/v1'
        elif api_type == 'old' and not base_url:
            return 'https://dns.hetzner.com/api'
        
        return base_url
    
    def _migrate_old_tokens(self) -> None:
        """Migrate old token structure to new multi-token structure"""
        config = self.load_config()
        api_config = config.get('api', {})
        
        # Check if already migrated
        if 'tokens' in api_config:
            return
        
        # Initialize tokens list
        api_config['tokens'] = []
        
        # Migrate new_api token if exists
        new_api = api_config.get('new_api', {})
        if new_api.get('token') and new_api['token'].startswith('encrypted:'):
            token_id = str(uuid.uuid4())
            api_config['tokens'].append({
                'id': token_id,
                'name': new_api.get('name', 'New Hetzner Console Token'),
                'token': new_api['token'],
                'base_url': new_api.get('base_url', 'https://api.hetzner.cloud/v1'),
                'type': 'new',
                'created_at': None
            })
        
        self._config = config
        self.save_config()
    
    def get_all_tokens(self) -> List[Dict[str, Any]]:
        """Get all API tokens"""
        self._migrate_old_tokens()
        config = self.load_config()
        tokens = config.get('api', {}).get('tokens', [])
        
        result = []
        encryption = get_encryption_manager()
        
        for token_config in tokens:
            token_encrypted = token_config.get('token', '')
            if not token_encrypted or not token_encrypted.startswith('encrypted:'):
                continue
            
            try:
                encrypted_part = token_encrypted.replace('encrypted:', '')
                token = encryption.decrypt_token(encrypted_part)
                
                # Mask token
                if len(token) > 8:
                    masked = token[:4] + '*' * (len(token) - 8) + token[-4:]
                else:
                    masked = '*' * len(token)
                
                result.append({
                    'id': token_config.get('id'),
                    'name': token_config.get('name', ''),
                    'masked_token': masked,
                    'base_url': token_config.get('base_url', ''),
                    'type': token_config.get('type', 'new'),
                    'created_at': token_config.get('created_at')
                })
            except Exception:
                continue
        
        return result
    
    def get_token_by_id(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Get token by ID"""
        self._migrate_old_tokens()
        config = self.load_config()
        tokens = config.get('api', {}).get('tokens', [])
        
        for token_config in tokens:
            if token_config.get('id') == token_id:
                token_encrypted = token_config.get('token', '')
                if not token_encrypted or not token_encrypted.startswith('encrypted:'):
                    return None
                
                encryption = get_encryption_manager()
                try:
                    encrypted_part = token_encrypted.replace('encrypted:', '')
                    token = encryption.decrypt_token(encrypted_part)
                    
                    return {
                        'id': token_config.get('id'),
                        'name': token_config.get('name', ''),
                        'token': token,
                        'base_url': token_config.get('base_url', ''),
                        'type': token_config.get('type', 'new')
                    }
                except Exception:
                    return None
        
        return None
    
    def add_token(self, token: str, name: str, api_type: str = 'new', base_url: Optional[str] = None) -> str:
        """Add a new API token and return its ID"""
        self._migrate_old_tokens()
        config = self.load_config()
        
        if 'api' not in config:
            config['api'] = {}
        if 'tokens' not in config['api']:
            config['api']['tokens'] = []
        
        # Set default base_url if not provided
        if not base_url:
            if api_type == 'new':
                base_url = 'https://api.hetzner.cloud/v1'
            else:
                base_url = 'https://dns.hetzner.com/api'
        
        # Encrypt token
        encryption = get_encryption_manager()
        encrypted_token = encryption.encrypt_token(token)
        
        # Generate ID
        token_id = str(uuid.uuid4())
        
        # Add token
        from datetime import datetime
        token_config = {
            'id': token_id,
            'name': name,
            'token': f'encrypted:{encrypted_token}',
            'base_url': base_url,
            'type': api_type,
            'created_at': datetime.now().isoformat()
        }
        
        config['api']['tokens'].append(token_config)
        self._config = config
        self.save_config()
        
        return token_id
    
    def update_token(self, token_id: str, token: Optional[str] = None, name: Optional[str] = None, 
                     base_url: Optional[str] = None) -> bool:
        """Update an existing token"""
        self._migrate_old_tokens()
        config = self.load_config()
        tokens = config.get('api', {}).get('tokens', [])
        
        for token_config in tokens:
            if token_config.get('id') == token_id:
                if name is not None:
                    token_config['name'] = name
                if base_url is not None:
                    token_config['base_url'] = base_url
                if token is not None:
                    encryption = get_encryption_manager()
                    encrypted_token = encryption.encrypt_token(token)
                    token_config['token'] = f'encrypted:{encrypted_token}'
                
                self._config = config
                self.save_config()
                return True
        
        return False
    
    def delete_token(self, token_id: str) -> bool:
        """Delete a token by ID"""
        self._migrate_old_tokens()
        config = self.load_config()
        tokens = config.get('api', {}).get('tokens', [])
        
        # Remove token
        original_count = len(tokens)
        config['api']['tokens'] = [t for t in tokens if t.get('id') != token_id]
        
        if len(config['api']['tokens']) < original_count:
            self._config = config
            self.save_config()
            return True
        
        return False
    
    def get_token_for_zone(self, zone_id: str) -> Optional[str]:
        """Get token ID assigned to a zone, or default token if none assigned"""
        config = self.load_config()
        zone_tokens = config.get('zone_tokens', {})
        token_id = zone_tokens.get(zone_id)
        
        if token_id:
            token_data = self.get_token_by_id(token_id)
            if token_data:
                return token_data['token']
        
        # Fallback to first available token
        tokens = self.get_all_tokens()
        if tokens:
            token_data = self.get_token_by_id(tokens[0]['id'])
            if token_data:
                return token_data['token']
        
        return None
    
    def set_token_for_zone(self, zone_id: str, token_id: str) -> None:
        """Assign a token to a zone"""
        config = self.load_config()
        if 'zone_tokens' not in config:
            config['zone_tokens'] = {}
        config['zone_tokens'][zone_id] = token_id
        self._config = config
        self.save_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'api': {
                'new_api': {
                    'base_url': 'https://api.hetzner.cloud/v1',
                    'token': ''
                },
                'tokens': [],
                'version': 'auto'
            },
            'zone_tokens': {},
            'server': {
                'host': '0.0.0.0',  # Listen on all interfaces by default (access control via IP whitelist/blacklist)
                'port': 8000,
                'machine_name': '',  # Machine name for email notifications (e.g. "my server")
                'session_secret': ''  # Session secret for cookies (if empty, uses SESSION_SECRET env var or generates default)
            },
            'auth': {
                'username': 'admin',
                'password': ''
            },
            'security': {
                'ip_whitelist': {
                    'enabled': False,
                    'allowed_ips': []
                },
                'brute_force_protection': {
                    'enabled': False,  # Disabled by default on initial start
                    'max_login_attempts': 5,
                    'max_2fa_attempts': 3,
                    'lockout_duration_login': 900,  # 15 minutes in seconds
                    'lockout_duration_2fa': 300,  # 5 minutes in seconds
                    'window_duration': 600  # 10 minutes in seconds
                },
                'audit_log': {
                    'max_size_mb': 10,  # Maximum log file size in MB
                    'max_age_days': 30,  # Maximum age of logs in days
                    'rotation_interval_hours': 24  # Check for rotation every 24 hours
                },
                'smtp': {
                    'enabled': False,
                    'host': '',
                    'port': 587,
                    'user': '',
                    'password': '',
                    'use_tls': True,
                    'from_address': '',
                    'to_address': '',
                    'enabled_events': []
                }
            },
            'sync': {
                'auto_sync': False,
                'cache_path': os.getenv('SYNC_CACHE_PATH', './config/sync_data.json')
            },
            'peer_sync': {
                'enabled': False,
                'peer_nodes': [],
                'interval': 300,
                'timeout': 5,
                'max_retries': 3,
                'rate_limit': 1.0,
                'ntp_enabled': False,
                'peer_public_keys': {}  # peer_ip -> {name, public_key} (public_key is X25519 Base64 PEM)
            }
        }


# Global instance
_config_manager = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """Get global config manager instance"""
    global _config_manager
    # Always check environment variable first
    env_path = os.getenv('CONFIG_PATH')
    if env_path:
        env_path = os.path.expanduser(env_path) if env_path.startswith('~') else env_path
        # Reinitialize if path changed or not initialized
        if _config_manager is None or str(_config_manager.config_path) != env_path:
            _config_manager = ConfigManager(env_path)
            return _config_manager
    
    # Use provided path or default
    if _config_manager is None or config_path:
        path = config_path or os.getenv('CONFIG_PATH', './config/config.yaml')
        # Expand user path if needed
        if path.startswith('~'):
            path = os.path.expanduser(path)
        # Also expand if it's a relative path that might need expansion
        if not os.path.isabs(path) and '~' in path:
            path = os.path.expanduser(path)
        _config_manager = ConfigManager(path)
    return _config_manager

