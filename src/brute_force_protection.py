"""Brute-Force Protection Module"""

import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from collections import defaultdict
import threading
import os
from pathlib import Path


class BruteForceProtection:
    """Protects against brute-force attacks on login and 2FA"""
    
    def __init__(self):
        self._login_attempts: Dict[str, list] = defaultdict(list)  # {identifier: [timestamps]}
        self._twofa_attempts: Dict[str, list] = defaultdict(list)  # {identifier: [timestamps]}
        self._backup_code_attempts: Dict[str, list] = defaultdict(list)  # {identifier: [timestamps]}
        self._lock = threading.Lock()
        
        # Default configuration
        self._enabled = False  # Disabled by default on initial start
        self._max_login_attempts = 5
        self._max_2fa_attempts = 3
        self._lockout_duration_login = 900  # 15 minutes in seconds
        self._lockout_duration_2fa = 300  # 5 minutes in seconds
        self._window_duration = 600  # 10 minutes in seconds
        
        # Load configuration
        self._load_config()
    
    def _load_config(self):
        """Load brute-force protection configuration"""
        try:
            from src.config_manager import get_config_manager
            config_manager = get_config_manager()
            config = config_manager.load_config()
            
            brute_force_config = config.get('security', {}).get('brute_force_protection', {})
            
            self._enabled = brute_force_config.get('enabled', False)  # Disabled by default on initial start
            self._max_login_attempts = brute_force_config.get('max_login_attempts', 5)
            self._max_2fa_attempts = brute_force_config.get('max_2fa_attempts', 3)
            self._lockout_duration_login = brute_force_config.get('lockout_duration_login', 900)
            self._lockout_duration_2fa = brute_force_config.get('lockout_duration_2fa', 300)
            self._window_duration = brute_force_config.get('window_duration', 600)
        except Exception:
            # Use defaults if config loading fails
            pass
    
    def is_enabled(self) -> bool:
        """Check if brute-force protection is enabled"""
        return self._enabled
    
    def set_enabled(self, enabled: bool):
        """Enable or disable brute-force protection"""
        self._enabled = enabled
        self._save_config()
    
    def get_config(self) -> dict:
        """Get current configuration"""
        return {
            'enabled': self._enabled,
            'max_login_attempts': self._max_login_attempts,
            'max_2fa_attempts': self._max_2fa_attempts,
            'lockout_duration_login': self._lockout_duration_login,
            'lockout_duration_2fa': self._lockout_duration_2fa,
            'window_duration': self._window_duration
        }
    
    def set_config(self, enabled: bool, max_login_attempts: int, max_2fa_attempts: int,
                   lockout_duration_login: int, lockout_duration_2fa: int, window_duration: int):
        """Set brute-force protection configuration"""
        self._enabled = enabled
        self._max_login_attempts = max_login_attempts
        self._max_2fa_attempts = max_2fa_attempts
        self._lockout_duration_login = lockout_duration_login
        self._lockout_duration_2fa = lockout_duration_2fa
        self._window_duration = window_duration
        self._save_config()
    
    def _save_config(self):
        """Save configuration to config file"""
        try:
            from src.config_manager import get_config_manager
            config_manager = get_config_manager()
            config = config_manager.load_config()
            
            if 'security' not in config:
                config['security'] = {}
            if 'brute_force_protection' not in config['security']:
                config['security']['brute_force_protection'] = {}
            
            config['security']['brute_force_protection'] = {
                'enabled': self._enabled,
                'max_login_attempts': self._max_login_attempts,
                'max_2fa_attempts': self._max_2fa_attempts,
                'lockout_duration_login': self._lockout_duration_login,
                'lockout_duration_2fa': self._lockout_duration_2fa,
                'window_duration': self._window_duration
            }
            
            config_manager._config = config
            config_manager.save_config()
        except Exception:
            # Silently fail if config save fails
            pass
    
    def _get_identifier(self, ip: str, username: Optional[str] = None) -> str:
        """Generate identifier for tracking (IP + username if provided)"""
        if username:
            return f"{ip}:{username}"
        return ip
    
    def _cleanup_old_attempts(self, attempts: list, window: int) -> list:
        """Remove attempts outside the time window"""
        current_time = time.time()
        cutoff = current_time - window
        return [ts for ts in attempts if ts > cutoff]
    
    def check_login_allowed(self, ip: str, username: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Check if login attempt is allowed
        Returns: (allowed, error_message)
        """
        if not self._enabled:
            return True, None
        
        with self._lock:
            identifier = self._get_identifier(ip, username)
            attempts = self._login_attempts[identifier]
            
            # Clean up old attempts
            attempts = self._cleanup_old_attempts(attempts, self._window_duration)
            self._login_attempts[identifier] = attempts
            
            # Check if locked out
            if len(attempts) >= self._max_login_attempts:
                # Check if lockout period has passed
                oldest_attempt = min(attempts) if attempts else 0
                lockout_end = oldest_attempt + self._lockout_duration_login
                current_time = time.time()
                
                if current_time < lockout_end:
                    remaining = int(lockout_end - current_time)
                    minutes = remaining // 60
                    seconds = remaining % 60
                    minute_text = "minute" if minutes == 1 else "minutes"
                    second_text = "second" if seconds == 1 else "seconds"
                    return False, f"Too many failed login attempts. Please try again in {minutes} {minute_text} and {seconds} {second_text}."
                
                # Lockout expired, reset attempts
                self._login_attempts[identifier] = []
            
            return True, None
    
    def record_login_failure(self, ip: str, username: Optional[str] = None):
        """Record a failed login attempt"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            self._login_attempts[identifier].append(time.time())
    
    def record_login_success(self, ip: str, username: Optional[str] = None):
        """Clear failed login attempts on successful login"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            if identifier in self._login_attempts:
                del self._login_attempts[identifier]
    
    def check_2fa_allowed(self, ip: str, username: str) -> Tuple[bool, Optional[str]]:
        """
        Check if 2FA attempt is allowed
        Returns: (allowed, error_message)
        """
        if not self._enabled:
            return True, None
        
        with self._lock:
            identifier = self._get_identifier(ip, username)
            attempts = self._twofa_attempts[identifier]
            
            # Clean up old attempts
            attempts = self._cleanup_old_attempts(attempts, self._window_duration)
            self._twofa_attempts[identifier] = attempts
            
            # Check if locked out
            if len(attempts) >= self._max_2fa_attempts:
                # Check if lockout period has passed
                oldest_attempt = min(attempts) if attempts else 0
                lockout_end = oldest_attempt + self._lockout_duration_2fa
                current_time = time.time()
                
                if current_time < lockout_end:
                    remaining = int(lockout_end - current_time)
                    minutes = remaining // 60
                    seconds = remaining % 60
                    minute_text = "minute" if minutes == 1 else "minutes"
                    second_text = "second" if seconds == 1 else "seconds"
                    return False, f"Too many failed 2FA attempts. Please try again in {minutes} {minute_text} and {seconds} {second_text}."
                
                # Lockout expired, reset attempts
                self._twofa_attempts[identifier] = []
            
            return True, None
    
    def record_2fa_failure(self, ip: str, username: str):
        """Record a failed 2FA attempt"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            self._twofa_attempts[identifier].append(time.time())
    
    def record_2fa_success(self, ip: str, username: str):
        """Clear failed 2FA attempts on successful verification"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            if identifier in self._twofa_attempts:
                del self._twofa_attempts[identifier]
    
    def get_login_attempts(self, ip: str, username: Optional[str] = None) -> int:
        """Get current number of failed login attempts"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            attempts = self._login_attempts[identifier]
            attempts = self._cleanup_old_attempts(attempts, self._window_duration)
            self._login_attempts[identifier] = attempts
            return len(attempts)
    
    def get_2fa_attempts(self, ip: str, username: str) -> int:
        """Get current number of failed 2FA attempts"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            attempts = self._twofa_attempts[identifier]
            attempts = self._cleanup_old_attempts(attempts, self._window_duration)
            self._twofa_attempts[identifier] = attempts
            return len(attempts)
    
    def check_backup_code_allowed(self, ip: str, username: str) -> Tuple[bool, Optional[str]]:
        """
        Check if backup code attempt is allowed
        Returns: (allowed, error_message)
        """
        if not self._enabled:
            return True, None
        
        with self._lock:
            identifier = self._get_identifier(ip, username)
            attempts = self._backup_code_attempts[identifier]
            
            # Clean up old attempts
            attempts = self._cleanup_old_attempts(attempts, self._window_duration)
            self._backup_code_attempts[identifier] = attempts
            
            # Check if locked out
            if len(attempts) >= self._max_2fa_attempts:  # Use same limit as 2FA
                # Check if lockout period has passed
                oldest_attempt = min(attempts) if attempts else 0
                lockout_end = oldest_attempt + self._lockout_duration_2fa
                current_time = time.time()
                
                if current_time < lockout_end:
                    remaining = int(lockout_end - current_time)
                    minutes = remaining // 60
                    seconds = remaining % 60
                    minute_text = "minute" if minutes == 1 else "minutes"
                    second_text = "second" if seconds == 1 else "seconds"
                    return False, f"Too many failed backup code attempts. Please try again in {minutes} {minute_text} and {seconds} {second_text}."
                
                # Lockout expired, reset attempts
                self._backup_code_attempts[identifier] = []
            
            return True, None
    
    def record_backup_code_failure(self, ip: str, username: str):
        """Record a failed backup code attempt"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            self._backup_code_attempts[identifier].append(time.time())
    
    def record_backup_code_success(self, ip: str, username: str):
        """Clear failed backup code attempts on successful verification"""
        with self._lock:
            identifier = self._get_identifier(ip, username)
            if identifier in self._backup_code_attempts:
                del self._backup_code_attempts[identifier]
            # Also clear 2FA attempts on successful backup code (user authenticated)
            if identifier in self._twofa_attempts:
                del self._twofa_attempts[identifier]


# Global instance
_brute_force_protection = None


def get_brute_force_protection() -> BruteForceProtection:
    """Get global brute-force protection instance"""
    global _brute_force_protection
    if _brute_force_protection is None:
        _brute_force_protection = BruteForceProtection()
    return _brute_force_protection

