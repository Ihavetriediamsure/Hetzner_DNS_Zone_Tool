"""SMTP Email Notifier Module for Audit Logs"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class SMTPNotifier:
    """Handles SMTP email notifications for audit logs"""
    
    def __init__(self):
        self._enabled = False
        self._smtp_host = ""
        self._smtp_port = 587
        self._smtp_user = ""
        self._smtp_password = ""
        self._use_tls = True
        self._from_address = ""
        self._to_address = ""
        self._enabled_events: List[str] = []
        self._machine_name = ""
        self._load_config()
    
    def _load_config(self):
        """Load SMTP configuration from config manager"""
        try:
            from src.config_manager import get_config_manager
            config_manager = get_config_manager()
            config = config_manager.load_config()
            
            smtp_config = config.get('security', {}).get('smtp', {})
            
            self._enabled = smtp_config.get('enabled', False)
            self._smtp_host = smtp_config.get('host', '')
            self._smtp_port = smtp_config.get('port', 587)
            self._smtp_user = smtp_config.get('user', '')
            self._smtp_password = smtp_config.get('password', '')
            self._use_tls = smtp_config.get('use_tls', True)
            self._from_address = smtp_config.get('from_address', '')
            self._to_address = smtp_config.get('to_address', '')
            self._enabled_events = smtp_config.get('enabled_events', [])
            
            # Load machine name from server config
            server_config = config.get('server', {})
            self._machine_name = server_config.get('machine_name', '')
        except Exception as e:
            logger.error(f"Failed to load SMTP config: {e}")
    
    def _decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt SMTP password if encrypted"""
        if not encrypted_password or not encrypted_password.startswith('encrypted:'):
            return encrypted_password
        
        try:
            from src.encryption import get_encryption_manager
            encryption = get_encryption_manager()
            encrypted_part = encrypted_password.replace('encrypted:', '')
            return encryption.decrypt_token(encrypted_part)
        except Exception as e:
            logger.error(f"Failed to decrypt SMTP password: {e}")
            return ""
    
    def is_enabled(self) -> bool:
        """Check if SMTP notifications are enabled"""
        return self._enabled and self._smtp_host and self._from_address and self._to_address
    
    def is_event_enabled(self, event_type: str) -> bool:
        """Check if a specific event type should trigger an email"""
        if not self.is_enabled():
            return False
        return event_type in self._enabled_events
    
    def send_notification(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """
        Send email notification for an audit log event
        
        Args:
            event_type: Type of audit event (e.g., 'ip_update', 'login_failure')
            event_data: Dictionary containing event details (timestamp, username, ip, success, details, error)
        
        Returns:
            True if email was sent successfully, False otherwise
        """
        if not self.is_event_enabled(event_type):
            return False
        
        try:
            # Decrypt password
            password = self._decrypt_password(self._smtp_password)
            if not password:
                logger.error("SMTP password is not configured or could not be decrypted")
                return False
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self._from_address
            msg['To'] = self._to_address
            
            # Format subject with machine name if available
            machine_prefix = f"[{self._machine_name}] " if self._machine_name else ""
            msg['Subject'] = f"{machine_prefix}[Hetzner DNS Zone Tool] {self._format_event_name(event_type)}"
            
            # Create email body
            body = self._format_email_body(event_type, event_data)
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Send email
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                if self._use_tls:
                    server.starttls(context=context)
                server.login(self._smtp_user, password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent for event: {event_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False
    
    def _format_event_name(self, event_type: str) -> str:
        """Format event type for email subject"""
        event_names = {
            'login_success': 'Login Success',
            'login_failure': 'Login Failure',
            'logout': 'Logout',
            'password_change': 'Password Changed',
            '2fa_setup': '2FA Setup',
            '2fa_disable': '2FA Disabled',
            '2fa_verify_success': '2FA Verification Success',
            '2fa_verify_failure': '2FA Verification Failure',
            'ip_whitelist_add': 'IP Whitelist Added',
            'ip_whitelist_remove': 'IP Whitelist Removed',
            'ip_whitelist_toggle': 'IP Whitelist Toggled',
            'ip_blacklist_add': 'IP Blacklist Added',
            'ip_blacklist_remove': 'IP Blacklist Removed',
            'ip_blacklist_toggle': 'IP Blacklist Toggled',
            'monitor_ip_offline': 'Monitor IP Offline',
            'token_add': 'API Token Added',
            'token_delete': 'API Token Deleted',
            'token_update': 'API Token Updated',
            'zone_create': 'DNS Zone Created',
            'zone_delete': 'DNS Zone Deleted',
            'record_create': 'DNS Record Created',
            'record_update': 'DNS Record Updated',
            'record_delete': 'DNS Record Deleted',
            'auto_update_enable': 'Auto-Update Enabled',
            'auto_update_disable': 'Auto-Update Disabled',
            'ttl_update': 'TTL Updated',
            'comment_update': 'Comment Updated',
            'ip_update': 'IP Address Updated',
            'brute_force_config_update': 'Brute-Force Config Updated',
        }
        return event_names.get(event_type, event_type.replace('_', ' ').title())
    
    def _format_email_body(self, event_type: str, event_data: Dict[str, Any]) -> str:
        """Format email body with event details"""
        lines = [
            f"Event: {self._format_event_name(event_type)}",
            f"Timestamp: {event_data.get('timestamp', 'Unknown')}",
            f"Username: {event_data.get('username', 'Unknown')}",
            f"IP Address: {event_data.get('ip', 'Unknown')}",
            f"Status: {'Success' if event_data.get('success', False) else 'Failure'}",
            ""
        ]
        
        # Add details if available
        details = event_data.get('details', {})
        if details:
            lines.append("Details:")
            for key, value in details.items():
                lines.append(f"  {key}: {value}")
            lines.append("")
        
        # Add error if available
        error = event_data.get('error')
        if error:
            lines.append(f"Error: {error}")
            lines.append("")
        
        lines.append("---")
        lines.append("This is an automated notification from Hetzner DNS Zone Tool")
        
        return "\n".join(lines)
    
    def get_config(self) -> Dict[str, Any]:
        """Get current SMTP configuration"""
        return {
            "enabled": self._enabled,
            "host": self._smtp_host,
            "port": self._smtp_port,
            "user": self._smtp_user,
            "password": "***" if self._smtp_password else "",  # Don't expose password
            "use_tls": self._use_tls,
            "from_address": self._from_address,
            "to_address": self._to_address,
            "enabled_events": self._enabled_events
        }
    
    def set_config(self, config: Dict[str, Any]):
        """Set SMTP configuration"""
        self._enabled = config.get('enabled', False)
        self._smtp_host = config.get('host', '')
        self._smtp_port = config.get('port', 587)
        self._smtp_user = config.get('user', '')
        
        # Encrypt password if provided and not already encrypted
        password = config.get('password', '')
        if password and password != "***" and not password.startswith('encrypted:'):
            from src.encryption import get_encryption_manager
            encryption = get_encryption_manager()
            encrypted_password = encryption.encrypt_token(password)
            self._smtp_password = f'encrypted:{encrypted_password}'
        elif password == "***":
            # Keep existing password
            pass
        else:
            self._smtp_password = password
        
        self._use_tls = config.get('use_tls', True)
        self._from_address = config.get('from_address', '')
        self._to_address = config.get('to_address', '')
        self._enabled_events = config.get('enabled_events', [])
        
        # Save to config
        from src.config_manager import get_config_manager
        config_manager = get_config_manager()
        app_config = config_manager.load_config()
        
        if 'security' not in app_config:
            app_config['security'] = {}
        app_config['security']['smtp'] = {
            "enabled": self._enabled,
            "host": self._smtp_host,
            "port": self._smtp_port,
            "user": self._smtp_user,
            "password": self._smtp_password,
            "use_tls": self._use_tls,
            "from_address": self._from_address,
            "to_address": self._to_address,
            "enabled_events": self._enabled_events
        }
        
        config_manager.save_config()
        
        # Reload config
        self._load_config()


_smtp_notifier = None


def get_smtp_notifier() -> SMTPNotifier:
    """Get global SMTP notifier instance"""
    global _smtp_notifier
    if _smtp_notifier is None:
        _smtp_notifier = SMTPNotifier()
    return _smtp_notifier

