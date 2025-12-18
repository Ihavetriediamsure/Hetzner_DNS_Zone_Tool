"""Audit Log Module"""

import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum
import threading
import asyncio
import logging


class AuditAction(str, Enum):
    """Types of audit actions"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    TWO_FA_SETUP = "2fa_setup"
    TWO_FA_DISABLE = "2fa_disable"
    TWO_FA_VERIFY_SUCCESS = "2fa_verify_success"
    TWO_FA_VERIFY_FAILURE = "2fa_verify_failure"
    TWO_FA_BACKUP_CODES_GENERATED = "2fa_backup_codes_generated"
    IP_WHITELIST_ADD = "ip_whitelist_add"
    IP_WHITELIST_REMOVE = "ip_whitelist_remove"
    IP_WHITELIST_TOGGLE = "ip_whitelist_toggle"
    IP_BLACKLIST_ADD = "ip_blacklist_add"
    IP_BLACKLIST_REMOVE = "ip_blacklist_remove"
    IP_BLACKLIST_TOGGLE = "ip_blacklist_toggle"
    TOKEN_ADD = "token_add"
    TOKEN_DELETE = "token_delete"
    TOKEN_UPDATE = "token_update"
    ZONE_CREATE = "zone_create"
    ZONE_DELETE = "zone_delete"
    RECORD_CREATE = "record_create"
    RECORD_UPDATE = "record_update"
    RECORD_DELETE = "record_delete"
    AUTO_UPDATE_ENABLE = "auto_update_enable"
    AUTO_UPDATE_DISABLE = "auto_update_disable"
    AUTO_UPDATE_TOKEN_MISSING = "auto_update_token_missing"
    AUTO_UPDATE_ZONE_ACCESS_DENIED = "auto_update_zone_access_denied"
    IP_UPDATE_SPLIT_BRAIN_DETECTED = "ip_update_split_brain_detected"
    TTL_UPDATE = "ttl_update"
    COMMENT_UPDATE = "comment_update"
    IP_UPDATE = "ip_update"
    MONITOR_IP_OFFLINE = "monitor_ip_offline"
    MONITOR_IP_ONLINE = "monitor_ip_online"
    MONITOR_IP_STATUS_CHECK = "monitor_ip_status_check"
    # Peer-Sync Actions
    PEER_SYNC_ENABLE = "peer_sync_enable"
    PEER_SYNC_DISABLE = "peer_sync_disable"
    PEER_SYNC_CONFIG_UPDATE = "peer_sync_config_update"
    PEER_SYNC_PEER_ADD = "peer_sync_peer_add"
    PEER_SYNC_PEER_REMOVE = "peer_sync_peer_remove"
    PEER_SYNC_PEER_KEY_UPDATE = "peer_sync_peer_key_update"
    PEER_SYNC_SUCCESS = "peer_sync_success"
    PEER_SYNC_FAILURE = "peer_sync_failure"
    PEER_SYNC_MANUAL_TRIGGER = "peer_sync_manual_trigger"
    PEER_SYNC_CONNECTION_TEST = "peer_sync_connection_test"
    PEER_SYNC_PULL_CONFIG = "peer_sync_pull_config"


class AuditLog:
    """Manages audit logging with automatic log rotation"""
    
    def __init__(self, log_file: Optional[str] = None):
        if log_file is None:
            # Priority: Environment variable > /config (Docker) > ~/.hetzner-dns (local)
            log_file = os.getenv("AUDIT_LOG_FILE")
            if not log_file:
                if os.path.exists('/config'):
                    log_file = '/config/audit.log'
                else:
                    log_file = os.path.expanduser("~/.hetzner-dns/audit.log")
        self.log_file = Path(log_file)
        self._lock = threading.Lock()
        self._ensure_log_file()
        
        # Log rotation configuration
        self._max_size_mb = 10  # Maximum log file size in MB
        self._max_age_days = 30  # Maximum age of logs in days
        self._rotation_interval_hours = 24  # Check for rotation every 24 hours
        self._rotation_task = None
        self._load_config()
        
        # Start rotation task
        self._start_rotation_task()
    
    def _ensure_log_file(self):
        """Ensure log file and directory exist"""
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.log_file.touch(mode=0o600)  # Restrictive permissions
    
    def _load_config(self):
        """Load log rotation configuration from config file"""
        try:
            from src.config_manager import get_config_manager
            config_manager = get_config_manager()
            config = config_manager.load_config()
            
            audit_config = config.get('security', {}).get('audit_log', {})
            self._max_size_mb = audit_config.get('max_size_mb', 10)
            self._max_age_days = audit_config.get('max_age_days', 30)
            self._rotation_interval_hours = audit_config.get('rotation_interval_hours', 24)
        except Exception:
            # Use defaults if config loading fails
            pass
    
    def _get_client_ip(self, request) -> str:
        """Extract client IP from request"""
        client_ip = request.client.host if request.client else "127.0.0.1"
        
        # Check X-Forwarded-For header (for reverse proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        return client_ip
    
    def log(
        self,
        action: AuditAction,
        username: Optional[str] = None,
        ip: Optional[str] = None,
        request: Optional[Any] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """
        Log an audit event
        
        Args:
            action: Type of action
            username: Username performing the action
            ip: IP address (extracted from request if not provided)
            request: FastAPI request object (for IP extraction)
            success: Whether the action was successful
            details: Additional details about the action
            error: Error message if action failed
        """
        # Extract IP from request if not provided
        if ip is None and request is not None:
            ip = self._get_client_ip(request)
        
        # Use more precise timestamp with milliseconds
        now = datetime.utcnow()
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"  # Include milliseconds
        
        log_entry = {
            "timestamp": timestamp,
            "action": action.value,
            "username": username or "unknown",
            "ip": ip or "unknown",
            "success": success,
        }
        
        if details:
            log_entry["details"] = details
        
        if error:
            log_entry["error"] = error
        
        # Write to log file (append mode)
        with self._lock:
            try:
                # Check if rotation is needed before writing
                self._check_and_rotate()
                
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            except Exception as e:
                # Silently fail to avoid breaking the application
                logging.getLogger(__name__).error(f"Failed to write audit log: {e}")
        
        # Send email notification if configured
        try:
            from src.smtp_notifier import get_smtp_notifier
            smtp_notifier = get_smtp_notifier()
            if smtp_notifier.is_event_enabled(action.value):
                # Send email in background (don't block logging)
                import threading
                email_thread = threading.Thread(
                    target=smtp_notifier.send_notification,
                    args=(action.value, log_entry),
                    daemon=True
                )
                email_thread.start()
        except Exception as e:
            # Silently fail to avoid breaking the application
            logging.getLogger(__name__).error(f"Failed to send email notification: {e}")
    
    def get_logs(
        self,
        limit: int = 100,
        action: Optional[AuditAction] = None,
        username: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> list:
        """
        Retrieve audit logs with optional filtering
        
        Args:
            limit: Maximum number of logs to return
            action: Filter by action type
            username: Filter by username
            start_date: Filter logs after this date
            end_date: Filter logs before this date
        
        Returns:
            List of log entries (most recent first)
        """
        if not self.log_file.exists():
            return []
        
        logs = []
        with self._lock:
            try:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            entry = json.loads(line)
                            
                            # Apply filters
                            if action and entry.get('action') != action.value:
                                continue
                            if username and entry.get('username') != username:
                                continue
                            
                            # Date filtering
                            if start_date or end_date:
                                entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                                if start_date and entry_time < start_date:
                                    continue
                                if end_date and entry_time > end_date:
                                    continue
                            
                            logs.append(entry)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to read audit log: {e}")
                return []
        
        # Sort by timestamp (most recent first) and limit
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return logs[:limit]
    
    def clear_logs(self, older_than_days: Optional[int] = None):
        """
        Clear audit logs
        
        Args:
            older_than_days: If provided, only clear logs older than this many days
        """
        if not self.log_file.exists():
            return
        
        if older_than_days is None:
            # Clear all logs
            with self._lock:
                self.log_file.unlink()
                self._ensure_log_file()
        else:
            # Clear old logs only
            cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
            logs = self.get_logs(limit=1000000)  # Get all logs
            filtered_logs = [
                log for log in logs
                if datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')) >= cutoff_date
            ]
            
            with self._lock:
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    for log in filtered_logs:
                        f.write(json.dumps(log, ensure_ascii=False) + '\n')
    
    def _check_and_rotate(self):
        """Check if log rotation is needed and perform it"""
        if not self.log_file.exists():
            return
        
        # Check file size
        file_size_mb = self.log_file.stat().st_size / (1024 * 1024)
        if file_size_mb >= self._max_size_mb:
            self._rotate_logs()
            return
        
        # Check file age (oldest entry)
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                first_line = f.readline()
                if first_line:
                    try:
                        first_entry = json.loads(first_line.strip())
                        first_timestamp = datetime.fromisoformat(first_entry['timestamp'].replace('Z', '+00:00'))
                        age = datetime.utcnow() - first_timestamp.replace(tzinfo=None)
                        if age.days >= self._max_age_days:
                            self._rotate_logs()
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass
        except Exception:
            pass
    
    def _rotate_logs(self):
        """Rotate logs by removing old entries"""
        if not self.log_file.exists():
            return
        
        try:
            # Read all logs
            logs = self.get_logs(limit=1000000)
            
            # Filter by age
            cutoff_date = datetime.utcnow() - timedelta(days=self._max_age_days)
            filtered_logs = [
                log for log in logs
                if datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')) >= cutoff_date
            ]
            
            # If still too large, keep only the most recent entries
            # Estimate size: each log entry is roughly 200-500 bytes
            # Keep approximately max_size_mb worth of entries
            max_entries = int((self._max_size_mb * 1024 * 1024) / 300)  # ~300 bytes per entry
            if len(filtered_logs) > max_entries:
                filtered_logs = filtered_logs[-max_entries:]
            
            # Write filtered logs back
            with open(self.log_file, 'w', encoding='utf-8') as f:
                for log in filtered_logs:
                    f.write(json.dumps(log, ensure_ascii=False) + '\n')
            
            logger = logging.getLogger(__name__)
            logger.info(f"Audit log rotated: kept {len(filtered_logs)} entries")
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to rotate audit log: {e}")
    
    def _start_rotation_task(self):
        """Start background task for periodic log rotation"""
        async def rotation_loop():
            while True:
                try:
                    await asyncio.sleep(self._rotation_interval_hours * 3600)
                    with self._lock:
                        self._check_and_rotate()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger = logging.getLogger(__name__)
                    logger.error(f"Error in log rotation task: {e}")
        
        # Start task if asyncio event loop is running
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                self._rotation_task = asyncio.create_task(rotation_loop())
        except RuntimeError:
            # No event loop running, rotation will happen on write
            pass
    
    def stop_rotation_task(self):
        """Stop the background rotation task"""
        if self._rotation_task and not self._rotation_task.done():
            self._rotation_task.cancel()


# Global instance
_audit_log = None


def get_audit_log(log_file: Optional[str] = None) -> AuditLog:
    """Get global audit log instance"""
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog(log_file)
    return _audit_log

