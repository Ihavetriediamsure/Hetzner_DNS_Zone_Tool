"""Auto-update service for DNS records"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from src.config_manager import get_config_manager
from src.ip_detector import get_public_ip
from src.hetzner_client import HetznerDNSClient
from src.internal_ip_monitor import get_internal_ip_monitor


class AutoUpdateService:
    """Manages automatic IP updates for DNS records"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.getenv("AUTO_UPDATE_CONFIG_PATH", "./config/auto_update.yaml")
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._enabled = False
        self._last_update: Optional[str] = None
        self._next_update: Optional[str] = None
    
    def _load_config(self) -> Dict[str, Any]:
        """Load auto-update configuration"""
        if not self.config_path.exists():
            return {"enabled": False, "interval_minutes": 15, "records": []}
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f) or {"enabled": False, "interval_minutes": 15, "records": []}
    
    def _save_config(self, config: Dict[str, Any]):
        """Save auto-update configuration"""
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def get_config(self) -> Dict[str, Any]:
        """Get auto-update configuration"""
        return self._load_config()
    
    def set_config(self, config: Dict[str, Any]):
        """Set auto-update configuration"""
        self._save_config(config)
        self._enabled = config.get("enabled", False)
    
    async def check_and_update(self) -> Dict[str, Any]:
        """Check IP and update configured records"""
        config = self._load_config()
        
        if not config.get("enabled", False):
            return {"updated": 0, "skipped": 0, "errors": []}
        
        records = config.get("records", [])
        updated = 0
        skipped = 0
        errors = []
        
        current_ip = await get_public_ip()
        client = HetznerDNSClient()
        monitor = get_internal_ip_monitor()
        
        try:
            for record_config in records:
                if not record_config.get("enabled", False):
                    skipped += 1
                    continue
                
                try:
                    zone_id = record_config["zone_id"]
                    record_id = record_config.get("record_id")
                    record_name = record_config.get("record_name")
                    record_type = record_config.get("record_type", "A")
                    
                    update_condition = record_config.get("update_condition", "always")
                    internal_ip = record_config.get("internal_ip")
                    
                    # Check internal IP if condition requires it
                    if update_condition == "internal_reachable" and internal_ip:
                        check_method = record_config.get("check_method", "ping")
                        timeout = record_config.get("check_timeout", 5)
                        
                        should_update = await monitor.should_update_dns(
                            internal_ip, zone_id, record_id or "", check_method, timeout
                        )
                        
                        if not should_update:
                            skipped += 1
                            continue
                    
                    # Update DNS record
                    if record_id:
                        # Update existing RRSet
                        await client.update_rrset_ip(zone_id, record_id, current_ip)
                    else:
                        # Create new RRSet
                        await client.create_or_update_rrset(
                            zone_id, record_name or "@", record_type, [current_ip]
                        )
                    
                    updated += 1
                
                except Exception as e:
                    errors.append({
                        "record": record_config.get("record_name", "unknown"),
                        "error": str(e)
                    })
        
        finally:
            await client.close()
        
        self._last_update = datetime.now().isoformat()
        interval_minutes = config.get("interval_minutes", 15)
        self._next_update = (datetime.now() + timedelta(minutes=interval_minutes)).isoformat()
        
        return {
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
            "current_ip": current_ip,
            "last_update": self._last_update
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get auto-update status"""
        config = self._load_config()
        return {
            "enabled": config.get("enabled", False),
            "running": False,  # TODO: Track running state
            "last_update": self._last_update,
            "next_update": self._next_update,
            "records_count": len(config.get("records", []))
        }


# Global instance
_auto_update_service = None


def get_auto_update_service(config_path: Optional[str] = None) -> AutoUpdateService:
    """Get global auto-update service instance"""
    global _auto_update_service
    if _auto_update_service is None:
        if config_path is None:
            config_path = os.getenv("AUTO_UPDATE_CONFIG_PATH", "./config/auto_update.yaml")
        _auto_update_service = AutoUpdateService(config_path)
    return _auto_update_service

