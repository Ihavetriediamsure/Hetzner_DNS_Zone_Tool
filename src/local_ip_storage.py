"""Local IP Storage for DNS Records"""

import os
import yaml
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Optional, Any


class LocalIPStorage:
    """Stores local IP addresses for DNS records"""
    
    def __init__(self, storage_path: Optional[str] = None):
        if storage_path is None:
            storage_path = os.getenv("LOCAL_IP_STORAGE_PATH", "./config/local_ips.yaml")
        self.storage_path = Path(storage_path)
        self._storage: Optional[Dict[str, Any]] = None
    
    def _load_storage(self) -> Dict[str, Any]:
        """Load storage from YAML file"""
        # Always reload from file to ensure we have the latest data
        # (Cache is only used within a single operation to avoid multiple file reads)
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    self._storage = yaml.safe_load(f) or {}
            except Exception:
                self._storage = {}
        else:
            self._storage = {}
        
        # Ensure structure
        if "local_ips" not in self._storage:
            self._storage["local_ips"] = {}
        if "settings" not in self._storage:
            self._storage["settings"] = {}
        if "generation" not in self._storage:
            self._storage["generation"] = {
                "sequence": 0,
                "node_id": self._get_node_id(),
                "timestamp": time.time(),
                "content_hash": ""
            }
            # Calculate initial content hash
            self._storage["generation"]["content_hash"] = self._calculate_content_hash(self._storage)
        
        return self._storage
    
    def _get_node_id(self) -> str:
        """Get node ID (WireGuard IP or hostname)"""
        # Try to get WireGuard IP from environment or use hostname
        wg_ip = os.getenv("WIREGUARD_IP")
        if wg_ip:
            return wg_ip
        import socket
        return socket.gethostname()
    
    def _calculate_content_hash(self, config_data: Dict) -> str:
        """Calculate hash of config content (without generation field)"""
        config_copy = config_data.copy()
        config_copy.pop('generation', None)  # Remove generation for hash
        content_str = json.dumps(config_copy, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()
    
    def _increment_generation(self) -> None:
        """Increment generation counter when config changes"""
        if self._storage is None:
            self._load_storage()
        
        if "generation" not in self._storage:
            self._storage["generation"] = {
                "sequence": 0,
                "node_id": self._get_node_id(),
                "timestamp": time.time(),
                "content_hash": ""
            }
        
        # Increment sequence
        self._storage["generation"]["sequence"] = self._storage["generation"].get("sequence", 0) + 1
        self._storage["generation"]["timestamp"] = time.time()
        self._storage["generation"]["content_hash"] = self._calculate_content_hash(self._storage)
    
    def _save_storage(self) -> None:
        """Save storage to YAML file"""
        if self._storage is None:
            self._storage = {"local_ips": {}}
        
        # Increment generation before saving (if config changed)
        self._increment_generation()
        
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._storage, f, default_flow_style=False, allow_unicode=True)
        except PermissionError:
            # Try alternative path in user's home directory
            home_storage = Path.home() / ".hetzner-dns" / "local_ips.yaml"
            home_storage.parent.mkdir(parents=True, exist_ok=True)
            with open(home_storage, 'w', encoding='utf-8') as f:
                yaml.dump(self._storage, f, default_flow_style=False, allow_unicode=True)
            # Update path for future use
            self.storage_path = home_storage
    
    def set_local_ip(self, zone_id: str, rrset_id: str, local_ip: str, port: Optional[int] = None) -> None:
        """Set local IP for a DNS record"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        if key not in storage["local_ips"]:
            storage["local_ips"][key] = {}
        storage["local_ips"][key].update({
            "zone_id": zone_id,
            "rrset_id": rrset_id,
            "local_ip": local_ip
        })
        if port is not None:
            storage["local_ips"][key]["port"] = port
        elif "port" in storage["local_ips"][key]:
            del storage["local_ips"][key]["port"]
        
        self._storage = storage
        self._save_storage()
    
    def set_auto_update(self, zone_id: str, rrset_id: str, enabled: bool) -> None:
        """Set auto-update enabled for a DNS record"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        if key not in storage["local_ips"]:
            storage["local_ips"][key] = {}
        storage["local_ips"][key].update({
            "zone_id": zone_id,
            "rrset_id": rrset_id,
            "auto_update_enabled": enabled
        })
        
        self._storage = storage
        self._save_storage()
    
    def get_auto_update(self, zone_id: str, rrset_id: str) -> bool:
        """Get auto-update enabled for a DNS record"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        record = storage["local_ips"].get(key)
        
        if record:
            return record.get("auto_update_enabled", False)
        
        return False
    
    def set_ttl(self, zone_id: str, rrset_id: str, ttl: Optional[int]) -> None:
        """Set TTL override for a DNS record"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        if key not in storage["local_ips"]:
            storage["local_ips"][key] = {}
        storage["local_ips"][key].update({
            "zone_id": zone_id,
            "rrset_id": rrset_id
        })
        if ttl is not None:
            storage["local_ips"][key]["ttl"] = ttl
        elif "ttl" in storage["local_ips"][key]:
            del storage["local_ips"][key]["ttl"]
        
        self._storage = storage
        self._save_storage()
    
    def get_ttl(self, zone_id: str, rrset_id: str) -> Optional[int]:
        """Get TTL override for a DNS record"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        record = storage["local_ips"].get(key)
        
        if record:
            return record.get("ttl")
        
        return None
    
    def set_public_ip_refresh_interval(self, interval_seconds: int) -> None:
        """Set public IP refresh interval in seconds"""
        storage = self._load_storage()
        
        if "settings" not in storage:
            storage["settings"] = {}
        storage["settings"]["public_ip_refresh_interval"] = interval_seconds
        
        self._storage = storage
        self._save_storage()
    
    def get_public_ip_refresh_interval(self) -> int:
        """Get public IP refresh interval in seconds"""
        storage = self._load_storage()
        
        if "settings" in storage:
            return storage["settings"].get("public_ip_refresh_interval", 600)
        
        return 600  # Default: 600 seconds (10 minutes)
    
    def set_manual_public_ip(self, ip: Optional[str]) -> None:
        """Set manual public IP override"""
        storage = self._load_storage()
        
        if "settings" not in storage:
            storage["settings"] = {}
        
        if ip:
            storage["settings"]["manual_public_ip"] = ip
        elif "manual_public_ip" in storage["settings"]:
            del storage["settings"]["manual_public_ip"]
        
        self._storage = storage
        self._save_storage()
    
    def get_manual_public_ip(self) -> Optional[str]:
        """Get manual public IP override"""
        storage = self._load_storage()
        
        if "settings" in storage:
            return storage["settings"].get("manual_public_ip")
        
        return None
    
    def set_auto_update_interval(self, interval_seconds: int) -> None:
        """Set auto-update check interval in seconds"""
        storage = self._load_storage()
        
        if "settings" not in storage:
            storage["settings"] = {}
        storage["settings"]["auto_update_interval"] = interval_seconds
        
        self._storage = storage
        self._save_storage()
    
    def get_auto_update_interval(self) -> int:
        """Get auto-update check interval in seconds"""
        storage = self._load_storage()
        
        if "settings" in storage:
            return storage["settings"].get("auto_update_interval", 600)
        
        return 600  # Default: 600 seconds (10 minutes)
    
    def get_local_ip(self, zone_id: str, rrset_id: str) -> Optional[str]:
        """Get local IP for a DNS record"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        record = storage["local_ips"].get(key)
        
        if record:
            return record.get("local_ip")
        
        return None
    
    def get_local_ip_port(self, zone_id: str, rrset_id: str) -> Optional[int]:
        """Get port for local IP monitoring"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        record = storage["local_ips"].get(key)
        
        if record:
            return record.get("port")
        
        return None
    
    def delete_local_ip(self, zone_id: str, rrset_id: str) -> None:
        """Delete local IP for a DNS record"""
        storage = self._load_storage()
        
        key = f"{zone_id}:{rrset_id}"
        if key in storage["local_ips"]:
            del storage["local_ips"][key]
            self._storage = storage
            self._save_storage()
    
    def get_all_local_ips(self) -> Dict[str, str]:
        """Get all local IPs as a dictionary: {zone_id:rrset_id -> local_ip}"""
        storage = self._load_storage()
        result = {}
        
        for key, record in storage["local_ips"].items():
            result[key] = record.get("local_ip")
        
        return result
    
    def get_local_ips_for_zone(self, zone_id: str) -> Dict[str, Dict[str, Any]]:
        """Get all local IPs and settings for a specific zone"""
        storage = self._load_storage()
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"get_local_ips_for_zone called for zone_id={zone_id}, storage_path={self.storage_path}")
        logger.info(f"Storage keys: {list(storage.get('local_ips', {}).keys())}")
        result = {}
        
        for key, record in storage["local_ips"].items():
            # Check if zone_id is stored in record
            stored_zone_id = record.get("zone_id")
            if stored_zone_id == zone_id:
                rrset_id = record.get("rrset_id")
                if rrset_id:
                    result[rrset_id] = {
                        "local_ip": record.get("local_ip"),
                        "port": record.get("port"),
                        "auto_update_enabled": record.get("auto_update_enabled", False),
                        "ttl": record.get("ttl")
                    }
            elif not stored_zone_id:
                # Fallback: Parse zone_id from key (for backward compatibility)
                # Key format: "zone_id:rrset_id"
                if ":" in key:
                    key_zone_id, key_rrset_id = key.split(":", 1)
                    if key_zone_id == zone_id:
                        result[key_rrset_id] = {
                            "local_ip": record.get("local_ip"),
                            "auto_update_enabled": record.get("auto_update_enabled", False),
                            "ttl": record.get("ttl")
                        }
                        # Update record with zone_id and rrset_id for future use
                        record["zone_id"] = zone_id
                        record["rrset_id"] = key_rrset_id
        
        # Save updated records if any were updated
        if any(not record.get("zone_id") for record in storage["local_ips"].values()):
            self._storage = storage
            self._save_storage()
        
        return result
    
    def get_zones_with_auto_update(self) -> set:
        """Get all zone IDs that have at least one record with auto-update enabled"""
        storage = self._load_storage()
        zones_with_auto_update = set()
        
        for key, record in storage["local_ips"].items():
            auto_update_enabled = record.get("auto_update_enabled", False)
            local_ip = record.get("local_ip")
            
            # Only include zones with auto-update enabled and local IP configured
            if auto_update_enabled and local_ip and local_ip.strip():
                zone_id = record.get("zone_id")
                if not zone_id and ":" in key:
                    # Fallback: Parse zone_id from key (for backward compatibility)
                    zone_id = key.split(":", 1)[0]
                
                if zone_id:
                    zones_with_auto_update.add(zone_id)
        
        return zones_with_auto_update


# Global instance
_local_ip_storage = None


def get_local_ip_storage(storage_path: Optional[str] = None) -> LocalIPStorage:
    """Get global local IP storage instance"""
    global _local_ip_storage
    
    # Environment variable always takes precedence
    env_path = os.getenv("LOCAL_IP_STORAGE_PATH")
    if env_path:
        storage_path = env_path
    
    # Always check if we need to recreate the instance
    need_recreate = False
    if _local_ip_storage is None:
        need_recreate = True
    elif storage_path:
        # Compare paths - resolve both to absolute paths for comparison
        try:
            current_path = str(_local_ip_storage.storage_path.resolve())
        except:
            current_path = str(_local_ip_storage.storage_path)
        
        try:
            new_path_obj = Path(storage_path)
            new_path = str(new_path_obj.resolve())
        except:
            new_path = str(Path(storage_path))
        
        # Force recreation if paths don't match
        if current_path != new_path:
            need_recreate = True
    
    if need_recreate:
        _local_ip_storage = LocalIPStorage(storage_path)
    elif _local_ip_storage:
        # Reset cache to ensure fresh data on each request
        _local_ip_storage._storage = None
    
    return _local_ip_storage

