"""Peer Sync NTP Storage - Synchronized NTP/Timezone Configuration"""

import os
import yaml
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Optional, Any


class PeerSyncNTPStorage:
    """Stores NTP server and timezone configuration (synchronized between peers)"""
    
    def __init__(self, storage_path: Optional[str] = None):
        if storage_path is None:
            storage_path = os.getenv("PEER_SYNC_NTP_STORAGE_PATH", "./config/peer_sync_ntp.yaml")
        self.storage_path = Path(storage_path)
        self._storage: Optional[Dict[str, Any]] = None
    
    def _load_storage(self) -> Dict[str, Any]:
        """Load storage from YAML file"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    self._storage = yaml.safe_load(f) or {}
            except Exception:
                self._storage = {}
        else:
            self._storage = {}
        
        # Ensure structure
        if "ntp_config" not in self._storage:
            self._storage["ntp_config"] = {
                "ntp_enabled": False,
                "ntp_server": "pool.ntp.org",
                "timezone": "UTC"
            }
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
        """Get unique node ID (hostname or machine ID)"""
        import socket
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"
    
    def _calculate_content_hash(self, config_data: Dict) -> str:
        """Calculate hash of config content (without generation field)"""
        config_copy = config_data.copy()
        config_copy.pop('generation', None)  # Remove generation for hash
        
        # Recursively sort the dictionary to ensure deterministic hashing
        sorted_config = self._sort_dict_recursively(config_copy)
        
        content_str = json.dumps(sorted_config, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()
    
    def _sort_dict_recursively(self, obj):
        """Recursively sort all dicts to ensure deterministic hash calculation"""
        if isinstance(obj, dict):
            return {k: self._sort_dict_recursively(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [self._sort_dict_recursively(elem) for elem in obj]
        else:
            return obj
    
    def _increment_generation(self):
        """Increment generation sequence"""
        if "generation" not in self._storage:
            self._storage["generation"] = {
                "sequence": 0,
                "node_id": self._get_node_id(),
                "timestamp": time.time(),
                "content_hash": ""
            }
        
        self._storage["generation"]["sequence"] += 1
        self._storage["generation"]["node_id"] = self._get_node_id()
        self._storage["generation"]["timestamp"] = time.time()
        self._storage["generation"]["content_hash"] = self._calculate_content_hash(self._storage)
    
    def _save_storage(self, increment_generation: bool = True) -> None:
        """Save storage to YAML file"""
        if self._storage is None:
            self._storage = {"ntp_config": {"ntp_enabled": False, "ntp_server": "pool.ntp.org", "timezone": "UTC"}}
        
        if increment_generation:
            self._increment_generation()
        
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._storage, f, default_flow_style=False, allow_unicode=True)
        except PermissionError:
            # Try alternative path in user's home directory
            home_storage = Path.home() / ".hetzner-dns" / "peer_sync_ntp.yaml"
            home_storage.parent.mkdir(parents=True, exist_ok=True)
            with open(home_storage, 'w', encoding='utf-8') as f:
                yaml.dump(self._storage, f, default_flow_style=False, allow_unicode=True)
            # Update path for future use
            self.storage_path = home_storage
    
    def get_ntp_config(self) -> Dict[str, Any]:
        """Get NTP configuration"""
        data = self._load_storage()
        return data.get("ntp_config", {
            "ntp_enabled": False,
            "ntp_server": "pool.ntp.org",
            "timezone": "UTC"
        })
    
    def set_ntp_config(self, ntp_enabled: bool, ntp_server: str, timezone: str) -> None:
        """Set NTP configuration (triggers generation increment)"""
        data = self._load_storage()
        data["ntp_config"] = {
            "ntp_enabled": ntp_enabled,
            "ntp_server": ntp_server,
            "timezone": timezone
        }
        self._storage = data
        self._save_storage(increment_generation=True)
    
    def set_config_from_peer(self, peer_config: Dict[str, Any]) -> None:
        """Set complete config from peer (including generation) - used for pull operations"""
        # Ensure structure
        if "ntp_config" not in peer_config:
            peer_config["ntp_config"] = {
                "ntp_enabled": False,
                "ntp_server": "pool.ntp.org",
                "timezone": "UTC"
            }
        if "generation" not in peer_config:
            peer_config["generation"] = {
                "sequence": 0,
                "node_id": self._get_node_id(),
                "timestamp": time.time(),
                "content_hash": ""
            }
            peer_config["generation"]["content_hash"] = self._calculate_content_hash(peer_config)
        
        self._storage = peer_config
        
        # Save without incrementing generation (we use peer's generation)
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._storage, f, default_flow_style=False, allow_unicode=True)
        except PermissionError:
            # Try alternative path in user's home directory
            home_storage = Path.home() / ".hetzner-dns" / "peer_sync_ntp.yaml"
            home_storage.parent.mkdir(parents=True, exist_ok=True)
            with open(home_storage, 'w', encoding='utf-8') as f:
                yaml.dump(self._storage, f, default_flow_style=False, allow_unicode=True)
            # Update path for future use
            self.storage_path = home_storage


# Global instance
_ntp_storage: Optional[PeerSyncNTPStorage] = None


def get_peer_sync_ntp_storage() -> PeerSyncNTPStorage:
    """Get global PeerSyncNTPStorage instance"""
    global _ntp_storage
    if _ntp_storage is None:
        _ntp_storage = PeerSyncNTPStorage()
    return _ntp_storage

