"""IP Whitelist and Blacklist module for access control"""

import os
import ipaddress
from typing import List, Optional
from src.config_manager import get_config_manager


class IPAccessControl:
    """Manages IP whitelist and blacklist for WebGUI access"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.getenv("CONFIG_PATH", "./config/config.yaml")
        self.config_path = config_path
        self._allowed_ips: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._blocked_ips: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._whitelist_enabled = False
        self._blacklist_enabled = False
        self._mode = "whitelist"  # "whitelist" or "blacklist"
        self._load_from_config()
    
    def _load_from_config(self):
        """Load whitelist/blacklist from configuration"""
        config = get_config_manager(self.config_path)
        cfg = config.load_config()
        
        security = cfg.get('security', {})
        ip_access_config = security.get('ip_access_control', {})
        
        # Whitelist
        whitelist_config = ip_access_config.get('whitelist', {})
        self._whitelist_enabled = whitelist_config.get('enabled', False)
        allowed_ips_raw = whitelist_config.get('ips', [])
        
        self._allowed_ips = []
        for ip_or_cidr in allowed_ips_raw:
            try:
                if '/' in ip_or_cidr:
                    self._allowed_ips.append(ipaddress.ip_network(ip_or_cidr, strict=False))
                else:
                    # Single IP, convert to /32 or /128
                    ip = ipaddress.ip_address(ip_or_cidr)
                    if isinstance(ip, ipaddress.IPv4Address):
                        self._allowed_ips.append(ipaddress.IPv4Network(f"{ip}/32", strict=False))
                    else:
                        self._allowed_ips.append(ipaddress.IPv6Network(f"{ip}/128", strict=False))
            except ValueError:
                continue
        
        # Blacklist
        blacklist_config = ip_access_config.get('blacklist', {})
        self._blacklist_enabled = blacklist_config.get('enabled', False)
        blocked_ips_raw = blacklist_config.get('ips', [])
        
        self._blocked_ips = []
        for ip_or_cidr in blocked_ips_raw:
            try:
                if '/' in ip_or_cidr:
                    self._blocked_ips.append(ipaddress.ip_network(ip_or_cidr, strict=False))
                else:
                    # Single IP, convert to /32 or /128
                    ip = ipaddress.ip_address(ip_or_cidr)
                    if isinstance(ip, ipaddress.IPv4Address):
                        self._blocked_ips.append(ipaddress.IPv4Network(f"{ip}/32", strict=False))
                    else:
                        self._blocked_ips.append(ipaddress.IPv6Network(f"{ip}/128", strict=False))
            except ValueError:
                continue
        
        # Mode (whitelist or blacklist)
        self._mode = ip_access_config.get('mode', 'whitelist')
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed"""
        try:
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        
        # Check blacklist first (if enabled)
        if self._blacklist_enabled:
            for network in self._blocked_ips:
                if ip_addr in network:
                    return False  # Blocked
        
        # Check whitelist (if enabled)
        if self._whitelist_enabled:
            if not self._allowed_ips:
                return True  # Empty whitelist, allow all
            for network in self._allowed_ips:
                if ip_addr in network:
                    return True
            return False  # Not in whitelist
        
        # Neither enabled, allow all
        return True
    
    def add_whitelist_ip(self, ip_or_cidr: str):
        """Add IP/CIDR to whitelist"""
        try:
            if '/' in ip_or_cidr:
                network = ipaddress.ip_network(ip_or_cidr, strict=False)
            else:
                ip = ipaddress.ip_address(ip_or_cidr)
                if isinstance(ip, ipaddress.IPv4Address):
                    network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                else:
                    network = ipaddress.IPv6Network(f"{ip}/128", strict=False)
            
            if network not in self._allowed_ips:
                self._allowed_ips.append(network)
                self._save_to_config()
        except ValueError as e:
            raise ValueError(f"Invalid IP/CIDR: {ip_or_cidr}") from e
    
    def remove_whitelist_ip(self, ip_or_cidr: str):
        """Remove IP/CIDR from whitelist"""
        try:
            if '/' in ip_or_cidr:
                network = ipaddress.ip_network(ip_or_cidr, strict=False)
            else:
                ip = ipaddress.ip_address(ip_or_cidr)
                if isinstance(ip, ipaddress.IPv4Address):
                    network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                else:
                    network = ipaddress.IPv6Network(f"{ip}/128", strict=False)
            
            if network in self._allowed_ips:
                self._allowed_ips.remove(network)
                self._save_to_config()
        except ValueError:
            pass
    
    def add_blacklist_ip(self, ip_or_cidr: str):
        """Add IP/CIDR to blacklist"""
        try:
            if '/' in ip_or_cidr:
                network = ipaddress.ip_network(ip_or_cidr, strict=False)
            else:
                ip = ipaddress.ip_address(ip_or_cidr)
                if isinstance(ip, ipaddress.IPv4Address):
                    network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                else:
                    network = ipaddress.IPv6Network(f"{ip}/128", strict=False)
            
            if network not in self._blocked_ips:
                self._blocked_ips.append(network)
                self._save_to_config()
        except ValueError as e:
            raise ValueError(f"Invalid IP/CIDR: {ip_or_cidr}") from e
    
    def remove_blacklist_ip(self, ip_or_cidr: str):
        """Remove IP/CIDR from blacklist"""
        try:
            if '/' in ip_or_cidr:
                network = ipaddress.ip_network(ip_or_cidr, strict=False)
            else:
                ip = ipaddress.ip_address(ip_or_cidr)
                if isinstance(ip, ipaddress.IPv4Address):
                    network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                else:
                    network = ipaddress.IPv6Network(f"{ip}/128", strict=False)
            
            if network in self._blocked_ips:
                self._blocked_ips.remove(network)
                self._save_to_config()
        except ValueError:
            pass
    
    def get_whitelist_ips(self) -> List[str]:
        """Get all whitelist IPs/CIDRs as strings"""
        return [str(net) for net in self._allowed_ips]
    
    def get_blacklist_ips(self) -> List[str]:
        """Get all blacklist IPs/CIDRs as strings"""
        return [str(net) for net in self._blocked_ips]
    
    def set_whitelist_enabled(self, enabled: bool):
        """Enable or disable whitelist"""
        self._whitelist_enabled = enabled
        self._save_to_config()
    
    def set_blacklist_enabled(self, enabled: bool):
        """Enable or disable blacklist"""
        self._blacklist_enabled = enabled
        self._save_to_config()
    
    def is_whitelist_enabled(self) -> bool:
        """Check if whitelist is enabled"""
        return self._whitelist_enabled
    
    def is_blacklist_enabled(self) -> bool:
        """Check if blacklist is enabled"""
        return self._blacklist_enabled
    
    def set_mode(self, mode: str):
        """Set mode: 'whitelist' or 'blacklist'"""
        if mode not in ['whitelist', 'blacklist']:
            raise ValueError("Mode must be 'whitelist' or 'blacklist'")
        self._mode = mode
        self._save_to_config()
    
    def get_mode(self) -> str:
        """Get current mode"""
        return self._mode
    
    def _save_to_config(self):
        """Save whitelist/blacklist to configuration"""
        config = get_config_manager(self.config_path)
        cfg = config.load_config()
        
        if 'security' not in cfg:
            cfg['security'] = {}
        if 'ip_access_control' not in cfg['security']:
            cfg['security']['ip_access_control'] = {}
        
        cfg['security']['ip_access_control']['mode'] = self._mode
        cfg['security']['ip_access_control']['whitelist'] = {
            'enabled': self._whitelist_enabled,
            'ips': self.get_whitelist_ips()
        }
        cfg['security']['ip_access_control']['blacklist'] = {
            'enabled': self._blacklist_enabled,
            'ips': self.get_blacklist_ips()
        }
        
        config._config = cfg
        config.save_config()


# Backward compatibility
class IPWhitelist(IPAccessControl):
    """Backward compatibility wrapper"""
    def __init__(self, config_path: Optional[str] = None):
        super().__init__(config_path)
    
    def add_ip(self, ip_or_cidr: str):
        """Add IP/CIDR to whitelist (backward compatibility)"""
        return self.add_whitelist_ip(ip_or_cidr)
    
    def remove_ip(self, ip_or_cidr: str):
        """Remove IP/CIDR from whitelist (backward compatibility)"""
        return self.remove_whitelist_ip(ip_or_cidr)
    
    def get_allowed_ips(self) -> List[str]:
        """Get all allowed IPs/CIDRs as strings (backward compatibility)"""
        return self.get_whitelist_ips()
    
    def set_enabled(self, enabled: bool):
        """Enable or disable whitelist (backward compatibility)"""
        return self.set_whitelist_enabled(enabled)
    
    def is_enabled(self) -> bool:
        """Check if whitelist is enabled (backward compatibility)"""
        return self.is_whitelist_enabled()


# Global instance
_ip_whitelist = None
_ip_access_control = None


def get_ip_whitelist(config_path: Optional[str] = None) -> IPWhitelist:
    """Get global IP whitelist instance (backward compatibility)"""
    global _ip_whitelist
    if _ip_whitelist is None:
        if config_path is None:
            config_path = os.getenv("CONFIG_PATH", "./config/config.yaml")
        _ip_whitelist = IPWhitelist(config_path)
    return _ip_whitelist


def get_ip_access_control(config_path: Optional[str] = None) -> IPAccessControl:
    """Get global IP access control instance"""
    global _ip_access_control
    if _ip_access_control is None:
        if config_path is None:
            config_path = os.getenv("CONFIG_PATH", "./config/config.yaml")
        _ip_access_control = IPAccessControl(config_path)
    return _ip_access_control

