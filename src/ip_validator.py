"""IP Address Validation Module - Only allows public IPs"""

import ipaddress
from typing import Union


class IPValidator:
    """Validates that IP addresses are public (not private)"""
    
    # Private IPv4 ranges
    PRIVATE_IPV4_RANGES = [
        ipaddress.IPv4Network('10.0.0.0/8'),      # 10.0.0.0 - 10.255.255.255
        ipaddress.IPv4Network('172.16.0.0/12'),  # 172.16.0.0 - 172.31.255.255
        ipaddress.IPv4Network('192.168.0.0/16'),  # 192.168.0.0 - 192.168.255.255
        ipaddress.IPv4Network('127.0.0.0/8'),    # 127.0.0.0 - 127.255.255.255 (loopback)
        ipaddress.IPv4Network('169.254.0.0/16'), # 169.254.0.0 - 169.254.255.255 (link-local)
    ]
    
    # Private IPv6 ranges
    PRIVATE_IPV6_RANGES = [
        ipaddress.IPv6Network('::1/128'),         # Loopback
        ipaddress.IPv6Network('fc00::/7'),       # Unique Local Address (ULA) - fd00::/8 is included
        ipaddress.IPv6Network('fe80::/10'),      # Link-local
        ipaddress.IPv6Network('ff00::/8'),       # Multicast
    ]
    
    @classmethod
    def is_public_ip(cls, ip_str: str) -> bool:
        """
        Check if an IP address is public (not private)
        
        Args:
            ip_str: IP address as string (IPv4 or IPv6)
        
        Returns:
            True if IP is public, False if private/local
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            
            if isinstance(ip, ipaddress.IPv4Address):
                return cls._is_public_ipv4(ip)
            elif isinstance(ip, ipaddress.IPv6Address):
                return cls._is_public_ipv6(ip)
            else:
                return False
        except ValueError:
            # Invalid IP format
            return False
    
    @classmethod
    def _is_public_ipv4(cls, ip: ipaddress.IPv4Address) -> bool:
        """Check if IPv4 address is public"""
        for private_range in cls.PRIVATE_IPV4_RANGES:
            if ip in private_range:
                return False
        return True
    
    @classmethod
    def _is_public_ipv6(cls, ip: ipaddress.IPv6Address) -> bool:
        """Check if IPv6 address is public"""
        for private_range in cls.PRIVATE_IPV6_RANGES:
            if ip in private_range:
                return False
        return True
    
    @classmethod
    def validate_public_ip(cls, ip_str: str) -> tuple[bool, str]:
        """
        Validate that an IP address is public
        
        Args:
            ip_str: IP address as string
        
        Returns:
            Tuple of (is_valid, error_message)
            If is_valid is True, error_message is empty
            If is_valid is False, error_message contains the reason
        """
        if not ip_str or not ip_str.strip():
            return False, "IP address is required"
        
        ip_str = ip_str.strip()
        
        # Check if it's a valid IP format
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address format: {ip_str}"
        
        # Check if it's public
        if not cls.is_public_ip(ip_str):
            ip_type = "IPv4" if isinstance(ip, ipaddress.IPv4Address) else "IPv6"
            
            # Determine which private range it belongs to
            if isinstance(ip, ipaddress.IPv4Address):
                if ip in ipaddress.IPv4Network('127.0.0.0/8'):
                    reason = "Loopback address (127.0.0.1)"
                elif ip in ipaddress.IPv4Network('192.168.0.0/16'):
                    reason = "Private network (192.168.x.x)"
                elif ip in ipaddress.IPv4Network('10.0.0.0/8'):
                    reason = "Private network (10.x.x.x)"
                elif ip in ipaddress.IPv4Network('172.16.0.0/12'):
                    reason = "Private network (172.16-31.x.x)"
                elif ip in ipaddress.IPv4Network('169.254.0.0/16'):
                    reason = "Link-local address (169.254.x.x)"
                else:
                    reason = "Private or reserved address"
            else:  # IPv6
                if ip in ipaddress.IPv6Network('::1/128'):
                    reason = "Loopback address (::1)"
                elif ip in ipaddress.IPv6Network('fc00::/7'):
                    reason = "Unique Local Address (fd00::/8 or fc00::/8)"
                elif ip in ipaddress.IPv6Network('fe80::/10'):
                    reason = "Link-local address (fe80::)"
                elif ip in ipaddress.IPv6Network('ff00::/8'):
                    reason = "Multicast address"
                else:
                    reason = "Private or reserved address"
            
            return False, f"Only public IP addresses are allowed. {ip_str} is a {reason}."
        
        return True, ""
    
    @classmethod
    def validate_ip_list(cls, ip_list: list[str]) -> tuple[bool, str]:
        """
        Validate a list of IP addresses
        
        Args:
            ip_list: List of IP address strings
        
        Returns:
            Tuple of (all_valid, error_message)
        """
        if not ip_list:
            return False, "At least one IP address is required"
        
        for ip_str in ip_list:
            is_valid, error_msg = cls.validate_public_ip(ip_str)
            if not is_valid:
                return False, error_msg
        
        return True, ""

