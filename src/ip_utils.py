"""IP Utilities for secure IP extraction and validation"""

import ipaddress
import logging
from typing import Optional, List
from fastapi import Request
from src.config_manager import get_config_manager

logger = logging.getLogger(__name__)


def get_trusted_proxy_ips() -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Get list of trusted proxy IPs from configuration"""
    try:
        config = get_config_manager()
        cfg = config.load_config()
        security = cfg.get('security', {})
        trusted_proxy_ips_raw = security.get('trusted_proxy_ips', [])
        
        trusted_proxy_ips = []
        for ip_or_cidr in trusted_proxy_ips_raw:
            try:
                if '/' in ip_or_cidr:
                    trusted_proxy_ips.append(ipaddress.ip_network(ip_or_cidr, strict=False))
                else:
                    # Single IP, convert to /32 or /128
                    ip = ipaddress.ip_address(ip_or_cidr)
                    if isinstance(ip, ipaddress.IPv4Address):
                        trusted_proxy_ips.append(ipaddress.IPv4Network(f"{ip}/32", strict=False))
                    else:
                        trusted_proxy_ips.append(ipaddress.IPv6Network(f"{ip}/128", strict=False))
            except ValueError:
                logger.warning(f"Invalid trusted proxy IP/CIDR in config: {ip_or_cidr}")
                continue
        
        return trusted_proxy_ips
    except Exception as e:
        logger.error(f"Error loading trusted proxy IPs: {e}")
        return []


def is_trusted_proxy(ip: str) -> bool:
    """Check if an IP is a trusted proxy"""
    try:
        ip_addr = ipaddress.ip_address(ip)
        trusted_proxy_ips = get_trusted_proxy_ips()
        
        # If no trusted proxies configured, don't trust any X-Forwarded-For headers
        if not trusted_proxy_ips:
            return False
        
        for network in trusted_proxy_ips:
            try:
                if ip_addr in network:
                    return True
            except (ValueError, TypeError):
                # IPv6 in IPv4Network or other type mismatch: treat as not trusted
                continue
        
        return False
    except (ValueError, TypeError):
        return False


def get_client_ip_safe(request: Request) -> str:
    """
    Safely extract client IP from request, validating X-Forwarded-For header.
    
    Only accepts X-Forwarded-For header if the direct connection IP (request.client.host)
    is in the list of trusted proxy IPs. This prevents IP spoofing attacks.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address as string
    """
    # Get direct connection IP (the IP that directly connected to the server)
    direct_ip = request.client.host if request.client else "127.0.0.1"
    
    # Check if direct connection is from a trusted proxy
    if is_trusted_proxy(direct_ip):
        # Only then, trust X-Forwarded-For header
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            client_ip = forwarded_for.split(",")[0].strip()
            
            # Validate that the extracted IP is a valid IP address
            try:
                ipaddress.ip_address(client_ip)
                return client_ip
            except ValueError:
                logger.warning(f"Invalid IP in X-Forwarded-For header: {client_ip}, using direct IP: {direct_ip}")
                return direct_ip
    
    # If not from trusted proxy, or no X-Forwarded-For header, use direct IP
    return direct_ip

