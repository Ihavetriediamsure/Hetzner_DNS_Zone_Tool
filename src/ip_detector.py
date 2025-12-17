"""Public IP detection module"""

import httpx
import asyncio
from typing import Optional
from datetime import datetime, timedelta


class IPDetector:
    """Detects current public IP address"""
    
    # Multiple IP detection services for fallback
    IP_SERVICES = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
        "https://api.ip.sb/ip",
    ]
    
    def __init__(self):
        self._cached_ip: Optional[str] = None
        self._cache_time: Optional[datetime] = None
        self._cache_ttl = timedelta(minutes=5)  # Cache for 5 minutes
    
    async def get_public_ip(self, use_cache: bool = True) -> str:
        """Get current public IP address"""
        # Check cache first
        if use_cache and self._cached_ip and self._cache_time:
            if datetime.now() - self._cache_time < self._cache_ttl:
                return self._cached_ip
        
        # Try to detect IP from multiple services
        ip = await self.detect_ip()
        
        if ip:
            self._cached_ip = ip
            self._cache_time = datetime.now()
            return ip
        
        raise RuntimeError("Failed to detect public IP address from all services")
    
    async def detect_ip(self) -> Optional[str]:
        """Detect IP using multiple services with fallback"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for service in self.IP_SERVICES:
                try:
                    response = await client.get(service)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        # Basic IP validation
                        if self._is_valid_ip(ip):
                            return ip
                except Exception:
                    continue
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation"""
        parts = ip.split('.')
        if len(parts) != 4:
            # Check for IPv6 (simplified)
            if ':' in ip:
                return True
            return False
        
        try:
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            return True
        except ValueError:
            return False
    
    def clear_cache(self):
        """Clear IP cache"""
        self._cached_ip = None
        self._cache_time = None
    
    def get_cached_ip(self) -> Optional[str]:
        """Get cached IP without fetching"""
        return self._cached_ip if self._cache_time and (datetime.now() - self._cache_time < self._cache_ttl) else None


# Global instance
_ip_detector = None


def get_ip_detector() -> IPDetector:
    """Get global IP detector instance"""
    global _ip_detector
    if _ip_detector is None:
        _ip_detector = IPDetector()
    return _ip_detector


# Convenience function
async def get_public_ip() -> str:
    """Get public IP address"""
    detector = get_ip_detector()
    return await detector.get_public_ip()


# Synchronous wrapper for CLI usage
def get_public_ip_sync() -> str:
    """Synchronous wrapper for getting public IP"""
    detector = get_ip_detector()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(detector.get_public_ip())
    finally:
        loop.close()

