"""Internal IP monitoring service"""

import socket
import httpx
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime
from src.hetzner_client import HetznerDNSClient


class InternalIPMonitor:
    """Monitors internal IP addresses for reachability"""
    
    async def check_internal_ip_reachable(self, internal_ip: str, port: Optional[int] = None, 
                                         check_method: str = "ping", timeout: int = 5) -> Dict[str, Any]:
        """Check if internal IP is reachable"""
        result = {
            "ip": internal_ip,
            "reachable": False,
            "last_check": datetime.now().isoformat(),
            "check_method": check_method,
            "response_time": None
        }
        
        try:
            if check_method == "ping":
                # Simple TCP connection test
                start_time = asyncio.get_event_loop().time()
                test_port = port or 80
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(internal_ip, test_port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    result["reachable"] = True
                    result["response_time"] = asyncio.get_event_loop().time() - start_time
                except (OSError, asyncio.TimeoutError):
                    result["reachable"] = False
            
            elif check_method == "http":
                start_time = asyncio.get_event_loop().time()
                url = f"http://{internal_ip}"
                if port:
                    url = f"http://{internal_ip}:{port}"
                
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(url)
                    result["reachable"] = response.status_code < 500
                    result["response_time"] = asyncio.get_event_loop().time() - start_time
            
            elif check_method == "tcp":
                start_time = asyncio.get_event_loop().time()
                test_port = port or 80
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(internal_ip, test_port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    result["reachable"] = True
                    result["response_time"] = asyncio.get_event_loop().time() - start_time
                except (OSError, asyncio.TimeoutError):
                    result["reachable"] = False
        
        except Exception as e:
            result["reachable"] = False
            result["error"] = str(e)
        
        return result
    
    async def should_update_dns(self, internal_ip: str, zone_id: str, record_id: str,
                               check_method: str = "ping", timeout: int = 5) -> bool:
        """Determine if DNS should be updated based on internal IP reachability"""
        check_result = await self.check_internal_ip_reachable(internal_ip, check_method=check_method, timeout=timeout)
        return check_result["reachable"]


# Global instance
_internal_ip_monitor = None


def get_internal_ip_monitor() -> InternalIPMonitor:
    """Get global internal IP monitor instance"""
    global _internal_ip_monitor
    if _internal_ip_monitor is None:
        _internal_ip_monitor = InternalIPMonitor()
    return _internal_ip_monitor

