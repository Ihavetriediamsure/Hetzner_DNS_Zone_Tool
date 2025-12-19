"""Config Event Broadcasting System for Server-Sent Events (SSE)"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ConfigEventBroadcaster:
    """Broadcasts configuration change events to connected SSE clients"""
    
    def __init__(self):
        # List of asyncio.Queue objects, one per connected client
        self._connections: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()
    
    async def subscribe(self) -> asyncio.Queue:
        """Subscribe to config events - returns a queue that will receive events"""
        queue = asyncio.Queue()
        async with self._lock:
            self._connections.append(queue)
        logger.debug(f"New SSE client subscribed (total: {len(self._connections)})")
        return queue
    
    async def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe from config events"""
        async with self._lock:
            if queue in self._connections:
                self._connections.remove(queue)
        logger.debug(f"SSE client unsubscribed (remaining: {len(self._connections)})")
    
    async def broadcast(self, event_type: str, data: Optional[Dict[str, Any]] = None):
        """Broadcast an event to all connected clients"""
        event = {
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": data or {}
        }
        
        async with self._lock:
            # Create a copy of connections list to avoid modification during iteration
            connections = list(self._connections)
        
        if not connections:
            logger.debug(f"Broadcasting event '{event_type}' but no clients connected")
            return
        
        # Send event to all connected clients
        disconnected = []
        for queue in connections:
            try:
                await queue.put(event)
            except Exception as e:
                logger.warning(f"Failed to send event to client: {e}")
                disconnected.append(queue)
        
        # Remove disconnected clients
        if disconnected:
            async with self._lock:
                for queue in disconnected:
                    if queue in self._connections:
                        self._connections.remove(queue)
        
        logger.debug(f"Broadcasted event '{event_type}' to {len(connections)} client(s)")
    
    def get_connection_count(self) -> int:
        """Get number of connected clients"""
        return len(self._connections)


# Global instance
_config_event_broadcaster: Optional[ConfigEventBroadcaster] = None


def get_config_event_broadcaster() -> ConfigEventBroadcaster:
    """Get global config event broadcaster instance"""
    global _config_event_broadcaster
    if _config_event_broadcaster is None:
        _config_event_broadcaster = ConfigEventBroadcaster()
    return _config_event_broadcaster

