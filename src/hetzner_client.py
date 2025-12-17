"""Hetzner DNS API Client Adapter"""

from typing import Optional, List
from src.config_manager import get_config_manager
from src.hetzner_dns_api import HetznerDNSAPI
from src.models import Zone, RRSet


class HetznerDNSClient:
    """Client for Hetzner DNS API (new API only)"""
    
    def __init__(self, token_id: Optional[str] = None):
        """
        Initialize Hetzner DNS client
        
        Args:
            token_id: Optional token ID to use. If not provided, uses default token
        """
        self.config = get_config_manager()
        self.token_id = token_id
        self._api: Optional[HetznerDNSAPI] = None
    
    def _get_token_and_base_url(self) -> tuple:
        """Get token and base URL, either from token_id or default"""
        if self.token_id:
            token_data = self.config.get_token_by_id(self.token_id)
            if token_data:
                base_url = token_data.get('base_url', '')
                if not base_url:
                    base_url = 'https://api.hetzner.cloud/v1'
                return token_data.get('token'), base_url
        
        # Fallback to default method
            token = self.config.get_api_token('new')
            base_url = self.config.get_api_base_url('new')
        return token, base_url
    
    def _get_api(self) -> HetznerDNSAPI:
        """Get or create API client"""
        if self._api is None:
            token, base_url = self._get_token_and_base_url()
            if not token:
                raise ValueError("API token not configured")
            self._api = HetznerDNSAPI(token, base_url=base_url, use_bearer=True)
        return self._api
    
    async def list_zones(self) -> List[Zone]:
        """List all DNS zones"""
        return await self._get_api().list_zones()
    
    async def get_zone(self, zone_id: str) -> Zone:
        """Get a specific zone"""
        return await self._get_api().get_zone(zone_id)
    
    async def create_zone(self, name: str, ttl: Optional[int] = None, mode: str = "primary") -> Zone:
        """Create a new DNS zone"""
        return await self._get_api().create_zone(name, ttl, mode)
    
    async def delete_zone(self, zone_id: str) -> None:
        """Delete a DNS zone"""
        await self._get_api().delete_zone(zone_id)
    
    async def list_rrsets(self, zone_id: str) -> List[RRSet]:
        """List all RRSets for a zone"""
        return await self._get_api().list_rrsets(zone_id)
    
    async def get_rrset(self, zone_id: str, rrset_id: str) -> RRSet:
        """Get a specific RRSet"""
        return await self._get_api().get_rrset(zone_id, rrset_id)
    
    async def create_or_update_rrset(self, zone_id: str, name: str, type: str, records: List[str], ttl: int = 3600, comment: Optional[str] = None) -> RRSet:
        """Create or update an RRSet"""
        return await self._get_api().create_or_update_rrset(zone_id, name, type, records, ttl, comment)
    
    async def delete_rrset(self, zone_id: str, rrset_id: str):
        """Delete an RRSet"""
        await self._get_api().delete_rrset(zone_id, rrset_id)
    
    async def update_rrset_ip(self, zone_id: str, rrset_id: str, ip: str) -> RRSet:
        """Update an RRSet's IP address"""
        rrset = await self._get_api().get_rrset(zone_id, rrset_id)
        return await self._get_api().create_or_update_rrset(
            zone_id, rrset.name, rrset.type, [ip], rrset.ttl, rrset.comment
        )
    
    async def close(self):
        """Close API client"""
        if self._api:
            await self._api.close()

