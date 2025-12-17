"""Hetzner DNS API Client for new Hetzner Cloud DNS API"""

import httpx
from typing import Optional, List, Dict, Any
from src.models import Zone, Record, RecordType, RRSet


class HetznerDNSAPI:
    """Client for Hetzner Cloud DNS API v1"""
    
    BASE_URL_CLOUD_API = "https://api.hetzner.cloud/v1"
    BASE_URL_DNS_CONSOLE = "https://dns.hetzner.com/api/v1"
    
    def __init__(self, token: str, base_url: Optional[str] = None, use_bearer: bool = True):
        """
        Initialize Hetzner DNS API client
        
        Args:
            token: API token
            base_url: Base URL for API (defaults to Cloud API)
            use_bearer: If True, use Bearer token; if False, use Auth-API-Token header
        """
        self.token = token
        self.use_bearer = use_bearer
        
        if base_url:
            self.base_url = base_url
        else:
            self.base_url = self.BASE_URL_CLOUD_API if use_bearer else self.BASE_URL_DNS_CONSOLE
        
        self.client = httpx.AsyncClient(timeout=30.0)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers"""
        if self.use_bearer:
            return {"Authorization": f"Bearer {self.token}"}
        else:
            return {"Auth-API-Token": self.token}
    
    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request"""
        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers()
        headers.update(kwargs.pop('headers', {}))
        
        # Ensure Content-Type is set for PUT/POST requests with JSON
        if method in ['PUT', 'POST'] and 'json' in kwargs and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        
        response = await self.client.request(method, url, headers=headers, **kwargs)
        if not response.is_success:
            # Try to get error details from response
            try:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', response.text)
                raise Exception(f"API error ({response.status_code}): {error_msg}")
            except:
                raise Exception(f"API error ({response.status_code}): {response.text}")
        response.raise_for_status()
        return response.json()
    
    async def list_zones(self) -> List[Zone]:
        """List all DNS zones"""
        data = await self._request("GET", "/zones")
        zones = []
        for zone_data in data.get("zones", []):
            zones.append(Zone(
                id=str(zone_data.get("id")),  # Convert to string
                name=zone_data.get("name"),
                ttl=zone_data.get("ttl"),
                created=zone_data.get("created"),
                modified=zone_data.get("modified")
            ))
        return zones
    
    async def get_zone(self, zone_id: str) -> Zone:
        """Get a specific zone"""
        data = await self._request("GET", f"/zones/{zone_id}")
        zone_data = data.get("zone", {})
        return Zone(
            id=str(zone_data.get("id")),  # Convert to string
            name=zone_data.get("name"),
            ttl=zone_data.get("ttl"),
            created=zone_data.get("created"),
            modified=zone_data.get("modified")
        )
    
    async def create_zone(self, name: str, ttl: Optional[int] = None, mode: str = "primary") -> Zone:
        """Create a new DNS zone"""
        payload = {
            "name": name,
            "mode": mode  # Required: "primary" or "secondary"
        }
        if ttl:
            payload["ttl"] = ttl
        
        data = await self._request("POST", "/zones", json=payload)
        zone_data = data.get("zone", {})
        return Zone(
            id=str(zone_data.get("id")),  # Convert to string
            name=zone_data.get("name"),
            ttl=zone_data.get("ttl"),
            created=zone_data.get("created"),
            modified=zone_data.get("modified")
        )
    
    async def delete_zone(self, zone_id: str) -> None:
        """Delete a DNS zone"""
        await self._request("DELETE", f"/zones/{zone_id}")
    
    async def list_rrsets(self, zone_id: str) -> List[RRSet]:
        """List all RRSets for a zone"""
        data = await self._request("GET", f"/zones/{zone_id}/rrsets")
        rrsets = []
        for rrset_data in data.get("rrsets", []):
            rrset_id = rrset_data.get("id")
            
            # Extract records - can be list of strings or list of dicts with 'value' key
            records_raw = rrset_data.get("records", [])
            records = []
            for record in records_raw:
                if isinstance(record, dict):
                    # Hetzner API returns records as dicts: {"value": "...", "comment": "..."}
                    records.append(record.get("value", ""))
                elif isinstance(record, str):
                    records.append(record)
            
            # Extract comment - can be in records[0].comment or top-level
            comment = rrset_data.get("comment")
            if not comment and records_raw and isinstance(records_raw[0], dict):
                comment = records_raw[0].get("comment")
            
            rrsets.append(RRSet(
                id=str(rrset_id) if rrset_id is not None else None,  # Convert to string
                zone_id=str(zone_id),  # Ensure string
                name=rrset_data.get("name"),
                type=rrset_data.get("type"),
                ttl=rrset_data.get("ttl"),  # Can be None
                records=records,
                comment=comment
            ))
        return rrsets
    
    async def get_rrset(self, zone_id: str, rrset_id: str) -> RRSet:
        """Get a specific RRSet"""
        # RRSet ID format: "name/type" (e.g., "test/A" or "@/NS")
        # URL encode the ID, but keep '/' and '@' unencoded as they're part of the format
        # '@' is used for root domain records and should be passed as-is
        import urllib.parse
        encoded_id = urllib.parse.quote(rrset_id, safe='/@')
        
        data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_id}")
        rrset_data = data.get("rrset", {})
        
        # Extract records - can be list of strings or list of dicts with 'value' key
        records_raw = rrset_data.get("records", [])
        records = []
        for record in records_raw:
            if isinstance(record, dict):
                records.append(record.get("value", ""))
            elif isinstance(record, str):
                records.append(record)
        
        # Extract comment
        comment = rrset_data.get("comment")
        if not comment and records_raw and isinstance(records_raw[0], dict):
            comment = records_raw[0].get("comment")
        
        return RRSet(
            id=str(rrset_data.get("id")) if rrset_data.get("id") else rrset_id,  # Convert to string
            zone_id=str(zone_id),  # Ensure string
            name=rrset_data.get("name"),
            type=rrset_data.get("type"),
            ttl=rrset_data.get("ttl"),  # Can be None
            records=records,
            comment=comment
        )
    
    async def create_or_update_rrset(self, zone_id: str, name: str, type: str, records: List[str], ttl: int = 3600, comment: Optional[str] = None) -> RRSet:
        """Create or update an RRSet"""
        # RRSet ID format: "name/type" (e.g., "test/A" or "@/NS")
        rrset_id = f"{name}/{type}"
        
        # Convert records to format expected by API (list of objects with 'value' and optional 'comment')
        records_formatted = []
        for record in records:
            if isinstance(record, dict):
                records_formatted.append(record)
            else:
                record_obj = {"value": record}
                if comment:
                    record_obj["comment"] = comment
                records_formatted.append(record_obj)
        
        # URL encode the rrset_id for API calls
        # Note: Keep '/' and '@' unencoded as they're part of the RRSet ID format (name/type)
        # '@' is used for root domain records and should be passed as-is
        import urllib.parse
        encoded_rrset_id = urllib.parse.quote(rrset_id, safe='/@')
        
        # Check if RRSet exists by trying to get it
        rrset_exists = False
        try:
            await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}")
            rrset_exists = True
        except Exception:
            # RRSet doesn't exist, will create it
            rrset_exists = False
        
        if rrset_exists:
            # Check if we need to update TTL
            # Hetzner API: TTL can be updated by deleting and recreating the RRSet, or by using set_records with TTL
            # However, set_records might not support TTL, so we'll use a workaround:
            # If TTL needs to be changed, we'll delete and recreate the RRSet with new TTL
            current_rrset_data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}")
            current_rrset = current_rrset_data.get("rrset", {})
            current_ttl = current_rrset.get("ttl")
            
            # If TTL needs to be changed, delete and recreate
            if ttl is not None and current_ttl != ttl:
                # Delete the RRSet
                await self._request("DELETE", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}")
                
                # Recreate with new TTL using add_records action
                add_payload = {
                    "records": records_formatted
                }
                if ttl is not None:
                    add_payload["ttl"] = ttl
                
                # Create RRSet with new TTL
                action_data = await self._request("POST", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}/actions/add_records", json=add_payload)
                action_id = action_data.get("action", {}).get("id")
                
                # Wait for action to complete
                if action_id:
                    import asyncio
                    for _ in range(10):  # Max 10 seconds wait
                        await asyncio.sleep(1)
                        try:
                            action_status_data = await self._request("GET", f"/actions/{action_id}")
                            action_status = action_status_data.get("action", {}).get("status")
                            if action_status == "success":
                                break
                            elif action_status == "error":
                                error = action_status_data.get("action", {}).get("error")
                                raise Exception(f"Action failed: {error}")
                        except Exception:
                            # If action status check fails, continue anyway
                            break
            else:
                # Just update records (TTL stays the same)
                action_payload = {
                    "records": records_formatted
                }
                
                # Start the set_records action
                action_data = await self._request("POST", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}/actions/set_records", json=action_payload)
                action_id = action_data.get("action", {}).get("id")
                
                # Wait for action to complete
                if action_id:
                    import asyncio
                    for _ in range(10):  # Max 10 seconds wait
                        await asyncio.sleep(1)
                        try:
                            action_status_data = await self._request("GET", f"/actions/{action_id}")
                            action_status = action_status_data.get("action", {}).get("status")
                            if action_status == "success":
                                break
                            elif action_status == "error":
                                error = action_status_data.get("action", {}).get("error")
                                raise Exception(f"Action failed: {error}")
                        except Exception:
                            # If action status check fails, continue anyway
                            break
            
            # Get updated RRSet to return
            data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}")
            rrset_data = data.get("rrset", {})
        else:
            # Create new RRSet using add_records action
            # According to Hetzner API docs: "For convenience, the RRSet will be automatically created if it doesn't exist"
            # POST /zones/{id_or_name}/rrsets/{rr_name}/{rr_type}/actions/add_records
            add_payload = {
                "records": records_formatted
            }
            if ttl:
                add_payload["ttl"] = ttl
            
            # Start the add_records action (this will create the RRSet if it doesn't exist)
            action_data = await self._request("POST", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}/actions/add_records", json=add_payload)
            action_id = action_data.get("action", {}).get("id")
            
            # Wait for action to complete
            if action_id:
                import asyncio
                for _ in range(10):  # Max 10 seconds wait
                    await asyncio.sleep(1)
                    try:
                        action_status_data = await self._request("GET", f"/actions/{action_id}")
                        action_status = action_status_data.get("action", {}).get("status")
                        if action_status == "success":
                            break
                        elif action_status == "error":
                            error = action_status_data.get("action", {}).get("error")
                            raise Exception(f"Action failed: {error}")
                    except Exception:
                        # If action status check fails, continue anyway
                        break
            
            # Get the created/updated RRSet
            data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_rrset_id}")
            rrset_data = data.get("rrset", {})
        
        # Extract records - can be list of strings or list of dicts with 'value' key
        records_raw = rrset_data.get("records", [])
        records_list = []
        for record in records_raw:
            if isinstance(record, dict):
                records_list.append(record.get("value", ""))
            elif isinstance(record, str):
                records_list.append(record)
        
        # Extract comment
        comment_value = rrset_data.get("comment")
        if not comment_value and records_raw and isinstance(records_raw[0], dict):
            comment_value = records_raw[0].get("comment")
        
        return RRSet(
            id=str(rrset_data.get("id")) if rrset_data.get("id") else rrset_id,  # Convert to string
            zone_id=str(zone_id),  # Ensure string
            name=rrset_data.get("name"),
            type=rrset_data.get("type"),
            ttl=rrset_data.get("ttl"),
            records=records_list,
            comment=comment_value
        )
    
    async def delete_rrset(self, zone_id: str, rrset_id: str):
        """Delete an RRSet"""
        await self._request("DELETE", f"/zones/{zone_id}/rrsets/{rrset_id}")
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()

