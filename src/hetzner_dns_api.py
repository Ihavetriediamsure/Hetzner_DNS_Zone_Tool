"""Hetzner DNS API Client for new Hetzner Cloud DNS API"""

import asyncio
import json
import logging
import re
import urllib.parse
import httpx
from typing import Optional, List, Dict, Any
from src.models import Zone, Record, RecordType, RRSet

logger = logging.getLogger(__name__)


def _format_mx_for_api(record) -> str:
    """Format MX record as 'PRIORITY TARGET.' string (DNS Console RRset API)."""
    def _normalize_target(value: str) -> str:
        target = str(value).strip()
        if target and not target.endswith('.'):
            target = f"{target}."
        return target

    if isinstance(record, dict):
        priority = int(record.get("priority", 0))
        value = _normalize_target(record.get("value", ""))
        return f"{priority} {value}".strip()
    s = str(record).strip()
    m = re.match(r"^\s*(\d{1,5})\s+(.+)\s*$", s)
    if m:
        return f"{int(m.group(1))} {_normalize_target(m.group(2))}"
    return _normalize_target(s)


def _format_mx_for_api_object(record) -> dict:
    """Format MX record as {value: 'PRIORITY TARGET.'} object (Cloud RRset API)."""
    def _normalize_target(value: str) -> str:
        target = str(value).strip()
        if target and not target.endswith('.'):
            target = f"{target}."
        return target

    if isinstance(record, dict):
        priority = str(record.get("priority", "")).strip()
        value = _normalize_target(record.get("value", ""))
        combined = f"{priority} {value}".strip()
        return {"value": combined}
    s = str(record).strip()
    m = re.match(r"^\s*(\d{1,5})\s+(.+)\s*$", s)
    if m:
        combined = f"{int(m.group(1))} {_normalize_target(m.group(2))}"
        return {"value": combined}
    return {"value": _normalize_target(s)}


def _format_record_for_display(record, rrset_type: str) -> str:
    """Format API record for UI. MX: 'PRIORITY TARGET'; else value string."""
    if rrset_type == "MX" and isinstance(record, dict) and "priority" in record and "value" in record:
        return f"{record['priority']} {record['value']}"
    if isinstance(record, dict):
        return record.get("value", "")
    return str(record)


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
            err_body = (response.text or "")[:1000]
            logger.error(
                "Hetzner API error: %s %s -> %s: %s",
                method, url, response.status_code, err_body,
            )
            if response.status_code == 400 and "json_error" in err_body:
                req_payload = None
                if "json" in kwargs:
                    req_payload = kwargs["json"]
                elif "content" in kwargs:
                    req_payload = kwargs["content"]
                elif "data" in kwargs:
                    req_payload = kwargs["data"]
                if isinstance(req_payload, (bytes, bytearray)):
                    try:
                        req_payload = req_payload.decode("utf-8", errors="replace")
                    except Exception:
                        req_payload = "<non-utf8-bytes>"
                logger.error("Hetzner API json_error payload: %r", req_payload)
            # Try to get error details from response
            try:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', response.text)
                raise Exception(f"API error ({response.status_code}): {error_msg}")
            except Exception:
                raise Exception(f"API error ({response.status_code}): {response.text}")
        response.raise_for_status()
        if response.status_code == 204:
            return {}
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
            
            # Extract records - can be list of strings or list of dicts with 'value' (MX: 'priority'+'value')
            records_raw = rrset_data.get("records", [])
            rrset_type = rrset_data.get("type", "")
            records = [_format_record_for_display(r, rrset_type) for r in records_raw]
            
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
        # RRSet ID format: "name/type" (e.g., "test/A" or "mail/MX")
        rrset_id = urllib.parse.unquote(rrset_id)
        encoded_id = urllib.parse.quote(rrset_id, safe='/@')
        
        data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_id}")
        rrset_data = data.get("rrset", {})
        
        # Extract records - MX: "PRIORITY TARGET"; else value string
        records_raw = rrset_data.get("records", [])
        rrset_type = rrset_data.get("type", "")
        records = [_format_record_for_display(r, rrset_type) for r in records_raw]
        
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
        """Create or update an RRSet via POST/PUT /zones/{id}/rrsets (Cloud DNS RRset API)."""
        rrset_id = f"{name}/{type}"
        
        # Records-Format für API: MX = "prio target." (Console) or {value, priority} (Cloud)
        records_formatted = []
        records_formatted_objects = []
        for record in records:
            if type == "MX":
                records_formatted.append(_format_mx_for_api(record))
                records_formatted_objects.append(_format_mx_for_api_object(record))
            elif isinstance(record, dict):
                v = record.get("value", "")
                normalized = str(v).rstrip('.') if v else ""
                records_formatted.append(normalized)
                records_formatted_objects.append({"value": normalized})
            else:
                normalized = str(record).rstrip('.')
                records_formatted.append(normalized)
                records_formatted_objects.append({"value": normalized})

        if type == "MX" and self.use_bearer:
            # Cloud API: prefer object format with priority/value
            primary_records = records_formatted_objects
            fallback_records = records_formatted
        else:
            primary_records = records_formatted
            fallback_records = records_formatted_objects
        
        encoded_id = urllib.parse.quote(rrset_id, safe='/@')
        rrset_data = None
        exists = False
        try:
            data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_id}")
            rrset_data = data.get("rrset", {})
            exists = True if rrset_data else False
        except Exception as e:
            if "404" not in str(e):
                raise

        if exists:
            payload = {"ttl": ttl, "records": primary_records}
            if comment is not None:
                payload["comment"] = comment
            payload_json = json.dumps(payload).encode("utf-8")
            try:
                data = await self._request(
                    "PUT",
                    f"/zones/{zone_id}/rrsets/{encoded_id}",
                    content=payload_json,
                    headers={"Content-Type": "application/json"},
                )
                rrset_data = data.get("rrset") or (data.get("rrsets", [None])[0])
            except Exception as e:
                if "json_error" not in str(e):
                    raise
                payload = {"ttl": ttl, "records": fallback_records}
                if comment is not None:
                    payload["comment"] = comment
                payload_json = json.dumps(payload).encode("utf-8")
                data = await self._request(
                    "PUT",
                    f"/zones/{zone_id}/rrsets/{encoded_id}",
                    content=payload_json,
                    headers={"Content-Type": "application/json"},
                )
                rrset_data = data.get("rrset") or (data.get("rrsets", [None])[0])
        else:
            payload = {"name": name, "type": type, "ttl": ttl, "records": primary_records}
            if comment is not None:
                payload["comment"] = comment
            payload_json = json.dumps(payload).encode("utf-8")
            try:
                data = await self._request(
                    "POST",
                    f"/zones/{zone_id}/rrsets",
                    content=payload_json,
                    headers={"Content-Type": "application/json"},
                )
                rrset_data = data.get("rrset") or (data.get("rrsets", [None])[0])
            except Exception as e:
                if "json_error" not in str(e):
                    raise
                payload = {"name": name, "type": type, "ttl": ttl, "records": fallback_records}
                if comment is not None:
                    payload["comment"] = comment
                payload_json = json.dumps(payload).encode("utf-8")
                data = await self._request(
                    "POST",
                    f"/zones/{zone_id}/rrsets",
                    content=payload_json,
                    headers={"Content-Type": "application/json"},
                )
                rrset_data = data.get("rrset") or (data.get("rrsets", [None])[0])

        if not rrset_data:
            data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_id}")
            rrset_data = data.get("rrset", {})
        
        records_raw = rrset_data.get("records", [])
        rrset_type = rrset_data.get("type", type)
        records_list = [_format_record_for_display(r, rrset_type) for r in records_raw]
        comment_value = rrset_data.get("comment")
        if not comment_value and records_raw and isinstance(records_raw[0], dict):
            comment_value = records_raw[0].get("comment")
        
        return RRSet(
            id=str(rrset_data.get("id")) if rrset_data.get("id") else rrset_id,
            zone_id=str(zone_id),
            name=rrset_data.get("name", name),
            type=rrset_data.get("type", type),
            ttl=rrset_data.get("ttl", ttl),
            records=records_list,
            comment=comment_value
        )
    
    async def _create_or_update_via_actions(
        self, zone_id: str, encoded_id: str, rrset_id: str,
        records_formatted: list, ttl: int, rtype: str
    ) -> dict:
        """Fallback: set_records/add_records unter /zones (wenn PUT /dns/zones 404)."""
        rrset_exists = False
        try:
            await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_id}")
            rrset_exists = True
        except Exception:
            pass
        if rrset_exists:
            current = (await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_id}")).get("rrset", {})
            cur_ttl = current.get("ttl")
            if ttl is not None and cur_ttl != ttl:
                await self._request("DELETE", f"/zones/{zone_id}/rrsets/{encoded_id}")
                add_p = {"records": records_formatted, "ttl": ttl}
                act = await self._request("POST", f"/zones/{zone_id}/rrsets/{encoded_id}/actions/add_records", json=add_p)
            else:
                act = await self._request("POST", f"/zones/{zone_id}/rrsets/{encoded_id}/actions/set_records", json={"records": records_formatted})
            aid = (act or {}).get("action", {}).get("id")
            if aid:
                for _ in range(10):
                    await asyncio.sleep(1)
                    try:
                        st = (await self._request("GET", f"/actions/{aid}")).get("action", {}).get("status")
                        if st == "success":
                            break
                        if st == "error":
                            raise Exception("Action failed")
                    except Exception:
                        break
        else:
            add_p = {"records": records_formatted}
            if ttl:
                add_p["ttl"] = ttl
            act = await self._request("POST", f"/zones/{zone_id}/rrsets/{encoded_id}/actions/add_records", json=add_p)
            aid = (act or {}).get("action", {}).get("id")
            if aid:
                for _ in range(10):
                    await asyncio.sleep(1)
                    try:
                        st = (await self._request("GET", f"/actions/{aid}")).get("action", {}).get("status")
                        if st == "success":
                            break
                        if st == "error":
                            raise Exception("Action failed")
                    except Exception:
                        break
        data = await self._request("GET", f"/zones/{zone_id}/rrsets/{encoded_id}")
        return data.get("rrset", {})
    
    async def delete_rrset(self, zone_id: str, rrset_id: str):
        """Delete an RRSet"""
        rrset_id = urllib.parse.unquote(rrset_id)
        await self._request("DELETE", f"/zones/{zone_id}/rrsets/{rrset_id}")
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
