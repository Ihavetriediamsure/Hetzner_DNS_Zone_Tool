"""Auto-Update Service for DNS Records based on Local IP Storage"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from src.hetzner_client import HetznerDNSClient
from src.local_ip_storage import get_local_ip_storage
from src.ip_detector import get_ip_detector
from src.internal_ip_monitor import get_internal_ip_monitor
from src.split_brain_protection import get_split_brain_protection
from src.audit_log import get_audit_log, AuditAction

logger = logging.getLogger(__name__)


class AutoUpdateService:
    """Automatic DNS record update service based on local IP reachability"""
    
    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._check_interval = 60  # Default: 60 seconds
        self._last_check: Optional[datetime] = None
        self._last_results: Dict[str, Any] = {}
    
    async def check_and_update_all(self) -> Dict[str, Any]:
        """
        Check all zones and RRSets with auto-update enabled.
        Update DNS records if:
        - Auto-update is enabled
        - Local IP is reachable
        - Public IP or TTL differs from Hetzner DNS
        """
        results = {
            "checked": 0,
            "updated": 0,
            "skipped": 0,
            "errors": [],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Get split-brain protection instance
            split_brain_protection = get_split_brain_protection()
            
            # Get current public IP - always use automatic detection for auto-update
            # (ignore manual IP setting, as auto-update should use the real server IP)
            detector = get_ip_detector()
            try:
                # Force fresh detection (don't use cache) and ignore manual IP
                current_public_ip = await detector.get_public_ip(use_cache=False)
            except Exception as e:
                logger.error(f"Failed to get public IP: {e}")
                results["errors"].append({"type": "public_ip", "error": str(e)})
                return results
            
            # Get storage
            storage = get_local_ip_storage()
            monitor = get_internal_ip_monitor()
            
            # Get zones that have auto-update enabled (to reduce API calls)
            zones_with_auto_update = storage.get_zones_with_auto_update()
            
            if not zones_with_auto_update:
                logger.debug("No zones with auto-update enabled, skipping check")
                results["skipped"] = 0
                return results
            
            logger.debug(f"Checking {len(zones_with_auto_update)} zone(s) with auto-update enabled: {zones_with_auto_update}")
            
            # Get all zones
            client = HetznerDNSClient()
            try:
                all_zones = await client.list_zones()
                
                # Filter to only zones with auto-update enabled
                zones = [zone for zone in all_zones if zone.id in zones_with_auto_update]
                
                if not zones:
                    logger.debug("No matching zones found in Hetzner DNS")
                    return results
                
                for zone in zones:
                    try:
                        # Get all RRSets for this zone
                        rrsets = await client.list_rrsets(zone.id)
                        
                        # Get local IP settings for this zone
                        local_settings = storage.get_local_ips_for_zone(zone.id)
                        
                        for rrset in rrsets:
                            results["checked"] += 1
                            
                            # Only process A and AAAA records
                            if rrset.type not in ["A", "AAAA"]:
                                results["skipped"] += 1
                                continue
                            
                            # Get settings for this RRSet
                            settings = local_settings.get(rrset.id, {})
                            auto_update_enabled = settings.get("auto_update_enabled", False)
                            local_ip = settings.get("local_ip")
                            ttl_override = settings.get("ttl")
                            
                            # Skip if auto-update is not enabled
                            if not auto_update_enabled:
                                results["skipped"] += 1
                                continue
                            
                            # Skip if no local IP (Monitor IP) is configured
                            if not local_ip or not local_ip.strip():
                                results["skipped"] += 1
                                logger.debug(f"Skipping {rrset.id}: No Monitor IP configured")
                                continue
                            
                            # Check if local IP (Monitor IP) is reachable
                            try:
                                # Get port from storage (if configured), otherwise use default 80
                                monitor_port = settings.get("port") or 80
                                # Use ping method with configured port (for TCP connection test)
                                check_result = await monitor.check_internal_ip_reachable(
                                    local_ip.strip(),
                                    port=monitor_port,
                                    check_method="ping",
                                    timeout=5
                                )
                                
                                if not check_result.get("reachable", False):
                                    results["skipped"] += 1
                                    logger.debug(f"Skipping {rrset.id}: Monitor IP {local_ip} not reachable")
                                    continue
                            except Exception as e:
                                logger.warning(f"Failed to check Monitor IP {local_ip} for {rrset.id}: {e}")
                                results["skipped"] += 1
                                continue
                            
                            # Now check if update is needed
                            needs_update = False
                            update_reason = []
                            
                            # Check IP difference
                            current_dns_ip = None
                            if rrset.records and len(rrset.records) > 0:
                                # Extract IP from records (can be string or dict)
                                first_record = rrset.records[0]
                                if isinstance(first_record, dict):
                                    current_dns_ip = first_record.get("value")
                                else:
                                    current_dns_ip = first_record
                            
                            # Normalize IPs for comparison (strip whitespace, handle None)
                            current_dns_ip_normalized = str(current_dns_ip).strip() if current_dns_ip else None
                            current_public_ip_normalized = str(current_public_ip).strip() if current_public_ip else None
                            
                            should_update_ip = current_dns_ip_normalized != current_public_ip_normalized
                            if should_update_ip:
                                needs_update = True
                                update_reason.append(f"IP: {current_dns_ip_normalized} -> {current_public_ip_normalized}")
                                logger.info(f"IP mismatch detected for {rrset.id}: DNS={current_dns_ip_normalized}, Public={current_public_ip_normalized}")
                            else:
                                logger.debug(f"IP match for {rrset.id}: {current_dns_ip_normalized}")
                            
                            # Check TTL difference (if override is set)
                            should_update_ttl = False
                            if ttl_override is not None:
                                current_ttl = rrset.ttl
                                if current_ttl != ttl_override:
                                    should_update_ttl = True
                                    needs_update = True
                                    update_reason.append(f"TTL: {current_ttl} -> {ttl_override}")
                                    logger.info(f"TTL mismatch detected for {rrset.id}: Current={current_ttl}, Override={ttl_override}")
                                else:
                                    logger.debug(f"TTL match for {rrset.id}: {current_ttl}")
                            
                            # Update if needed
                            if needs_update:
                                # Split-Brain-Schutz: Prüfe andere Peers (nur wenn Peer-Sync aktiviert UND Monitor IP konfiguriert)
                                if should_update_ip and split_brain_protection.is_enabled() and local_ip:
                                    monitor_port = local_settings.get("port", 80)
                                    split_brain_check = await split_brain_protection.check_split_brain(
                                        monitor_ip=local_ip,
                                        port=monitor_port
                                    )
                                    
                                    if split_brain_check.get("split_brain_detected", False):
                                        logger.warning(
                                            f"Split-Brain detected for {rrset.id}: "
                                            f"Monitor IP {local_ip} is alive on multiple peers. "
                                            f"Skipping update to prevent endless loop."
                                        )
                                        # Log to audit log
                                        audit_log = get_audit_log()
                                        audit_log.log(
                                            action=AuditAction.IP_UPDATE_SPLIT_BRAIN_DETECTED,
                                            username="system",
                                            success=False,
                                            details={
                                                "zone_id": zone.id,
                                                "rrset_id": rrset.id,
                                                "monitor_ip": local_ip,
                                                "port": monitor_port,
                                                "alive_peers": split_brain_check.get("alive_peers", []),
                                                "reason": split_brain_check.get("reason", ""),
                                                "source": "auto_update"
                                            }
                                        )
                                        results["skipped"] += 1
                                        continue  # Skip update
                                try:
                                    # Double-check: Only update if values are actually different
                                    # This prevents unnecessary API calls
                                    if not should_update_ip and not should_update_ttl:
                                        logger.debug(f"Skipping update for {rrset.id}: Values match after normalization")
                                        results["skipped"] += 1
                                        continue
                                    
                                    # Prepare records (use public IP)
                                    records_to_set = [current_public_ip]
                                    
                                    # Use TTL override if set, otherwise keep current TTL or default to 3600
                                    ttl_to_use = ttl_override if ttl_override is not None else (rrset.ttl or 3600)
                                    
                                    # Keep existing comment if any
                                    comment_to_use = rrset.comment or ""
                                    
                                    logger.info(f"Updating {rrset.id} ({rrset.name}): {', '.join(update_reason)}")
                                    
                                    # Update RRSet
                                    await client.create_or_update_rrset(
                                        zone_id=zone.id,
                                        name=rrset.name,
                                        type=rrset.type,
                                        records=records_to_set,
                                        ttl=ttl_to_use,
                                        comment=comment_to_use
                                    )
                                    
                                    results["updated"] += 1
                                    logger.info(f"Successfully updated {rrset.id} ({rrset.name}): {', '.join(update_reason)}")
                                    
                                except Exception as e:
                                    error_msg = f"Failed to update {rrset.id}: {str(e)}"
                                    logger.error(error_msg)
                                    results["errors"].append({
                                        "rrset_id": rrset.id,
                                        "zone_id": zone.id,
                                        "error": str(e)
                                    })
                            else:
                                results["skipped"] += 1
                                logger.debug(f"No update needed for {rrset.id}")
                    
                    except Exception as e:
                        logger.error(f"Error processing zone {zone.id}: {e}")
                        results["errors"].append({
                            "zone_id": zone.id,
                            "error": str(e)
                        })
            
            finally:
                await client.close()
        
        except Exception as e:
            logger.error(f"Error in check_and_update_all: {e}")
            results["errors"].append({"type": "general", "error": str(e)})
        
        self._last_check = datetime.now()
        self._last_results = results
        return results
    
    async def start(self, check_interval: int = 60):
        """Start automatic checking"""
        if self._running:
            logger.warning("Auto-update service is already running, stopping old instance first")
            await self.stop()
        
        # Ensure minimum interval of 60 seconds to prevent too frequent updates
        if check_interval < 60:
            logger.warning(f"Auto-update interval {check_interval}s is too short, using minimum of 60s")
            check_interval = 60
        
        self._check_interval = check_interval
        self._running = True
        
        async def run_loop():
            logger.info(f"Auto-update service started (interval: {check_interval}s)")
            
            # Run initial check immediately
            await self.check_and_update_all()
            
            # Then run periodically
            while self._running:
                try:
                    await asyncio.sleep(check_interval)
                    if self._running:
                        logger.debug(f"Running scheduled auto-update check (interval: {check_interval}s)")
                        await self.check_and_update_all()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in auto-update loop: {e}")
                    # Continue running even if one check fails
                    await asyncio.sleep(5)  # Wait a bit before retrying
        
        self._task = asyncio.create_task(run_loop())
        logger.info("Auto-update service task created")
    
    async def stop(self):
        """Stop automatic checking"""
        if not self._running:
            return
        
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("Auto-update service stopped")
    
    def is_running(self) -> bool:
        """Check if service is running"""
        return self._running
    
    def get_status(self) -> Dict[str, Any]:
        """Get service status"""
        return {
            "running": self._running,
            "check_interval": self._check_interval,
            "last_check": self._last_check.isoformat() if self._last_check else None,
            "last_results": self._last_results
        }


# Global instance
_auto_update_service: Optional[AutoUpdateService] = None


def get_auto_update_service() -> AutoUpdateService:
    """Get global auto-update service instance"""
    global _auto_update_service
    if _auto_update_service is None:
        _auto_update_service = AutoUpdateService()
    return _auto_update_service

