"""Pydantic Models for Request/Response"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class RecordType(str, Enum):
    """DNS Record Types"""
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    SRV = "SRV"
    CAA = "CAA"
    DS = "DS"
    HINFO = "HINFO"
    HTTPS = "HTTPS"
    PTR = "PTR"
    RP = "RP"
    SVCB = "SVCB"
    TLSA = "TLSA"


class Zone(BaseModel):
    """DNS Zone Model"""
    id: str
    name: str
    ttl: Optional[int] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    protected: Optional[bool] = None
    labels: Optional[Dict[str, str]] = None


class Record(BaseModel):
    """DNS Record Model"""
    id: Optional[str] = None
    zone_id: str
    type: RecordType
    name: str
    value: str
    ttl: Optional[int] = 3600
    created: Optional[str] = None
    modified: Optional[str] = None
    comment: Optional[str] = None


class RRSet(BaseModel):
    """Resource Record Set Model (new API)"""
    id: Optional[str] = None
    zone_id: str
    name: str
    type: str
    ttl: Optional[int] = None  # TTL can be null, defaults to zone TTL
    records: List[str] = Field(default_factory=list)
    comment: Optional[str] = None


class RecordCreate(BaseModel):
    """Create DNS Record Request"""
    zone_id: str
    type: RecordType
    name: str
    value: str
    ttl: Optional[int] = 3600


class RecordUpdate(BaseModel):
    """Update DNS Record Request"""
    name: Optional[str] = None
    value: Optional[str] = None
    ttl: Optional[int] = None


class IPUpdateRequest(BaseModel):
    """IP Update Request"""
    ip: Optional[str] = None  # If None, uses current public IP


class LoginRequest(BaseModel):
    """Login Request"""
    username: str
    password: str
    totp_token: Optional[str] = None  # 2FA token


class LoginResponse(BaseModel):
    """Login Response"""
    success: bool
    message: str
    requires_2fa: Optional[bool] = False


class SetupRequest(BaseModel):
    """Initial Setup Request"""
    username: str
    password: str


class SetupResponse(BaseModel):
    """Initial Setup Response"""
    success: bool
    message: str


class TwoFactorSetup(BaseModel):
    """2FA Setup Response"""
    secret: str
    qr_code: str  # Base64 encoded QR code
    backup_codes: List[str]


class TwoFactorStatus(BaseModel):
    """2FA Status"""
    enabled: bool


class IPWhitelistEntry(BaseModel):
    """IP Whitelist Entry"""
    ip_or_cidr: str


class IPWhitelistResponse(BaseModel):
    """IP Whitelist Response"""
    enabled: bool
    allowed_ips: List[str]


class IPAccessControlResponse(BaseModel):
    """IP Access Control Response"""
    whitelist_enabled: bool
    blacklist_enabled: bool
    whitelist_ips: List[str]
    blacklist_ips: List[str]
    mode: str  # "whitelist" or "blacklist"


class ChangePasswordRequest(BaseModel):
    """Change Password Request"""
    current_password: str
    new_password: str


class TwoFactorSetupRequest(BaseModel):
    """2FA Setup Request"""
    password: str  # Verify password before enabling 2FA


class TwoFactorVerifyRequest(BaseModel):
    """2FA Verify Request"""
    token: str


class BruteForceConfigResponse(BaseModel):
    """Brute-Force Protection Configuration Response"""
    enabled: bool
    max_login_attempts: int
    max_2fa_attempts: int
    lockout_duration_login: int  # in seconds
    lockout_duration_2fa: int  # in seconds
    window_duration: int  # in seconds


class BruteForceConfigRequest(BaseModel):
    """Brute-Force Protection Configuration Request"""
    enabled: bool
    max_login_attempts: int
    max_2fa_attempts: int
    lockout_duration_login: int  # in minutes (will be converted to seconds)
    lockout_duration_2fa: int  # in minutes (will be converted to seconds)
    window_duration: int  # in minutes (will be converted to seconds)


class SecurityConfigResponse(BaseModel):
    """Security Configuration Response"""
    two_factor_enabled: bool
    ip_access_control: IPAccessControlResponse


class SMTPConfigResponse(BaseModel):
    """SMTP Configuration Response"""
    enabled: bool
    host: str
    port: int
    user: str
    password: str  # Will be masked as "***"
    use_tls: bool
    from_address: str
    to_address: str
    enabled_events: List[str]


class SMTPConfigRequest(BaseModel):
    """SMTP Configuration Request"""
    enabled: bool
    host: str
    port: int
    user: str
    password: str  # Empty string or "***" to keep existing, new password to update
    use_tls: bool
    from_address: str
    to_address: str
    enabled_events: List[str]

class AuditLogConfigResponse(BaseModel):
    """Audit Log Rotation Configuration Response"""
    max_size_mb: int
    max_age_days: int
    rotation_interval_hours: int

class AuditLogConfigRequest(BaseModel):
    """Audit Log Rotation Configuration Request"""
    max_size_mb: int = Field(ge=1, le=1000, description="Maximum log file size in MB")
    max_age_days: int = Field(ge=1, le=365, description="Maximum age of logs in days")
    rotation_interval_hours: int = Field(ge=1, le=168, description="Rotation check interval in hours")

class PeerSyncConfigResponse(BaseModel):
    """Peer-Sync Configuration Response"""
    enabled: bool  # If enabled, automatically sync on every change
    peer_nodes: List[str]
    interval: int  # Not used when enabled - kept for backward compatibility
    timeout: float  # Request timeout in seconds
    ntp_enabled: bool
    ntp_server: str  # NTP server address (e.g., pool.ntp.org)
    timezone: str  # Timezone (e.g., Europe/Berlin, UTC)
    peer_public_keys: Dict[str, Dict[str, str]]  # peer_ip -> {name, public_key} (public_key is X25519 Base64 PEM)

class PeerSyncConfigRequest(BaseModel):
    """Peer-Sync Configuration Request"""
    enabled: bool  # If enabled, automatically sync on every change
    peer_nodes: List[str]
    interval: int = Field(ge=60, le=3600, description="Sync interval in seconds (not used when enabled)")
    timeout: float = Field(ge=1.0, le=30.0, description="Request timeout in seconds")
    # ntp_enabled, ntp_server, timezone removed - now stored in peer_sync_ntp.yaml (synchronized file)
    # max_retries and rate_limit removed - not needed when syncing on every change
    peer_public_keys: Dict[str, Dict[str, str]]  # peer_ip -> {name, public_key} (public_key is X25519 WireGuard format: 32 bytes raw, Base64)

class PeerSyncPublicKeysResponse(BaseModel):
    """Peer-Sync Public Key Response"""
    public_key: str  # Base64-encoded X25519 public key (WireGuard format: 32 bytes raw)

class PeerSyncStatusResponse(BaseModel):
    """Peer-Sync Status Response"""
    enabled: bool
    peer_nodes: List[str]
    overview: Dict[str, Any]
    peer_statuses: List[Dict[str, Any]]
    recent_events: List[Dict[str, Any]]

class PeerSyncSyncNowRequest(BaseModel):
    """Peer-Sync Manual Sync Request"""
    peer: Optional[str] = None  # Optional: sync only with this peer

class PeerSyncTestConnectionRequest(BaseModel):
    """Peer-Sync Test Connection Request"""
    peer: str


class SyncStatus(BaseModel):
    """Sync Status"""
    last_sync: Optional[str] = None
    zones_count: int = 0
    records_count: int = 0
    in_progress: bool = False


class AutoUpdateConfig(BaseModel):
    """Auto Update Configuration"""
    enabled: bool
    interval_minutes: int = 15
    records: List[Dict[str, Any]] = Field(default_factory=list)


class AutoUpdateRecord(BaseModel):
    """Auto Update Record Configuration"""
    zone_id: str
    record_id: str
    record_name: str
    record_type: str
    enabled: bool
    internal_ip: Optional[str] = None
    internal_port: Optional[int] = None
    check_method: Optional[str] = "ping"  # "ping", "http", "tcp"
    check_timeout: Optional[int] = 5
    update_condition: Optional[str] = "always"  # "always", "internal_reachable"


class AutoUpdateStatus(BaseModel):
    """Auto Update Status"""
    enabled: bool
    running: bool
    last_update: Optional[str] = None
    next_update: Optional[str] = None
    records_count: int = 0


class InternalIPStatus(BaseModel):
    """Internal IP Status"""
    ip: str
    reachable: bool
    last_check: Optional[str] = None
    check_method: Optional[str] = None
    response_time: Optional[float] = None


class InternalIPConfig(BaseModel):
    """Internal IP Configuration"""
    zone_id: str
    record_id: str
    internal_ip: str
    internal_port: Optional[int] = None
    check_method: str = "ping"
    check_timeout: int = 5
    update_condition: str = "internal_reachable"


class ConfigResponse(BaseModel):
    """Configuration Response"""
    api_version: str
    server_host: str
    server_port: int
    two_factor_enabled: bool
    ip_whitelist_enabled: bool


class HealthResponse(BaseModel):
    """Health Check Response"""
    status: str
    timestamp: str
    version: str


class ErrorResponse(BaseModel):
    """Error Response"""
    error: str
    message: str
    detail: Optional[str] = None

