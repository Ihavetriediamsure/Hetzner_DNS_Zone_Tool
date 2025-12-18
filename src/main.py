"""Main FastAPI application"""

import os
import sys

# Set environment variables early if not set (before any imports)
# Priority: Environment variable > /config (Docker) > ~/.hetzner-dns (local)
if not os.getenv('CONFIG_PATH'):
    # Check if /config exists (Docker), otherwise use home directory
    if os.path.exists('/config'):
        os.environ['CONFIG_PATH'] = '/config/config.yaml'
    else:
        os.environ['CONFIG_PATH'] = os.path.expanduser('~/.hetzner-dns/config.yaml')
if not os.getenv('ENCRYPTION_KEY_PATH'):
    if os.path.exists('/config'):
        os.environ['ENCRYPTION_KEY_PATH'] = '/config/.encryption_key'
    else:
        os.environ['ENCRYPTION_KEY_PATH'] = os.path.expanduser('~/.hetzner-dns/.encryption_key')
if not os.getenv('AUTH_FILE'):
    if os.path.exists('/config'):
        os.environ['AUTH_FILE'] = '/config/auth.yaml'
    else:
        os.environ['AUTH_FILE'] = os.path.expanduser('~/.hetzner-dns/auth.yaml')

# Reset config manager if it was already imported
if 'src.config_manager' in sys.modules:
    import src.config_manager
    src.config_manager._config_manager = None

from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
from src.models import HealthResponse, LoginRequest, LoginResponse, ChangePasswordRequest, TwoFactorSetupRequest, TwoFactorVerifyRequest, SecurityConfigResponse, IPAccessControlResponse, TwoFactorStatus, IPWhitelistEntry, BruteForceConfigResponse, BruteForceConfigRequest, SMTPConfigResponse, SMTPConfigRequest, SetupRequest, SetupResponse, AuditLogConfigResponse, AuditLogConfigRequest, PeerSyncConfigResponse, PeerSyncConfigRequest, PeerSyncPublicKeysResponse, PeerSyncStatusResponse, PeerSyncSyncNowRequest, PeerSyncTestConnectionRequest
from src.config_manager import get_config_manager
from src.auth import get_auth_manager
from src.two_factor import get_two_factor_auth
from src.ip_whitelist import get_ip_access_control
from src.hetzner_client import HetznerDNSClient
from src.ip_detector import get_ip_detector
from src.internal_ip_monitor import get_internal_ip_monitor
from src.local_ip_storage import get_local_ip_storage
from src.auto_update_service import get_auto_update_service
from src.brute_force_protection import get_brute_force_protection
from src.audit_log import get_audit_log, AuditAction
from src.ip_validator import IPValidator
from src.smtp_notifier import get_smtp_notifier
from src.split_brain_protection import get_split_brain_protection
from src.peer_sync import get_peer_sync
from src.peer_auth import verify_peer_signature, verify_peer_signature_for_body
from src.peer_sync_ntp_storage import get_peer_sync_ntp_storage
from pydantic import BaseModel
from typing import Optional, List, Dict
import logging
import httpx
import asyncio
import yaml
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def trigger_auto_sync_if_enabled():
    """Trigger auto-sync if enabled (non-blocking) - enabled=true means always auto-sync"""
    try:
        peer_sync = get_peer_sync()
        if peer_sync._enabled:
            # Trigger sync in background (non-blocking)
            asyncio.create_task(peer_sync.sync_with_all_peers())
            logger.debug("Auto-sync triggered")
    except Exception as e:
        logger.warning(f"Failed to trigger auto-sync: {e}")

async def trigger_auto_sync_with_result(timeout: float = 2.0):
    """Trigger auto-sync if enabled and wait for result (with timeout) - enabled=true means always auto-sync"""
    try:
        peer_sync = get_peer_sync()
        if peer_sync._enabled:
            # Trigger sync and wait for result with timeout
            sync_task = peer_sync.sync_with_all_peers()
            try:
                result = await asyncio.wait_for(sync_task, timeout=timeout)
                return result
            except asyncio.TimeoutError:
                logger.debug(f"Auto-sync timeout after {timeout}s")
                return None
        return None
    except Exception as e:
        logger.warning(f"Failed to trigger auto-sync: {e}")
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup: Start auto-update service
    auto_update_service = get_auto_update_service()
    try:
        # Load interval from storage
        storage = get_local_ip_storage()
        interval = storage.get_auto_update_interval()
        await auto_update_service.start(check_interval=interval)
        logger.info(f"Auto-update service started on application startup with interval: {interval}s")
    except Exception as e:
        logger.error(f"Failed to start auto-update service: {e}")
    
    # Startup: Initialize audit log (starts rotation task)
    try:
        audit_log = get_audit_log()
        logger.info("Audit log initialized")
    except Exception as e:
        logger.error(f"Failed to initialize audit log: {e}")
    
    # Startup: Start peer-sync service if enabled
    try:
        peer_sync = get_peer_sync()
        if peer_sync._enabled:
            await peer_sync.start()
            logger.info("Peer-Sync service started on application startup")
        else:
            logger.info("Peer-Sync service is disabled")
    except Exception as e:
        logger.error(f"Failed to start peer-sync service: {e}")
    
    yield
    
    # Shutdown: Stop auto-update service
    try:
        await auto_update_service.stop()
        logger.info("Auto-update service stopped on application shutdown")
    except Exception as e:
        logger.error(f"Error stopping auto-update service: {e}")
    
    # Shutdown: Stop peer-sync service
    try:
        peer_sync = get_peer_sync()
        await peer_sync.stop()
        logger.info("Peer-Sync service stopped on application shutdown")
    except Exception as e:
        logger.error(f"Error stopping peer-sync service: {e}")
    
    # Shutdown: Stop audit log rotation task
    try:
        audit_log = get_audit_log()
        audit_log.stop_rotation_task()
        logger.info("Audit log rotation task stopped")
    except Exception as e:
        logger.error(f"Error stopping audit log rotation task: {e}")


app = FastAPI(title="Hetzner DNS Zone Tool", version="1.0.0", lifespan=lifespan)

# Session middleware - Load secret from config file (for Docker) or environment variable
config_manager = get_config_manager()
session_secret = config_manager.get_session_secret()
app.add_middleware(SessionMiddleware, secret_key=session_secret)


# IP Access Control Middleware
@app.middleware("http")
async def ip_access_control_middleware(request: Request, call_next):
    """Check IP whitelist/blacklist before processing request"""
    # Skip IP check for health endpoint, login page, setup page, and setup API
    if request.url.path in ["/health", "/login", "/setup", "/favicon.ico"] or request.url.path.startswith("/api/v1/setup"):
        return await call_next(request)
    
    # Skip IP check for static files
    if request.url.path.startswith("/static/"):
        return await call_next(request)
    
    # Get client IP
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    # Check X-Forwarded-For header (for reverse proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        client_ip = forwarded_for.split(",")[0].strip()
    
    # Check IP access control
    try:
        ip_access = get_ip_access_control()
        if not ip_access.is_ip_allowed(client_ip):
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "message": f"IP {client_ip} is not allowed"}
            )
    except Exception as e:
        logger.error(f"Error checking IP access control: {e}")
        # On error, allow access (fail open)
    
    return await call_next(request)

# Mount static files
static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main page or setup page if setup is required"""
    # Check if setup is required
    auth_manager = get_auth_manager()
    if auth_manager.needs_setup():
        # Redirect to setup page
        setup_path = os.path.join(os.path.dirname(__file__), "static", "setup.html")
        if os.path.exists(setup_path):
            with open(setup_path, 'r', encoding='utf-8') as f:
                return f.read()
        return "<h1>Initial Setup Required</h1><p>Please configure the application first.</p>"
    
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "<h1>Hetzner DNS Zone Tool</h1><p>Web-GUI wird geladen...</p>"


@app.get("/favicon.ico")
async def favicon():
    """Favicon endpoint - returns 204 No Content"""
    from fastapi.responses import Response
    return Response(status_code=204)

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve login page or setup page if setup is required"""
    # Check if setup is required
    auth_manager = get_auth_manager()
    if auth_manager.needs_setup():
        # Redirect to setup page
        setup_path = os.path.join(os.path.dirname(__file__), "static", "setup.html")
        if os.path.exists(setup_path):
            with open(setup_path, 'r', encoding='utf-8') as f:
                return f.read()
        return "<h1>Initial Setup Required</h1><p>Please configure the application first.</p>"
    
    login_path = os.path.join(os.path.dirname(__file__), "static", "login.html")
    if os.path.exists(login_path):
        with open(login_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "<h1>Login</h1><p>Login-Seite wird geladen...</p>"


@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    """Serve setup page"""
    setup_path = os.path.join(os.path.dirname(__file__), "static", "setup.html")
    if os.path.exists(setup_path):
        with open(setup_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "<h1>Initial Setup</h1><p>Setup-Seite wird geladen...</p>"


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint"""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
    )


@app.get("/api/v1/config/machine-name")
async def get_machine_name(request: Request):
    """Get machine name configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    config = get_config_manager()
    app_config = config.load_config()
    machine_name = app_config.get('server', {}).get('machine_name', '')
    
    return {"machine_name": machine_name}


@app.put("/api/v1/config/machine-name")
async def set_machine_name(request: Request, machine_name_data: Dict[str, str]):
    """Set machine name configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    config = get_config_manager()
    
    try:
        machine_name = machine_name_data.get('machine_name', '').strip()
        app_config = config.load_config()
        
        if 'server' not in app_config:
            app_config['server'] = {}
        
        app_config['server']['machine_name'] = machine_name
        config._config = app_config
        config.save_config()
        
        # Reload SMTP notifier to get new machine name
        from src.smtp_notifier import get_smtp_notifier
        smtp_notifier = get_smtp_notifier()
        smtp_notifier._load_config()
        
        audit_log.log(
            action=AuditAction.IP_WHITELIST_TOGGLE,  # Reuse action type for config change
            username=username,
            request=request,
            success=True,
            details={"machine_name": machine_name}
        )
        
        return {"success": True, "message": "Machine name updated", "machine_name": machine_name}
    except Exception as e:
        audit_log.log(
            action=AuditAction.IP_WHITELIST_TOGGLE,
            username=username,
            request=request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Failed to update machine name: {str(e)}")


@app.get("/api/v1/config/api-tokens")
async def get_api_tokens():
    """Get all API tokens"""
    config = get_config_manager()
    tokens = config.get_all_tokens()
    
    # Also include new_api format for backward compatibility
    new_info = config.get_api_token_info('new')
    
    return {
        "tokens": tokens,
        "new_api": {
            "base_url": new_info.get('base_url', 'https://api.hetzner.cloud/v1'),
            "token_set": new_info.get('token_set', False),
            "name": new_info.get('name', ''),
            "masked_token": new_info.get('masked_token', '')
        }
    }


@app.post("/api/v1/config/api-tokens")
async def set_api_tokens(request: Request):
    """Add a new API token or set old/new tokens (backward compatibility)"""
    data = await request.json()
    config = get_config_manager()
    
    # New format: add new token
    if 'token' in data and 'name' in data:
        token = data.get('token', '').strip()
        name = data.get('name', '').strip()
        api_type = data.get('type', 'new').strip()
        base_url = data.get('base_url', '').strip()
        
        if not token:
            raise HTTPException(status_code=400, detail="Token is required")
        if not name:
            raise HTTPException(status_code=400, detail="Token name is required")
        
        # Check if token already exists
        from src.encryption import get_encryption_manager
        encryption = get_encryption_manager()
        config_data = config.load_config()
        tokens_list = config_data.get('api', {}).get('tokens', [])
        
        for token_config in tokens_list:
            token_encrypted = token_config.get('token', '')
            if token_encrypted and token_encrypted.startswith('encrypted:'):
                try:
                    encrypted_part = token_encrypted.replace('encrypted:', '')
                    decrypted_token = encryption.decrypt_token(encrypted_part)
                    if decrypted_token == token:
                        raise HTTPException(status_code=400, detail="This token is already in use")
                except HTTPException:
                    # Re-raise HTTPException (duplicate token found)
                    raise
                except Exception:
                    # Skip tokens that can't be decrypted
                    continue
        
        token_id = config.add_token(token, name, api_type, base_url if base_url else None)
        
        # Audit log
        username = request.session.get("username", "unknown") if hasattr(request, 'session') else "unknown"
        audit_log = get_audit_log()
        audit_log.log(
            action=AuditAction.TOKEN_ADD,
            username=username,
            request=request,
            success=True,
            details={"token_id": token_id, "name": name}
        )
        
        return {"success": True, "message": "Token saved", "token_id": token_id}
    
    # Legacy format: backward compatibility (only new token)
    new_token = data.get('new_token', '').strip() if data.get('new_token') else ''
    new_name = data.get('new_name', '').strip() if data.get('new_name') else ''
    
    if new_token:
        config.set_api_token(
            new_token,
            api_type='new',
            base_url='https://api.hetzner.cloud/v1',
            name=new_name if new_name else None
        )
        return {"success": True, "message": "Token saved"}
    
    raise HTTPException(status_code=400, detail="Token is required")


@app.delete("/api/v1/config/api-tokens/{token_id}")
async def delete_api_token(token_id: str, request: Request):
    """Delete API token by ID"""
    config = get_config_manager()
    
    # Try new format first
    username = request.session.get("username", "unknown") if hasattr(request, 'session') else "unknown"
    audit_log = get_audit_log()
    
    if config.delete_token(token_id):
        audit_log.log(
            action=AuditAction.TOKEN_DELETE,
            username=username,
            request=request,
            success=True,
            details={"token_id": token_id}
        )
        return {"success": True, "message": "Token deleted"}
    
    # Fallback to legacy format for backward compatibility
    if token_id == 'new':
        config.delete_api_token(token_id)
        audit_log.log(
            action=AuditAction.TOKEN_DELETE,
            username=username,
            request=request,
            success=True,
            details={"token_id": token_id}
        )
        return {"success": True, "message": "API token deleted"}
    
    raise HTTPException(status_code=404, detail="Token not found")


@app.put("/api/v1/config/api-tokens/{token_id}")
async def update_api_token(token_id: str, request: Request):
    """Update an existing API token"""
    username = request.session.get("username", "unknown") if hasattr(request, 'session') else "unknown"
    audit_log = get_audit_log()
    
    data = await request.json()
    config = get_config_manager()
    
    token = data.get('token', '').strip() if data.get('token') else None
    name = data.get('name', '').strip() if data.get('name') else None
    base_url = data.get('base_url', '').strip() if data.get('base_url') else None
    
    if config.update_token(token_id, token, name, base_url):
        audit_log.log(
            action=AuditAction.TOKEN_UPDATE,
            username=username,
            request=request,
            success=True,
            details={"token_id": token_id, "name_updated": name is not None}
        )
        return {"success": True, "message": "Token updated"}
    
    raise HTTPException(status_code=404, detail="Token not found")


@app.post("/api/v1/config/test-api-tokens")
async def test_api_tokens(request: Request):
    """Test API tokens (legacy endpoint - deprecated)"""
    return {"error": "This endpoint is deprecated. Use the new token system instead."}, 400


@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def login(request: Request, login_data: LoginRequest):
    """Login endpoint"""
    auth_manager = get_auth_manager()
    brute_force = get_brute_force_protection()
    audit_log = get_audit_log()
    
    # Get client IP
    client_ip = request.client.host if request.client else "127.0.0.1"
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    # Check brute-force protection for login
    allowed, error_msg = brute_force.check_login_allowed(client_ip, login_data.username)
    if not allowed:
        audit_log.log(
            action=AuditAction.LOGIN_FAILURE,
            username=login_data.username,
            ip=client_ip,
            request=request,
            success=False,
            error=error_msg
        )
        return LoginResponse(
            success=False,
            message=error_msg
        )
    
    # Verify password
    if not auth_manager.verify_password(login_data.username, login_data.password):
        brute_force.record_login_failure(client_ip, login_data.username)
        audit_log.log(
            action=AuditAction.LOGIN_FAILURE,
            username=login_data.username,
            ip=client_ip,
            request=request,
            success=False,
            error="Invalid password"
        )
        return LoginResponse(
            success=False,
            message="Ungültiger Benutzername oder Passwort"
        )
    
    # Check if 2FA is enabled
    if auth_manager.is_2fa_enabled(login_data.username):
        if not login_data.totp_token:
            # Password correct, but 2FA required
            audit_log.log(
                action=AuditAction.LOGIN_FAILURE,
                username=login_data.username,
                ip=client_ip,
                request=request,
                success=False,
                error="2FA code required"
            )
            return LoginResponse(
                success=False,
                message="2FA-Code erforderlich",
                requires_2fa=True
            )
        
        # Check if token is a backup code (32 characters, alphanumeric)
        token_stripped = login_data.totp_token.strip() if login_data.totp_token else ""
        is_backup_code = len(token_stripped) == 32 and token_stripped.isalnum()
        
        # Check brute-force protection (separate for 2FA and backup codes)
        if is_backup_code:
            # Check brute-force protection for backup codes
            allowed, error_msg = brute_force.check_backup_code_allowed(client_ip, login_data.username)
            if not allowed:
                audit_log.log(
                    action=AuditAction.TWO_FA_VERIFY_FAILURE,
                    username=login_data.username,
                    ip=client_ip,
                    request=request,
                    success=False,
                    error=error_msg
                )
                return LoginResponse(
                    success=False,
                    message=error_msg
                )
        else:
            # Check brute-force protection for 2FA (TOTP)
            allowed, error_msg = brute_force.check_2fa_allowed(client_ip, login_data.username)
            if not allowed:
                audit_log.log(
                    action=AuditAction.TWO_FA_VERIFY_FAILURE,
                    username=login_data.username,
                    ip=client_ip,
                    request=request,
                    success=False,
                    error=error_msg
                )
                return LoginResponse(
                    success=False,
                    message=error_msg
                )
        
        # Verify 2FA token
        if not auth_manager.verify_2fa(login_data.username, login_data.totp_token):
            # Record failure in appropriate counter
            if is_backup_code:
                brute_force.record_backup_code_failure(client_ip, login_data.username)
            else:
                brute_force.record_2fa_failure(client_ip, login_data.username)
            audit_log.log(
                action=AuditAction.TWO_FA_VERIFY_FAILURE,
                username=login_data.username,
                ip=client_ip,
                request=request,
                success=False,
                error="Invalid 2FA token" if not is_backup_code else "Invalid backup code"
            )
            return LoginResponse(
                success=False,
                message="Ungültiger 2FA-Code" if not is_backup_code else "Ungültiger Backup-Code"
            )
        
        # 2FA/Backup code successful - clear both counters
        if is_backup_code:
            brute_force.record_backup_code_success(client_ip, login_data.username)
        else:
            brute_force.record_2fa_success(client_ip, login_data.username)
        audit_log.log(
            action=AuditAction.TWO_FA_VERIFY_SUCCESS,
            username=login_data.username,
            ip=client_ip,
            request=request,
            success=True
        )
    
    # Login successful - clear brute-force counters
    brute_force.record_login_success(client_ip, login_data.username)
    
    # Create session
    request.session["authenticated"] = True
    request.session["username"] = login_data.username
    
    audit_log.log(
        action=AuditAction.LOGIN_SUCCESS,
        username=login_data.username,
        ip=client_ip,
        request=request,
        success=True
    )
    
    return LoginResponse(
        success=True,
        message="Erfolgreich angemeldet"
    )


@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    """Logout endpoint"""
    username = request.session.get("username", "unknown")
    audit_log = get_audit_log()
    
    audit_log.log(
        action=AuditAction.LOGOUT,
        username=username,
        request=request,
        success=True
    )
    
    request.session.clear()
    return {"success": True, "message": "Erfolgreich abgemeldet"}


@app.get("/api/v1/auth/status")
async def auth_status(request: Request):
    """Check authentication status"""
    # Check if setup is required
    auth_manager = get_auth_manager()
    needs_setup = auth_manager.needs_setup()
    
    if needs_setup:
        return {
            "authenticated": False,
            "username": None,
            "needs_setup": True
        }
    
    authenticated = request.session.get("authenticated", False)
    username = request.session.get("username", None)
    
    return {
        "authenticated": authenticated,
        "username": username,
        "needs_setup": False
    }


@app.get("/api/v1/setup/status")
async def setup_status():
    """Check if initial setup is required"""
    auth_manager = get_auth_manager()
    needs_setup = auth_manager.needs_setup()
    return {"needs_setup": needs_setup}


@app.post("/api/v1/setup", response_model=SetupResponse)
async def initial_setup(request: Request, setup_data: SetupRequest):
    """Create initial admin user during setup"""
    auth_manager = get_auth_manager()
    config_manager = get_config_manager()
    
    # Check if setup is already completed
    if not auth_manager.needs_setup():
        raise HTTPException(status_code=400, detail="Setup already completed")
    
    try:
        # Validate username and password (validation happens in create_initial_user)
        # Generate and save session secret if not already present
        # This ensures every installation has a unique secret
        config_manager.ensure_session_secret()
        
        # Create initial user
        success = auth_manager.create_initial_user(
            username=setup_data.username.strip(),
            password=setup_data.password
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to create initial user")
        
        # Log setup completion
        audit_log = get_audit_log()
        audit_log.log(
            action=AuditAction.PASSWORD_CHANGE,  # Reuse action type for initial setup
            username=setup_data.username.strip(),
            request=request,
            success=True,
            details={"initial_setup": True}
        )
        
        return SetupResponse(
            success=True,
            message="Initial setup completed successfully. You can now log in."
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Setup failed: {str(e)}")


@app.get("/api/v1/zones")
async def list_zones(token_id: Optional[str] = None):
    """List all DNS zones (new API)"""
    try:
        client = HetznerDNSClient(token_id=token_id)
        try:
            zones = await client.list_zones()
            return {
                "zones": [zone.dict() for zone in zones],
                "count": len(zones)
            }
        finally:
            await client.close()
    except ValueError as e:
        # Token nicht konfiguriert
        if "token not configured" in str(e).lower():
            raise HTTPException(status_code=400, detail="New API token not configured. Please enter token in configuration tab.")
        raise HTTPException(status_code=500, detail=f"Error loading zones: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading zones: {str(e)}")




class CreateZoneRequest(BaseModel):
    name: str
    ttl: Optional[int] = None


@app.post("/api/v1/zones")
async def create_zone(request: CreateZoneRequest, http_request: Request = None, token_id: Optional[str] = None):
    """Create a new DNS zone"""
    try:
        # Validate zone name
        if not request.name or not request.name.strip():
            raise HTTPException(status_code=400, detail="Zone name cannot be empty.")
        
        # Basic domain name validation
        import re
        domain_pattern = r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, request.name.lower()):
            raise HTTPException(status_code=400, detail="Invalid zone name. Must be a valid domain name (e.g. example.com).")
        
        # Validate token_id is provided
        if not token_id:
            raise HTTPException(status_code=400, detail="API token must be selected. Please select a token when creating a zone.")
        
        username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
        audit_log = get_audit_log()
        
        client = HetznerDNSClient(token_id=token_id)
        try:
            # Create zone
            new_zone = await client.create_zone(
                name=request.name.strip().lower(),
                ttl=request.ttl
            )
            
            audit_log.log(
                action=AuditAction.ZONE_CREATE,
                username=username,
                request=http_request,
                success=True,
                details={"zone_id": new_zone.id, "zone_name": new_zone.name, "token_id": token_id}
            )
            
            return {"zone": new_zone.dict(), "success": True}
        finally:
            await client.close()
    except HTTPException:
        raise
    except ValueError as e:
        if "token not configured" in str(e).lower():
            raise HTTPException(status_code=400, detail="Neuer API-Token nicht konfiguriert.")
        raise HTTPException(status_code=500, detail=f"Fehler beim Erstellen der Zone: {str(e)}")
    except Exception as e:
        username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
        audit_log = get_audit_log()
        audit_log.log(
            action=AuditAction.ZONE_CREATE,
            username=username,
            request=http_request,
            success=False,
            error=str(e),
            details={"zone_name": request.name if request.name else "unknown"}
        )
        raise HTTPException(status_code=500, detail=f"Fehler beim Erstellen der Zone: {str(e)}")


@app.delete("/api/v1/zones/{zone_id}")
async def delete_zone(zone_id: str, request: Request, token_id: Optional[str] = None):
    """Delete a DNS zone"""
    try:
        # Get zone name for confirmation
        client = HetznerDNSClient(token_id=token_id)
        try:
            zone = await client.get_zone(zone_id)
            zone_name = zone.name
        finally:
            await client.close()
        
        # Get confirmation name from request body
        try:
            body = await request.json()
            confirmation_name = body.get("confirmation_name", "").strip()
        except:
            raise HTTPException(status_code=400, detail="Confirmation name required.")
        
        # Validate confirmation
        if confirmation_name != zone_name:
            raise HTTPException(status_code=400, detail=f"Confirmation failed. Please enter '{zone_name}'.")
        
        # Delete zone
        username = request.session.get("username", "unknown") if hasattr(request, 'session') else "unknown"
        audit_log = get_audit_log()
        
        client = HetznerDNSClient(token_id=token_id)
        try:
            await client.delete_zone(zone_id)
            
            audit_log.log(
                action=AuditAction.ZONE_DELETE,
                username=username,
                request=request,
                success=True,
                details={"zone_id": zone_id, "zone_name": zone_name, "token_id": token_id}
            )
            
            return {"success": True, "message": f"Zone '{zone_name}' deleted."}
        finally:
            await client.close()
    except ValueError as e:
        if "token not configured" in str(e).lower():
            raise HTTPException(status_code=400, detail="Neuer API-Token nicht konfiguriert.")
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen der Zone: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen der Zone: {str(e)}")


@app.get("/api/v1/public-ip")
async def get_public_ip():
    """Get current public IP address (always shows automatically detected IP)"""
    try:
        # Always detect IP automatically (ignore manual IP setting for display)
        detector = get_ip_detector()
        ip = await detector.get_public_ip()
        
        # Get refresh interval
        storage = get_local_ip_storage()
        interval = storage.get_public_ip_refresh_interval()
        
        return {"ip": ip, "refresh_interval": interval, "manual": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Abrufen der öffentlichen IP: {str(e)}")


class RefreshIntervalRequest(BaseModel):
    interval: int


class SetPublicIPRequest(BaseModel):
    ip: Optional[str] = None


@app.put("/api/v1/public-ip/refresh-interval")
async def set_public_ip_refresh_interval(request: RefreshIntervalRequest):
    """Set public IP refresh interval in seconds"""
    try:
        if request.interval < 10:
            raise HTTPException(status_code=400, detail="Intervall muss mindestens 10 Sekunden sein")
        if request.interval > 3600:
            raise HTTPException(status_code=400, detail="Intervall darf maximal 3600 Sekunden (1 Stunde) sein")
        
        storage = get_local_ip_storage()
        storage.set_public_ip_refresh_interval(request.interval)
        
        return {"success": True, "interval": request.interval}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Setzen des Intervalls: {str(e)}")


@app.put("/api/v1/public-ip")
async def set_public_ip(request: SetPublicIPRequest, http_request: Request):
    """Set manual public IP address"""
    username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
    audit_log = get_audit_log()
    
    try:
        storage = get_local_ip_storage()
        
        if request.ip:
            # Validate IP is public (not private)
            is_valid, error_msg = IPValidator.validate_public_ip(request.ip)
            if not is_valid:
                raise HTTPException(status_code=400, detail=error_msg)
            storage.set_manual_public_ip(request.ip)
            
            audit_log.log(
                action=AuditAction.IP_UPDATE,  # Reuse for manual IP setting
                username=username,
                request=http_request,
                success=True,
                details={"ip": request.ip, "source": "manual"}
            )
        else:
            storage.clear_manual_public_ip()
            
            audit_log.log(
                action=AuditAction.IP_UPDATE,
                username=username,
                request=http_request,
                success=True,
                details={"ip": "cleared", "source": "manual"}
            )
        
        # Trigger auto-sync if enabled
        await trigger_auto_sync_if_enabled()
        
        return {"success": True, "ip": request.ip, "message": "IP gespeichert" if request.ip else "Manuelle IP entfernt, automatische Erkennung aktiviert"}
    except HTTPException:
        raise
    except Exception as e:
        audit_log.log(
            action=AuditAction.IP_UPDATE,
            username=username,
            request=http_request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Fehler beim Setzen der IP: {str(e)}")




@app.get("/api/v1/zones/{zone_id}/rrsets")
async def list_zone_rrsets(zone_id: str, token_id: Optional[str] = None):
    """List all RRSets for a zone"""
    try:
        client = HetznerDNSClient(token_id=token_id)
        try:
            rrsets = await client.list_rrsets(zone_id)
            
            # Load local IPs and settings for this zone
            # Force recreation of storage instance to ensure correct path
            import os
            env_path = os.getenv("LOCAL_IP_STORAGE_PATH")
            if env_path:
                storage = get_local_ip_storage(env_path)
            else:
                storage = get_local_ip_storage()
            local_ips_data = storage.get_local_ips_for_zone(zone_id)
            
            # Get public IP for display
            detector = get_ip_detector()
            try:
                public_ip = await detector.get_public_ip()
            except:
                public_ip = None
            
            # Add local_ip, auto_update, and ttl to each RRSet
            rrsets_dict = []
            existing_rrset_ids = set()
            
            for rrset in rrsets:
                rrset_dict = rrset.dict()
                rrset_data = local_ips_data.get(rrset.id, {})
                rrset_dict["local_ip"] = rrset_data.get("local_ip")
                rrset_dict["port"] = rrset_data.get("port")
                rrset_dict["auto_update_enabled"] = rrset_data.get("auto_update_enabled", False)
                # Only set ttl_override if it exists and is not None
                # This allows frontend to distinguish between "not set" (undefined) and "explicitly cleared" (null)
                ttl_override = rrset_data.get("ttl")
                if ttl_override is not None:
                    rrset_dict["ttl_override"] = ttl_override
                rrset_dict["public_ip"] = public_ip  # Add public IP for display
                rrset_dict["exists_in_dns"] = True  # Mark as existing in DNS
                rrsets_dict.append(rrset_dict)
                existing_rrset_ids.add(rrset.id)
            
            # Add records from config that don't exist in Hetzner DNS anymore
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Checking for deleted records. Existing RRSet IDs: {existing_rrset_ids}")
            logger.info(f"Local IPs data keys: {list(local_ips_data.keys())}")
            
            deleted_count = 0
            for rrset_id, rrset_data in local_ips_data.items():
                if rrset_id not in existing_rrset_ids:
                    logger.info(f"Found deleted record: {rrset_id}")
                    deleted_count += 1
                    # Parse name and type from rrset_id (format: "name/type")
                    parts = rrset_id.rsplit('/', 1)
                    if len(parts) == 2:
                        name, record_type = parts
                    else:
                        name = rrset_id
                        record_type = "A"  # Default type
                    
                    # Create a "deleted" RRSet entry
                    deleted_rrset = {
                        "id": rrset_id,
                        "zone_id": zone_id,
                        "name": name,
                        "type": record_type,
                        "ttl": None,
                        "records": [],
                        "comment": "",
                        "local_ip": rrset_data.get("local_ip"),
                        "port": rrset_data.get("port"),
                        "auto_update_enabled": rrset_data.get("auto_update_enabled", False),
                        # Only set ttl_override if it exists and is not None
                        "public_ip": public_ip,
                        "exists_in_dns": False  # Mark as not existing in DNS
                    }
                    rrsets_dict.append(deleted_rrset)
                    logger.info(f"Added deleted record to response: {rrset_id} (name={name}, type={record_type})")
            
            logger.info(f"Total deleted records added: {deleted_count}")
            
            return {
                "rrsets": rrsets_dict,
                "count": len(rrsets_dict)
            }
        finally:
            await client.close()
    except ValueError as e:
        if "token not configured" in str(e).lower():
            raise HTTPException(status_code=400, detail="Neuer API-Token nicht konfiguriert.")
        raise HTTPException(status_code=500, detail=f"Fehler beim Laden der RRSets: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Laden der RRSets: {str(e)}")


class UpdateRRSetRequest(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    records: List[str]
    ttl: Optional[int] = None
    comment: Optional[str] = None


class CheckIPRequest(BaseModel):
    ip: str
    port: Optional[int] = None
    check_method: str = "ping"
    timeout: int = 5
    previous_status: Optional[bool] = None


class SaveLocalIPRequest(BaseModel):
    local_ip: str
    port: Optional[int] = None


class SetAutoUpdateRequest(BaseModel):
    enabled: bool


class SetTTLRequest(BaseModel):
    ttl: Optional[int] = None


class SetCommentRequest(BaseModel):
    comment: Optional[str] = None


class SetIPRequest(BaseModel):
    ip: str


class CreateRRSetRequest(BaseModel):
    name: str
    type: str
    records: List[str]
    ttl: Optional[int] = 3600
    comment: Optional[str] = None


@app.post("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/check-ip")
async def check_ip_status(zone_id: str, rrset_id: str, request: CheckIPRequest, http_request: Request):
    """Check if an IP address is reachable"""
    try:
        monitor = get_internal_ip_monitor()
        result = await monitor.check_internal_ip_reachable(
            request.ip,
            port=request.port,
            check_method=request.check_method,
            timeout=request.timeout
        )
        
        # Log monitor IP status changes
        username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
        audit_log = get_audit_log()
        is_reachable = result.get("reachable", False)
        
        # Log status change events
        if request.previous_status is not None:
            # IP status changed
            if request.previous_status is True and not is_reachable:
                # IP went from online to offline
                audit_log.log(
                    action=AuditAction.MONITOR_IP_OFFLINE,
                    username=username,
                    request=http_request,
                    success=False,
                    details={
                        "zone_id": zone_id,
                        "rrset_id": rrset_id,
                        "ip": request.ip,
                        "port": request.port,
                        "check_method": request.check_method,
                        "response_time_ms": result.get("response_time", 0) * 1000 if result.get("response_time") else None
                    }
                )
            elif request.previous_status is False and is_reachable:
                # IP went from offline to online
                audit_log.log(
                    action=AuditAction.MONITOR_IP_ONLINE,
                    username=username,
                    request=http_request,
                    success=True,
                    details={
                        "zone_id": zone_id,
                        "rrset_id": rrset_id,
                        "ip": request.ip,
                        "port": request.port,
                        "check_method": request.check_method,
                        "response_time_ms": result.get("response_time", 0) * 1000 if result.get("response_time") else None
                    }
                )
        
        # Log every status check (for monitoring and debugging)
        audit_log.log(
            action=AuditAction.MONITOR_IP_STATUS_CHECK,
            username=username,
            request=http_request,
            success=is_reachable,
            details={
                "zone_id": zone_id,
                "rrset_id": rrset_id,
                "ip": request.ip,
                "port": request.port,
                "check_method": request.check_method,
                "reachable": is_reachable,
                "response_time_ms": result.get("response_time", 0) * 1000 if result.get("response_time") else None,
                "previous_status": request.previous_status
            }
        )
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Prüfen der IP: {str(e)}")


@app.put("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/auto-update")
async def set_auto_update(zone_id: str, rrset_id: str, request: SetAutoUpdateRequest, http_request: Request):
    """Set auto-update enabled for a DNS record"""
    username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
    audit_log = get_audit_log()
    
    try:
        storage = get_local_ip_storage()
        storage.set_auto_update(zone_id, rrset_id, request.enabled)
        
        action = AuditAction.AUTO_UPDATE_ENABLE if request.enabled else AuditAction.AUTO_UPDATE_DISABLE
        audit_log.log(
            action=action,
            username=username,
            request=http_request,
            success=True,
            details={"zone_id": zone_id, "rrset_id": rrset_id, "enabled": request.enabled}
        )
        
        # Trigger auto-sync if enabled
        await trigger_auto_sync_if_enabled()
        
        return {"success": True, "enabled": request.enabled, "zone_id": zone_id, "rrset_id": rrset_id}
    except Exception as e:
        audit_log.log(
            action=AuditAction.AUTO_UPDATE_ENABLE if request.enabled else AuditAction.AUTO_UPDATE_DISABLE,
            username=username,
            request=http_request,
            success=False,
            error=str(e),
            details={"zone_id": zone_id, "rrset_id": rrset_id}
        )
        raise HTTPException(status_code=500, detail=f"Fehler beim Setzen der Auto-Update-Einstellung: {str(e)}")


@app.put("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/ttl")
async def set_ttl(zone_id: str, rrset_id: str, request: SetTTLRequest, http_request: Request, token_id: Optional[str] = None):
    """Set TTL for a DNS record"""
    try:
        allowed_ttl_values = [60, 300, 600, 1800, 3600, 86400]
        if request.ttl is not None and request.ttl not in allowed_ttl_values:
            raise HTTPException(status_code=400, detail="TTL must be one of the allowed values: 60, 300, 600, 1800, 3600, 86400 seconds")
        
        # Update RRSet if TTL is provided
        if request.ttl is not None:
            # rrset_id is already decoded by FastAPI :path
            client = HetznerDNSClient(token_id=token_id)
            try:
                # Get current RRSet from list to preserve all data
                rrsets = await client.list_rrsets(zone_id)
                current_rrset = None
                for rrset in rrsets:
                    if rrset.id == rrset_id:
                        current_rrset = rrset
                        break
                
                if not current_rrset:
                    raise HTTPException(status_code=404, detail=f"RRSet {rrset_id} nicht gefunden")
                
                # Update with new TTL
                updated_rrset = await client.create_or_update_rrset(
                    zone_id=zone_id,
                    name=current_rrset.name,
                    type=current_rrset.type,
                    records=current_rrset.records,
                    ttl=request.ttl,
                    comment=current_rrset.comment
                )
            finally:
                await client.close()
        
        # Store TTL override
        storage = get_local_ip_storage()
        storage.set_ttl(zone_id, rrset_id, request.ttl)
        
        username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
        audit_log = get_audit_log()
        audit_log.log(
            action=AuditAction.TTL_UPDATE,
            username=username,
            request=http_request,
            success=True,
            details={"zone_id": zone_id, "rrset_id": rrset_id, "ttl": request.ttl, "token_id": token_id}
        )
        
        # Trigger auto-sync if enabled
        await trigger_auto_sync_if_enabled()
        
        return {"success": True, "ttl": request.ttl, "zone_id": zone_id, "rrset_id": rrset_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Setzen der TTL: {str(e)}")


@app.put("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/comment")
async def set_comment(zone_id: str, rrset_id: str, request: SetCommentRequest, http_request: Request, token_id: Optional[str] = None):
    """Set comment for a DNS record"""
    try:
        client = HetznerDNSClient(token_id=token_id)
        try:
            # Get current RRSet from list to preserve all data
            rrsets = await client.list_rrsets(zone_id)
            current_rrset = None
            for rrset in rrsets:
                if rrset.id == rrset_id:
                    current_rrset = rrset
                    break
            
            if not current_rrset:
                raise HTTPException(status_code=404, detail=f"RRSet {rrset_id} nicht gefunden")
            
            # Update with new comment (preserve all other values)
            updated_rrset = await client.create_or_update_rrset(
                zone_id=zone_id,
                name=current_rrset.name,
                type=current_rrset.type,
                records=current_rrset.records,
                ttl=current_rrset.ttl or 3600,
                comment=request.comment
            )
            
            username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
            audit_log = get_audit_log()
            audit_log.log(
                action=AuditAction.COMMENT_UPDATE,
                username=username,
                request=http_request,
                success=True,
                details={"zone_id": zone_id, "rrset_id": rrset_id, "token_id": token_id}
            )
        finally:
            await client.close()
        
        return {"success": True, "comment": request.comment, "zone_id": zone_id, "rrset_id": rrset_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Setzen des Kommentars: {str(e)}")


@app.put("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/ip")
async def set_ip(zone_id: str, rrset_id: str, request: SetIPRequest, http_request: Request, token_id: Optional[str] = None):
    """Set IP address for an A or AAAA DNS record"""
    try:
        # Validate IP is public (not private)
        is_valid, error_msg = IPValidator.validate_public_ip(request.ip)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
        
        client = HetznerDNSClient(token_id=token_id)
        try:
            # Get current RRSet from list to preserve all data
            rrsets = await client.list_rrsets(zone_id)
            current_rrset = None
            for rrset in rrsets:
                if rrset.id == rrset_id:
                    current_rrset = rrset
                    break
            
            if not current_rrset:
                raise HTTPException(status_code=404, detail=f"RRSet {rrset_id} nicht gefunden")
            
            # Check if record type is A or AAAA
            if current_rrset.type not in ["A", "AAAA"]:
                raise HTTPException(status_code=400, detail=f"IP kann nur für A oder AAAA Records gesetzt werden, nicht für {current_rrset.type}")
            
            # Split-Brain-Schutz: Prüfe andere Peers (nur wenn Peer-Sync aktiviert UND Monitor IP konfiguriert)
            storage = get_local_ip_storage()
            local_settings = storage.get_local_ip(zone_id, rrset_id)
            
            if local_settings and local_settings.get("local_ip"):
                split_brain_protection = get_split_brain_protection()
                
                if split_brain_protection.is_enabled():
                    monitor_ip = local_settings.get("local_ip")
                    monitor_port = local_settings.get("port", 80)
                    
                    split_brain_check = await split_brain_protection.check_split_brain(
                        monitor_ip=monitor_ip,
                        port=monitor_port
                    )
                    
                    if split_brain_check.get("split_brain_detected", False):
                        # Log to audit log
                        audit_log = get_audit_log()
                        username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
                        audit_log.log(
                            action=AuditAction.IP_UPDATE_SPLIT_BRAIN_DETECTED,
                            username=username,
                            request=http_request,
                            success=False,
                            details={
                                "zone_id": zone_id,
                                "rrset_id": rrset_id,
                                "monitor_ip": monitor_ip,
                                "port": monitor_port,
                                "alive_peers": split_brain_check.get("alive_peers", []),
                                "reason": split_brain_check.get("reason", ""),
                                "source": "manual"
                            }
                        )
                        raise HTTPException(
                            status_code=409,
                            detail=f"Split-Brain detected: Monitor IP {monitor_ip} is alive on multiple peers. Update blocked to prevent endless loop."
                        )
            
            # Update with new IP (preserve all other values)
            updated_rrset = await client.create_or_update_rrset(
                zone_id=zone_id,
                name=current_rrset.name,
                type=current_rrset.type,
                records=[request.ip],
                ttl=current_rrset.ttl or 3600,
                comment=current_rrset.comment
            )
            
            username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
            audit_log = get_audit_log()
            audit_log.log(
                action=AuditAction.IP_UPDATE,
                username=username,
                request=http_request,
                success=True,
                details={"zone_id": zone_id, "rrset_id": rrset_id, "ip": request.ip, "token_id": token_id}
            )
        finally:
            await client.close()
        
        # Trigger auto-sync if enabled
        await trigger_auto_sync_if_enabled()
        
        return {"success": True, "ip": request.ip, "zone_id": zone_id, "rrset_id": rrset_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Setzen der IP: {str(e)}")


@app.post("/api/v1/zones/{zone_id}/rrsets")
async def create_rrset(zone_id: str, request: CreateRRSetRequest, http_request: Request, token_id: Optional[str] = None):
    """Create a new RRSet (A or AAAA record)"""
    try:
        # Validate record type
        if request.type not in ['A', 'AAAA']:
            raise HTTPException(status_code=400, detail="Only A and AAAA records can be created.")
        
        # Validate TTL
        allowed_ttl_values = [60, 300, 600, 1800, 3600, 86400]
        ttl_to_use = request.ttl or 3600
        if ttl_to_use not in allowed_ttl_values:
            raise HTTPException(status_code=400, detail="TTL must be one of the allowed values: 60, 300, 600, 1800, 3600, 86400 seconds")
        
        # Validate IP format and ensure they are public IPs
        for record in request.records:
            is_valid, error_msg = IPValidator.validate_public_ip(record)
            if not is_valid:
                raise HTTPException(status_code=400, detail=error_msg)
        
        username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
        audit_log = get_audit_log()
        
        client = HetznerDNSClient(token_id=token_id)
        try:
            # Create RRSet
            new_rrset = await client.create_or_update_rrset(
                zone_id=zone_id,
                name=request.name,
                type=request.type,
                records=request.records,
                ttl=request.ttl or 3600,
                comment=request.comment
            )
            
            audit_log.log(
                action=AuditAction.RECORD_CREATE,
                username=username,
                request=http_request,
                success=True,
                details={"zone_id": zone_id, "rrset_id": new_rrset.id, "name": request.name, "type": request.type, "token_id": token_id}
            )
            
            return {"rrset": new_rrset.dict(), "success": True}
        finally:
            await client.close()
    except ValueError as e:
        if "token not configured" in str(e).lower():
            raise HTTPException(status_code=400, detail="Neuer API-Token nicht konfiguriert.")
        raise HTTPException(status_code=500, detail=f"Fehler beim Erstellen des RRSets: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Erstellen des RRSets: {str(e)}")


@app.put("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}")
async def update_rrset(zone_id: str, rrset_id: str, request: UpdateRRSetRequest, http_request: Request, token_id: Optional[str] = None):
    """Update an RRSet"""
    try:
        # URL encode rrset_id for API call
        import urllib.parse
        encoded_rrset_id = urllib.parse.quote(rrset_id, safe='')
        
        client = HetznerDNSClient(token_id=token_id)
        try:
            # Get current RRSet to preserve values if not provided
            current_rrset = await client.get_rrset(zone_id, encoded_rrset_id)
            
            # Use provided name/type or keep current ones
            new_name = request.name if request.name is not None else current_rrset.name
            new_type = request.type if request.type is not None else current_rrset.type
            
            # If name or type changed, we need to delete old RRSet and create new one
            if new_name != current_rrset.name or new_type != current_rrset.type:
                # Validate TTL if provided
                allowed_ttl_values = [60, 300, 600, 1800, 3600, 86400]
                ttl_to_use = request.ttl or current_rrset.ttl or 3600
                if ttl_to_use not in allowed_ttl_values:
                    raise HTTPException(status_code=400, detail="TTL muss einer der erlaubten Werte sein: 60, 300, 600, 1800, 3600, 86400 Sekunden")
                
                # Delete old RRSet
                await client.delete_rrset(zone_id, encoded_rrset_id)
                
                # Create new RRSet with new name/type
                updated_rrset = await client.create_or_update_rrset(
                    zone_id=zone_id,
                    name=new_name,
                    type=new_type,
                    records=request.records,
                    ttl=ttl_to_use,
                    comment=request.comment or current_rrset.comment
                )
            else:
                # Validate TTL if provided
                allowed_ttl_values = [60, 300, 600, 1800, 3600, 86400]
                ttl_to_use = request.ttl or current_rrset.ttl or 3600
                if ttl_to_use not in allowed_ttl_values:
                    raise HTTPException(status_code=400, detail="TTL muss einer der erlaubten Werte sein: 60, 300, 600, 1800, 3600, 86400 Sekunden")
                
                # Validate IPs are public (for A and AAAA records)
                if current_rrset.type in ['A', 'AAAA']:
                    is_valid, error_msg = IPValidator.validate_ip_list(request.records)
                    if not is_valid:
                        raise HTTPException(status_code=400, detail=error_msg)
                
                # Just update records and TTL
                updated_rrset = await client.create_or_update_rrset(
                    zone_id=zone_id,
                    name=current_rrset.name,
                    type=current_rrset.type,
                    records=request.records,
                    ttl=ttl_to_use,
                    comment=request.comment or current_rrset.comment
                )
            
            username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
            audit_log = get_audit_log()
            
            audit_log.log(
                action=AuditAction.RECORD_UPDATE,
                username=username,
                request=http_request,
                success=True,
                details={"zone_id": zone_id, "rrset_id": rrset_id, "token_id": token_id}
            )
            
            return {"rrset": updated_rrset.dict(), "success": True}
        finally:
            await client.close()
    except ValueError as e:
        if "token not configured" in str(e).lower():
            raise HTTPException(status_code=400, detail="Neuer API-Token nicht konfiguriert.")
        raise HTTPException(status_code=500, detail=f"Fehler beim Aktualisieren des RRSets: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
        audit_log = get_audit_log()
        audit_log.log(
            action=AuditAction.RECORD_UPDATE,
            username=username,
            request=http_request,
            success=False,
            error=str(e),
            details={"zone_id": zone_id, "rrset_id": rrset_id}
        )
        raise HTTPException(status_code=500, detail=f"Fehler beim Aktualisieren des RRSets: {str(e)}")


@app.post("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/assign-server-ip")
async def assign_server_ip(zone_id: str, rrset_id: str, request: Request, token_id: Optional[str] = None):
    """Assign current server public IP to an RRSet"""
    try:
        # Get public IP (check manual IP first, then auto-detect)
        storage = get_local_ip_storage()
        manual_ip = storage.get_manual_public_ip()
        
        if manual_ip:
            public_ip = manual_ip
        else:
            detector = get_ip_detector()
            public_ip = await detector.get_public_ip()
        
        # Parse rrset_id: format is "name/type" (e.g., "test/A" or "@/NS")
        # rrset_id is already decoded by FastAPI :path
        parts = rrset_id.rsplit('/', 1)
        if len(parts) != 2:
            raise HTTPException(status_code=400, detail=f"Invalid RRSet ID format: {rrset_id}")
        
        name, record_type = parts
        
        # Only update A or AAAA records
        if record_type not in ["A", "AAAA"]:
            raise HTTPException(status_code=400, detail=f"IP can only be assigned to A or AAAA records, not {record_type}")
        
        # Get current RRSet from list to preserve TTL and comment
        client = HetznerDNSClient(token_id=token_id)
        try:
            rrsets = await client.list_rrsets(zone_id)
            current_rrset = None
            for rrset in rrsets:
                if rrset.id == rrset_id:
                    current_rrset = rrset
                    break
            
            if not current_rrset:
                raise HTTPException(status_code=404, detail=f"RRSet {rrset_id} nicht gefunden")
            
            # Split-Brain-Schutz: Prüfe andere Peers (nur wenn Peer-Sync aktiviert UND Monitor IP konfiguriert)
            storage = get_local_ip_storage()
            local_settings = storage.get_local_ip(zone_id, rrset_id)
            
            if local_settings and local_settings.get("local_ip"):
                split_brain_protection = get_split_brain_protection()
                
                if split_brain_protection.is_enabled():
                    monitor_ip = local_settings.get("local_ip")
                    monitor_port = local_settings.get("port", 80)
                    
                    split_brain_check = await split_brain_protection.check_split_brain(
                        monitor_ip=monitor_ip,
                        port=monitor_port
                    )
                    
                    if split_brain_check.get("split_brain_detected", False):
                        # Log to audit log
                        audit_log = get_audit_log()
                        username = request.session.get("username", "unknown") if hasattr(request, 'session') else "unknown"
                        audit_log.log(
                            action=AuditAction.IP_UPDATE_SPLIT_BRAIN_DETECTED,
                            username=username,
                            request=request,
                            success=False,
                            details={
                                "zone_id": zone_id,
                                "rrset_id": rrset_id,
                                "monitor_ip": monitor_ip,
                                "port": monitor_port,
                                "alive_peers": split_brain_check.get("alive_peers", []),
                                "reason": split_brain_check.get("reason", ""),
                                "source": "server_ip"
                            }
                        )
                        raise HTTPException(
                            status_code=409,
                            detail=f"Split-Brain detected: Monitor IP {monitor_ip} is alive on multiple peers. Update blocked to prevent endless loop."
                        )
            
            # Get TTL override from storage if set
            ttl_override = storage.get_ttl(zone_id, rrset_id)
            
            # Use TTL override if set, otherwise keep current TTL or default to 3600
            ttl_to_use = ttl_override if ttl_override is not None else (current_rrset.ttl or 3600)
            
            # Update with public IP
            updated_rrset = await client.create_or_update_rrset(
                zone_id=zone_id,
                name=current_rrset.name,
                type=current_rrset.type,
                records=[public_ip],
                ttl=ttl_to_use,
                comment=current_rrset.comment
            )
            
            username = request.session.get("username", "unknown") if hasattr(request, 'session') else "unknown"
            audit_log = get_audit_log()
            audit_log.log(
                action=AuditAction.IP_UPDATE,
                username=username,
                request=request,
                success=True,
                details={"zone_id": zone_id, "rrset_id": rrset_id, "ip": public_ip, "token_id": token_id, "source": "server_ip"}
            )
            
            # Trigger auto-sync if enabled
            await trigger_auto_sync_if_enabled()
            
            return {"rrset": updated_rrset.dict(), "assigned_ip": public_ip, "success": True}
        finally:
            await client.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Zuweisen der Server-IP: {str(e)}")


@app.post("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/local-ip")
async def save_local_ip(zone_id: str, rrset_id: str, request: SaveLocalIPRequest, token_id: Optional[str] = None):
    """Save local IP for a DNS record"""
    try:
        # Validate IP format
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        if not (re.match(ipv4_pattern, request.local_ip) or re.match(ipv6_pattern, request.local_ip)):
            raise HTTPException(status_code=400, detail="Invalid IP format")
        
        storage = get_local_ip_storage()
        storage.set_local_ip(zone_id, rrset_id, request.local_ip, port=request.port)
        
        # Trigger auto-sync if enabled
        await trigger_auto_sync_if_enabled()
        
        return {"success": True, "local_ip": request.local_ip, "port": request.port, "zone_id": zone_id, "rrset_id": rrset_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving local IP: {str(e)}")


@app.delete("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/local-ip")
async def delete_local_ip(zone_id: str, rrset_id: str, token_id: Optional[str] = None):
    """Delete local IP for a DNS record"""
    try:
        storage = get_local_ip_storage()
        storage.delete_local_ip(zone_id, rrset_id)
        
        return {"success": True, "zone_id": zone_id, "rrset_id": rrset_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen der lokalen IP: {str(e)}")


@app.delete("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}")
async def delete_rrset(zone_id: str, rrset_id: str, request: Request, token_id: Optional[str] = None):
    """Delete an RRSet (DNS record)"""
    try:
        # Get RRSet info for confirmation
        client = HetznerDNSClient(token_id=token_id)
        try:
            import urllib.parse
            encoded_rrset_id = urllib.parse.quote(rrset_id, safe='/@')
            rrset = await client.get_rrset(zone_id, encoded_rrset_id)
            rrset_name = rrset.name
            rrset_type = rrset.type
            # Format: "name/type" for confirmation
            confirmation_text = f"{rrset_name}/{rrset_type}" if rrset_name else f"@/{rrset_type}"
        finally:
            await client.close()
        
        # Get confirmation name from request body
        try:
            body = await request.json()
            confirmation_name = body.get("confirmation_name", "").strip()
        except:
            raise HTTPException(status_code=400, detail="Confirmation name required.")
        
        # Validate confirmation
        if confirmation_name != confirmation_text:
            raise HTTPException(status_code=400, detail=f"Confirmation failed. Please enter '{confirmation_text}'.")
        
        # Delete RRSet
        username = request.session.get("username", "unknown") if hasattr(request, 'session') else "unknown"
        audit_log = get_audit_log()
        
        client = HetznerDNSClient(token_id=token_id)
        try:
            import urllib.parse
            encoded_rrset_id = urllib.parse.quote(rrset_id, safe='/@')
            await client.delete_rrset(zone_id, encoded_rrset_id)
            
            audit_log.log(
                action=AuditAction.RECORD_DELETE,
                username=username,
                request=request,
                success=True,
                details={"zone_id": zone_id, "rrset_id": rrset_id, "name": rrset_name, "type": rrset_type, "token_id": token_id}
            )
            
            return {"success": True, "message": f"RRSet '{confirmation_text}' deleted."}
        finally:
            await client.close()
    except ValueError as e:
        if "token not configured" in str(e).lower():
            raise HTTPException(status_code=400, detail="Neuer API-Token nicht konfiguriert.")
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen des RRSets: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen des RRSets: {str(e)}")


@app.delete("/api/v1/zones/{zone_id}/rrsets/{rrset_id:path}/settings")
async def delete_rrset_settings(zone_id: str, rrset_id: str):
    """Delete all settings (local IP, auto-update, TTL) for a DNS record"""
    try:
        storage = get_local_ip_storage()
        
        # Delete all settings for this record
        key = f"{zone_id}:{rrset_id}"
        storage_data = storage._load_storage()
        
        if key in storage_data.get("local_ips", {}):
            del storage_data["local_ips"][key]
            storage._storage = storage_data
            storage._save_storage()
        
        return {"success": True, "zone_id": zone_id, "rrset_id": rrset_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen der Einstellungen: {str(e)}")


@app.get("/api/v1/auto-update/status")
async def get_auto_update_status():
    """Get auto-update service status"""
    try:
        service = get_auto_update_service()
        status = service.get_status()
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Abrufen des Auto-Update-Status: {str(e)}")


@app.post("/api/v1/auto-update/check")
async def trigger_auto_update_check():
    """Manually trigger an auto-update check"""
    try:
        service = get_auto_update_service()
        results = await service.check_and_update_all()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Ausführen der Auto-Update-Prüfung: {str(e)}")


@app.get("/api/v1/auto-update/interval")
async def get_auto_update_interval():
    """Get auto-update check interval"""
    try:
        storage = get_local_ip_storage()
        interval = storage.get_auto_update_interval()
        return {"interval": interval}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Abrufen des Auto-Update-Intervalls: {str(e)}")


@app.put("/api/v1/auto-update/interval")
async def set_auto_update_interval(request: RefreshIntervalRequest, http_request: Request):
    """Set auto-update check interval in seconds"""
    username = http_request.session.get("username", "unknown") if hasattr(http_request, 'session') else "unknown"
    audit_log = get_audit_log()
    
    try:
        if request.interval < 60:
            raise HTTPException(status_code=400, detail="Intervall muss mindestens 60 Sekunden sein")
        if request.interval > 3600:
            raise HTTPException(status_code=400, detail="Intervall darf maximal 3600 Sekunden (1 Stunde) sein")
        
        storage = get_local_ip_storage()
        storage.set_auto_update_interval(request.interval)
        
        # Restart service with new interval
        service = get_auto_update_service()
        if service.is_running():
            await service.stop()
            await service.start(check_interval=request.interval)
        
        audit_log.log(
            action=AuditAction.AUTO_UPDATE_ENABLE,  # Reuse for interval change
            username=username,
            request=http_request,
            success=True,
            details={"interval": request.interval}
        )
        
        return {"success": True, "interval": request.interval}
    except HTTPException:
        raise
    except Exception as e:
        audit_log.log(
            action=AuditAction.AUTO_UPDATE_ENABLE,
            username=username,
            request=http_request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Fehler beim Setzen des Auto-Update-Intervalls: {str(e)}")


# Security Configuration Endpoints
@app.get("/api/v1/security/config", response_model=SecurityConfigResponse)
async def get_security_config(request: Request):
    """Get security configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    auth_manager = get_auth_manager()
    two_factor_auth = get_two_factor_auth()
    ip_access = get_ip_access_control()
    
    return SecurityConfigResponse(
        two_factor_enabled=auth_manager.is_2fa_enabled(username),
        ip_access_control=IPAccessControlResponse(
            whitelist_enabled=ip_access.is_whitelist_enabled(),
            blacklist_enabled=ip_access.is_blacklist_enabled(),
            whitelist_ips=ip_access.get_whitelist_ips(),
            blacklist_ips=ip_access.get_blacklist_ips(),
            mode=ip_access.get_mode()
        )
    )


@app.post("/api/v1/security/password/change")
async def change_password(request: Request, password_data: ChangePasswordRequest):
    """Change password"""
    try:
        if not request.session.get("authenticated", False):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        username = request.session.get("username", "admin")
        auth_manager = get_auth_manager()
        
        # Verify current password
        if not auth_manager.verify_password(username, password_data.current_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        
        # Change password
        audit_log = get_audit_log()
        try:
            auth_manager.change_password(username, password_data.new_password)
            audit_log.log(
                action=AuditAction.PASSWORD_CHANGE,
                username=username,
                request=request,
                success=True
            )
        except ValueError as e:
            logger.error(f"ValueError changing password: {e}")
            audit_log.log(
                action=AuditAction.PASSWORD_CHANGE,
                username=username,
                request=request,
                success=False,
                error=str(e)
            )
            raise HTTPException(status_code=400, detail=str(e))
        except IOError as e:
            logger.error(f"IOError changing password: {e}")
            audit_log.log(
                action=AuditAction.PASSWORD_CHANGE,
                username=username,
                request=request,
                success=False,
                error=str(e)
            )
            raise HTTPException(status_code=500, detail=f"Failed to save password: {str(e)}")
        except Exception as e:
            logger.error(f"Error changing password: {e}", exc_info=True)
            audit_log.log(
                action=AuditAction.PASSWORD_CHANGE,
                username=username,
                request=request,
                success=False,
                error=str(e)
            )
            raise HTTPException(status_code=500, detail=f"Failed to change password: {str(e)}")
        
        return {"success": True, "message": "Password changed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in change_password: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/security/2fa/status", response_model=TwoFactorStatus)
async def get_2fa_status(request: Request):
    """Get 2FA status"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    auth_manager = get_auth_manager()
    
    return TwoFactorStatus(enabled=auth_manager.is_2fa_enabled(username))


@app.post("/api/v1/security/2fa/setup")
async def setup_2fa(request: Request, setup_data: TwoFactorSetupRequest):
    """Setup 2FA"""
    try:
        if not request.session.get("authenticated", False):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        username = request.session.get("username", "admin")
        auth_manager = get_auth_manager()
        two_factor_auth = get_two_factor_auth()
        
        # Verify password
        if not auth_manager.verify_password(username, setup_data.password):
            raise HTTPException(status_code=400, detail="Password is incorrect")
        
        # Generate secret and QR code
        try:
            secret = two_factor_auth.generate_secret()
            qr_code = two_factor_auth.get_qr_code(secret, username)
        except Exception as e:
            logger.error(f"Error generating 2FA secret/QR code: {e}")
            raise HTTPException(status_code=500, detail="Failed to generate 2FA setup data")
        
        # Setup 2FA secret (but don't enable it yet - requires verification first)
        audit_log = get_audit_log()
        try:
            two_factor_auth.setup_2fa_secret(username, secret)
            audit_log.log(
                action=AuditAction.TWO_FA_SETUP,
                username=username,
                request=request,
                success=True
            )
        except Exception as e:
            logger.error(f"Error setting up 2FA secret: {e}")
            audit_log.log(
                action=AuditAction.TWO_FA_SETUP,
                username=username,
                request=request,
                success=False,
                error=str(e)
            )
            raise HTTPException(status_code=500, detail="Failed to setup 2FA")
        
        return {
            "success": True,
            "secret": secret,
            "qr_code": qr_code,
            "message": "2FA setup initiated. Please verify with a token to complete setup."
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in setup_2fa: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/v1/security/2fa/verify")
async def verify_2fa(request: Request, verify_data: TwoFactorVerifyRequest):
    """Verify 2FA token to complete setup"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    auth_manager = get_auth_manager()
    two_factor_auth = get_two_factor_auth()
    
    # Get secret
    secret = two_factor_auth.get_secret(username)
    if not secret:
        raise HTTPException(status_code=400, detail="2FA not set up. Please set up 2FA first.")
    
    # Verify token
    audit_log = get_audit_log()
    if not two_factor_auth.verify_totp(secret, verify_data.token):
        audit_log.log(
            action=AuditAction.TWO_FA_VERIFY_FAILURE,
            username=username,
            request=request,
            success=False,
            error="Invalid 2FA token"
        )
        raise HTTPException(status_code=400, detail="Invalid 2FA token")
    
    # Now enable 2FA after successful verification
    try:
        two_factor_auth.enable_2fa(username, secret, backup_codes=None)
    except Exception as e:
        logger.error(f"Error enabling 2FA after verification: {e}")
        raise HTTPException(status_code=500, detail="Failed to enable 2FA")
    
    audit_log.log(
        action=AuditAction.TWO_FA_VERIFY_SUCCESS,
        username=username,
        request=request,
        success=True
    )
    
    # 2FA is now enabled after verification
    return {
        "success": True,
        "message": "2FA verified and enabled successfully"
    }


class Disable2FARequest(BaseModel):
    """Disable 2FA Request"""
    password: str


@app.post("/api/v1/security/2fa/disable")
async def disable_2fa(request: Request, disable_data: Disable2FARequest):
    """Disable 2FA"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    auth_manager = get_auth_manager()
    two_factor_auth = get_two_factor_auth()
    
    # Verify password
    if not auth_manager.verify_password(username, disable_data.password):
        raise HTTPException(status_code=400, detail="Password is incorrect")
    
    # Disable 2FA
    audit_log = get_audit_log()
    two_factor_auth.disable_2fa(username)
    
    audit_log.log(
        action=AuditAction.TWO_FA_DISABLE,
        username=username,
        request=request,
        success=True
    )
    
    return {"success": True, "message": "2FA disabled successfully"}


@app.get("/api/v1/security/2fa/backup-codes/status")
async def get_backup_codes_status(request: Request):
    """Get backup codes status (whether backup codes exist)"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    auth_manager = get_auth_manager()
    two_factor_auth = get_two_factor_auth()
    
    # Check if 2FA is enabled
    if not auth_manager.is_2fa_enabled(username):
        return {"enabled": False, "count": 0}
    
    # Get backup codes count
    backup_codes = two_factor_auth.get_backup_codes(username)
    return {
        "enabled": len(backup_codes) > 0,
        "count": len(backup_codes)
    }


@app.post("/api/v1/security/2fa/backup-codes/generate")
async def generate_backup_codes(request: Request):
    """Generate new backup codes for 2FA"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    auth_manager = get_auth_manager()
    two_factor_auth = get_two_factor_auth()
    
    # Check if 2FA is enabled
    if not auth_manager.is_2fa_enabled(username):
        raise HTTPException(status_code=400, detail="2FA is not enabled. Please enable 2FA first.")
    
    # Generate new backup codes
    try:
        backup_codes = two_factor_auth.generate_backup_codes()
        
        # Get current secret and update with new backup codes
        secret = two_factor_auth.get_secret(username)
        if not secret:
            raise HTTPException(status_code=400, detail="2FA secret not found")
        
        # Update 2FA with new backup codes
        two_factor_auth.enable_2fa(username, secret, backup_codes)
        
        audit_log = get_audit_log()
        audit_log.log(
            action=AuditAction.TWO_FA_BACKUP_CODES_GENERATED,
            username=username,
            request=request,
            success=True
        )
        
        return {
            "success": True,
            "backup_codes": backup_codes,
            "message": "Backup codes generated successfully. Please save them securely."
        }
    except Exception as e:
        logger.error(f"Error generating backup codes: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate backup codes")


@app.get("/api/v1/security/ip-access-control", response_model=IPAccessControlResponse)
async def get_ip_access_control_config(request: Request):
    """Get IP access control configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    ip_access = get_ip_access_control()
    
    return IPAccessControlResponse(
        whitelist_enabled=ip_access.is_whitelist_enabled(),
        blacklist_enabled=ip_access.is_blacklist_enabled(),
        whitelist_ips=ip_access.get_whitelist_ips(),
        blacklist_ips=ip_access.get_blacklist_ips(),
        mode=ip_access.get_mode()
    )


@app.post("/api/v1/security/ip-access-control/whitelist/add")
async def add_whitelist_ip(request: Request, entry: IPWhitelistEntry):
    """Add IP to whitelist"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    ip_access = get_ip_access_control()
    try:
        ip_access.add_whitelist_ip(entry.ip_or_cidr)
        audit_log.log(
            action=AuditAction.IP_WHITELIST_ADD,
            username=username,
            request=request,
            success=True,
            details={"ip": entry.ip_or_cidr}
        )
        return {"success": True, "message": f"IP {entry.ip_or_cidr} added to whitelist"}
    except ValueError as e:
        audit_log.log(
            action=AuditAction.IP_WHITELIST_ADD,
            username=username,
            request=request,
            success=False,
            error=str(e),
            details={"ip": entry.ip_or_cidr}
        )
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/security/ip-access-control/whitelist/{ip_or_cidr:path}")
async def remove_whitelist_ip(request: Request, ip_or_cidr: str):
    """Remove IP from whitelist"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    ip_access = get_ip_access_control()
    ip_access.remove_whitelist_ip(ip_or_cidr)
    
    audit_log.log(
        action=AuditAction.IP_WHITELIST_REMOVE,
        username=username,
        request=request,
        success=True,
        details={"ip": ip_or_cidr}
    )
    
    return {"success": True, "message": f"IP {ip_or_cidr} removed from whitelist"}


@app.post("/api/v1/security/ip-access-control/blacklist/add")
async def add_blacklist_ip(request: Request, entry: IPWhitelistEntry):
    """Add IP to blacklist"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    ip_access = get_ip_access_control()
    try:
        ip_access.add_blacklist_ip(entry.ip_or_cidr)
        audit_log.log(
            action=AuditAction.IP_BLACKLIST_ADD,
            username=username,
            request=request,
            success=True,
            details={"ip": entry.ip_or_cidr}
        )
        return {"success": True, "message": f"IP {entry.ip_or_cidr} added to blacklist"}
    except ValueError as e:
        audit_log.log(
            action=AuditAction.IP_BLACKLIST_ADD,
            username=username,
            request=request,
            success=False,
            error=str(e),
            details={"ip": entry.ip_or_cidr}
        )
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/security/ip-access-control/blacklist/{ip_or_cidr:path}")
async def remove_blacklist_ip(request: Request, ip_or_cidr: str):
    """Remove IP from blacklist"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    ip_access = get_ip_access_control()
    ip_access.remove_blacklist_ip(ip_or_cidr)
    
    audit_log.log(
        action=AuditAction.IP_BLACKLIST_REMOVE,
        username=username,
        request=request,
        success=True,
        details={"ip": ip_or_cidr}
    )
    
    return {"success": True, "message": f"IP {ip_or_cidr} removed from blacklist"}


@app.put("/api/v1/security/ip-access-control/whitelist/enabled")
async def set_whitelist_enabled(request: Request, enabled: bool):
    """Enable or disable whitelist"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    ip_access = get_ip_access_control()
    ip_access.set_whitelist_enabled(enabled)
    
    audit_log.log(
        action=AuditAction.IP_WHITELIST_TOGGLE,
        username=username,
        request=request,
        success=True,
        details={"enabled": enabled}
    )
    
    return {"success": True, "enabled": enabled}


@app.put("/api/v1/security/ip-access-control/blacklist/enabled")
async def set_blacklist_enabled(request: Request, enabled: bool):
    """Enable or disable blacklist"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    ip_access = get_ip_access_control()
    ip_access.set_blacklist_enabled(enabled)
    
    audit_log.log(
        action=AuditAction.IP_BLACKLIST_TOGGLE,
        username=username,
        request=request,
        success=True,
        details={"enabled": enabled}
    )
    
    return {"success": True, "enabled": enabled}


@app.get("/api/v1/security/audit-logs")
async def get_audit_logs(
    request: Request,
    limit: int = 100,
    action: Optional[str] = None,
    username: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
):
    """Get audit logs with optional filtering"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    audit_log = get_audit_log()
    
    # Parse dates if provided
    start_datetime = None
    end_datetime = None
    if start_date:
        try:
            from datetime import datetime
            start_datetime = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        except Exception:
            pass
    if end_date:
        try:
            from datetime import datetime
            end_datetime = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        except Exception:
            pass
    
    # Convert action string to AuditAction enum if provided
    action_enum = None
    if action:
        try:
            action_enum = AuditAction(action)
        except ValueError:
            pass
    
    logs = audit_log.get_logs(
        limit=limit,
        action=action_enum,
        username=username,
        start_date=start_datetime,
        end_date=end_datetime
    )
    
    return {"success": True, "logs": logs, "count": len(logs)}


@app.get("/api/v1/security/audit-log-config", response_model=AuditLogConfigResponse)
async def get_audit_log_config(request: Request):
    """Get audit log rotation configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    config_manager = get_config_manager()
    config = config_manager.load_config()
    audit_config = config.get('security', {}).get('audit_log', {})
    
    return AuditLogConfigResponse(
        max_size_mb=audit_config.get('max_size_mb', 10),
        max_age_days=audit_config.get('max_age_days', 30),
        rotation_interval_hours=audit_config.get('rotation_interval_hours', 24)
    )


@app.put("/api/v1/security/audit-log-config")
async def update_audit_log_config(request: Request, config_data: AuditLogConfigRequest):
    """Update audit log rotation configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    config_manager = get_config_manager()
    
    try:
        # Update config
        config = config_manager.load_config()
        if 'security' not in config:
            config['security'] = {}
        if 'audit_log' not in config['security']:
            config['security']['audit_log'] = {}
        
        config['security']['audit_log']['max_size_mb'] = config_data.max_size_mb
        config['security']['audit_log']['max_age_days'] = config_data.max_age_days
        config['security']['audit_log']['rotation_interval_hours'] = config_data.rotation_interval_hours
        
        config_manager._config = config
        config_manager.save_config()
        
        # Reload audit log config
        audit_log._load_config()
        
        # Restart rotation task if interval changed
        audit_log.stop_rotation_task()
        audit_log._start_rotation_task()
        
        # Log configuration change
        audit_log.log(
            action=AuditAction.TOKEN_UPDATE,  # Reuse existing action for config changes
            username=username,
            request=request,
            success=True,
            details={
                "config_type": "audit_log_rotation",
                "max_size_mb": config_data.max_size_mb,
                "max_age_days": config_data.max_age_days,
                "rotation_interval_hours": config_data.rotation_interval_hours
            }
        )
        
        return {"success": True, "message": "Audit log configuration updated"}
    except Exception as e:
        logger.error(f"Error updating audit log config: {e}")
        audit_log.log(
            action=AuditAction.TOKEN_UPDATE,
            username=username,
            request=request,
            success=False,
            error=str(e),
            details={"config_type": "audit_log_rotation"}
        )
        raise HTTPException(status_code=500, detail=f"Error updating audit log configuration: {str(e)}")


@app.get("/api/v1/security/brute-force", response_model=BruteForceConfigResponse)
async def get_brute_force_config(request: Request):
    """Get brute-force protection configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    brute_force = get_brute_force_protection()
    config = brute_force.get_config()
    
    return BruteForceConfigResponse(
        enabled=config['enabled'],
        max_login_attempts=config['max_login_attempts'],
        max_2fa_attempts=config['max_2fa_attempts'],
        lockout_duration_login=config['lockout_duration_login'],
        lockout_duration_2fa=config['lockout_duration_2fa'],
        window_duration=config['window_duration']
    )


@app.put("/api/v1/security/brute-force")
async def update_brute_force_config(request: Request, config_data: BruteForceConfigRequest):
    """Update brute-force protection configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    brute_force = get_brute_force_protection()
    
    try:
        # Convert minutes to seconds
        lockout_duration_login_sec = config_data.lockout_duration_login * 60
        lockout_duration_2fa_sec = config_data.lockout_duration_2fa * 60
        window_duration_sec = config_data.window_duration * 60
        
        brute_force.set_config(
            enabled=config_data.enabled,
            max_login_attempts=config_data.max_login_attempts,
            max_2fa_attempts=config_data.max_2fa_attempts,
            lockout_duration_login=lockout_duration_login_sec,
            lockout_duration_2fa=lockout_duration_2fa_sec,
            window_duration=window_duration_sec
        )
        
        audit_log.log(
            action=AuditAction.IP_WHITELIST_TOGGLE,  # Reuse action type for brute-force config change
            username=username,
            request=request,
            success=True,
            details={"brute_force_config": config_data.dict()}
        )
        
        return {"success": True, "message": "Brute-force protection configuration updated"}
    except Exception as e:
        audit_log.log(
            action=AuditAction.IP_WHITELIST_TOGGLE,
            username=username,
            request=request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Failed to update brute-force configuration: {str(e)}")


@app.get("/api/v1/security/smtp", response_model=SMTPConfigResponse)
async def get_smtp_config(request: Request):
    """Get SMTP email notification configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    smtp_notifier = get_smtp_notifier()
    config = smtp_notifier.get_config()
    
    return SMTPConfigResponse(**config)


@app.put("/api/v1/security/smtp")
async def update_smtp_config(request: Request, config_data: SMTPConfigRequest):
    """Update SMTP email notification configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    smtp_notifier = get_smtp_notifier()
    
    try:
        smtp_notifier.set_config(config_data.dict())
        
        audit_log.log(
            action=AuditAction.IP_WHITELIST_TOGGLE,  # Reuse action type for SMTP config change
            username=username,
            request=request,
            success=True,
            details={"smtp_config_updated": True}
        )
        
        return {"success": True, "message": "SMTP configuration updated"}
    except Exception as e:
        audit_log.log(
            action=AuditAction.IP_WHITELIST_TOGGLE,
            username=username,
            request=request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Failed to update SMTP configuration: {str(e)}")


# Peer-Sync API Endpoints

@app.get("/api/v1/peer-sync/config", response_model=PeerSyncConfigResponse)
async def get_peer_sync_config(request: Request):
    """Get peer-sync configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        config_manager = get_config_manager()
        config = config_manager.load_config()
        peer_sync_config = config.get('peer_sync', {})
        
        return PeerSyncConfigResponse(
            enabled=peer_sync_config.get('enabled', False),
            peer_nodes=peer_sync_config.get('peer_nodes', []),
            interval=peer_sync_config.get('interval', 300),
            timeout=peer_sync_config.get('timeout', 3.0),
            ntp_enabled=peer_sync_config.get('ntp_enabled', False),
            ntp_server=peer_sync_config.get('ntp_server', 'pool.ntp.org'),
            timezone=peer_sync_config.get('timezone', 'UTC'),
            peer_public_keys=peer_sync_config.get('peer_public_keys', {})
        )
    except Exception as e:
        logger.error(f"Error getting peer-sync config: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting peer-sync configuration: {str(e)}")


@app.put("/api/v1/peer-sync/config")
async def update_peer_sync_config(request: Request, config_data: PeerSyncConfigRequest):
    """Update peer-sync configuration"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    config_manager = get_config_manager()
    peer_sync = get_peer_sync()
    
    try:
        # Update config
        config = config_manager.load_config()
        if 'peer_sync' not in config:
            config['peer_sync'] = {}
        
        old_enabled = config['peer_sync'].get('enabled', False)
        config['peer_sync']['enabled'] = config_data.enabled
        # auto_sync_enabled removed - enabled=true means always auto-sync on every change
        # Keep auto_sync_enabled in config for backward compatibility, but set it to same as enabled
        config['peer_sync']['auto_sync_enabled'] = config_data.enabled
        config['peer_sync']['peer_nodes'] = config_data.peer_nodes
        config['peer_sync']['interval'] = config_data.interval
        config['peer_sync']['timeout'] = config_data.timeout
        # max_retries and rate_limit removed - not needed when syncing on every change
        # ntp_enabled, ntp_server, timezone removed - now stored in peer_sync_ntp.yaml (synchronized file)
        config['peer_sync']['peer_public_keys'] = config_data.peer_public_keys
        
        config_manager._config = config
        config_manager.save_config()
        
        # Reload peer-sync config
        peer_sync._load_config()
        peer_sync._load_peer_public_keys()
        
        # Restart service if enabled changed
        if old_enabled != config_data.enabled:
            if config_data.enabled:
                await peer_sync.start()
                audit_log.log(
                    action=AuditAction.PEER_SYNC_ENABLE,
                    username=username,
                    request=request,
                    success=True
                )
            else:
                await peer_sync.stop()
                audit_log.log(
                    action=AuditAction.PEER_SYNC_DISABLE,
                    username=username,
                    request=request,
                    success=True
                )
        else:
            # Log config update
            audit_log.log(
                action=AuditAction.PEER_SYNC_CONFIG_UPDATE,
                username=username,
                request=request,
                success=True,
                details={
                    "interval": config_data.interval,
                    "timeout": config_data.timeout,
                    # max_retries and rate_limit removed - not needed when syncing on every change
                    # ntp_enabled removed - now stored in peer_sync_ntp.yaml
                }
            )
        
        return {"success": True, "message": "Peer-Sync configuration updated"}
    except Exception as e:
        logger.error(f"Error updating peer-sync config: {e}")
        audit_log.log(
            action=AuditAction.PEER_SYNC_CONFIG_UPDATE,
            username=username,
            request=request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Error updating peer-sync configuration: {str(e)}")


@app.get("/api/v1/peer-sync/public-keys", response_model=PeerSyncPublicKeysResponse)
async def get_peer_sync_public_keys(request: Request):
    """Get our own X25519 public key for peer-sync"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        peer_sync = get_peer_sync()
        public_key_b64 = peer_sync.get_public_key_base64()
        
        return PeerSyncPublicKeysResponse(
            public_key=public_key_b64
        )
    except Exception as e:
        logger.error(f"Error getting public key: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting public key: {str(e)}")


@app.post("/api/v1/peer-sync/regenerate-key")
async def regenerate_peer_sync_key(request: Request):
    """Manually regenerate X25519 key pair"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        from src.audit_log import get_audit_log, AuditAction
        username = request.session.get("username", "unknown")
        
        peer_sync = get_peer_sync()
        success = peer_sync.regenerate_x25519_key()
        
        if success:
            # Log the action
            audit_log = get_audit_log()
            audit_log.log(
                action=AuditAction.PEER_SYNC_PEER_KEY_UPDATE,
                username=username,
                request=request,
                success=True,
                details={"action": "regenerate_private_key"}
            )
            return {"success": True, "message": "X25519 key pair regenerated successfully", "public_key": peer_sync.get_public_key_base64()}
        else:
            raise HTTPException(status_code=500, detail="Failed to regenerate X25519 key pair")
    except Exception as e:
        logger.error(f"Error regenerating X25519 key: {e}")
        raise HTTPException(status_code=500, detail=f"Error regenerating X25519 key: {str(e)}")


@app.get("/api/v1/peer-sync/status", response_model=PeerSyncStatusResponse)
async def get_peer_sync_status(request: Request):
    """Get peer-sync status and metrics"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        peer_sync = get_peer_sync()
        status = peer_sync.get_status()
        
        # Build overview
        stats = status.get("stats", {})
        total_success = stats.get("total_successful_syncs", 0)
        total_fail = stats.get("total_failed_syncs", 0)
        total = total_success + total_fail
        success_rate = (total_success / total * 100) if total > 0 else 0
        
        # Get last sync time from recent events
        last_sync = None
        last_error = None
        if status.get("recent_events"):
            for event in reversed(status["recent_events"]):
                if event.get("status") == "success" and not last_sync:
                    last_sync = event.get("timestamp")
                elif event.get("status") == "error" and not last_error:
                    last_error = event.get("timestamp")
        
        overview = {
            "last_sync": last_sync,
            "last_error": last_error,
            "overall_status": "success" if not last_error or (last_sync and last_sync > last_error) else "error",
            "total_successful_syncs": total_success,
            "total_failed_syncs": total_fail,
            "average_sync_duration_ms": 0,  # TODO: Calculate from events
            "overall_success_rate": round(success_rate, 2)
        }
        
        # Build peer statuses
        peer_statuses = []
        peer_stats = stats.get("peer_stats", {})
        for peer in status.get("peer_nodes", []):
            peer_ip = peer.split(":")[0]
            peer_name = peer_sync.peer_names.get(peer_ip, peer_ip)
            peer_stat = peer_stats.get(peer_ip, {})
            
            # Find last event for this peer
            last_event = None
            for event in reversed(status.get("recent_events", [])):
                if event.get("peer_name") == peer_name:
                    last_event = event
                    break
            
            peer_statuses.append({
                "peer_name": peer_name,
                "peer_ip": peer,
                "status": last_event.get("status", "unknown") if last_event else "unknown",
                "last_sync": last_event.get("timestamp") if last_event else None,
                "sync_duration_ms": last_event.get("duration_ms", 0) if last_event else 0,
                "success_rate": round((peer_stat.get("success_count", 0) / (peer_stat.get("success_count", 0) + peer_stat.get("fail_count", 0)) * 100) if (peer_stat.get("success_count", 0) + peer_stat.get("fail_count", 0)) > 0 else 0, 2),
                "average_response_time_ms": round(peer_stat.get("avg_response_time_ms", 0), 2),
                "total_retries": peer_stat.get("total_retries", 0),
                "rate_limit_violations": peer_stat.get("rate_limit_violations", 0),
                "generation": {},  # TODO: Get from storage
                "error": last_event.get("details") if last_event and last_event.get("status") == "error" else None
            })
        
        return PeerSyncStatusResponse(
            enabled=status.get("enabled", False),
            peer_nodes=status.get("peer_nodes", []),
            overview=overview,
            peer_statuses=peer_statuses,
            recent_events=status.get("recent_events", [])
        )
    except Exception as e:
        logger.error(f"Error getting peer-sync status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting peer-sync status: {str(e)}")


@app.post("/api/v1/peer-sync/sync-now")
async def trigger_peer_sync(request: Request, sync_request: PeerSyncSyncNowRequest = None):
    """Manually trigger peer-sync"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    peer_sync = get_peer_sync()
    
    try:
        # TODO: Implement single-peer sync if peer is specified
        result = await peer_sync.sync_with_all_peers()
        
        audit_log.log(
            action=AuditAction.PEER_SYNC_MANUAL_TRIGGER,
            username=username,
            request=request,
            success=len(result.get("synced_peers", [])) > 0,
            details={
                "synced_peers": result.get("synced_peers", []),
                "failed_peers": result.get("failed_peers", [])
            }
        )
        
        return {
            "success": True,
            "message": f"Sync completed: {len(result.get('synced_peers', []))} peers synced",
            "synced_peers": result.get("synced_peers", []),
            "failed_peers": result.get("failed_peers", [])
        }
    except Exception as e:
        logger.error(f"Error triggering peer-sync: {e}")
        audit_log.log(
            action=AuditAction.PEER_SYNC_MANUAL_TRIGGER,
            username=username,
            request=request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Error triggering peer-sync: {str(e)}")


@app.post("/api/v1/peer-sync/auto-sync")
async def trigger_auto_sync_endpoint(request: Request):
    """Trigger auto-sync with result (max 2s timeout)"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        result = await trigger_auto_sync_with_result(timeout=2.0)
        if result is None:
            return {"success": False, "message": "Auto-sync timeout or not enabled", "timeout": True}
        return {"success": True, "result": result}
    except Exception as e:
        logger.error(f"Error triggering auto-sync: {e}")
        return {"success": False, "message": str(e), "timeout": False}


@app.post("/api/v1/peer-sync/test-connection")
async def test_peer_connection(request: Request, test_request: PeerSyncTestConnectionRequest, log_to_audit: bool = True):
    """Test connection to a peer
    
    Args:
        log_to_audit: If True, log the test to audit log (default: True).
                      Set to False for automatic/background tests.
    """
    # Check if log_to_audit is explicitly set to False via query parameter
    query_log_to_audit = request.query_params.get("log_to_audit", "true").lower() == "true"
    if not query_log_to_audit:
        log_to_audit = False
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    
    try:
        import time
        # Create client first (outside timing)
        client = httpx.AsyncClient(timeout=5.0)
        
        # Measure only the actual request time
        start_time = time.time()
        try:
            response = await client.get(f"http://{test_request.peer}/health")
            latency_ms = (time.time() - start_time) * 1000
        finally:
            await client.aclose()
        
        success = response.status_code == 200
        
        # Only log to audit if explicitly requested (manual tests)
        if log_to_audit:
            audit_log.log(
                action=AuditAction.PEER_SYNC_CONNECTION_TEST,
                username=username,
                request=request,
                success=success,
                details={
                    "peer": test_request.peer,
                    "latency_ms": round(latency_ms, 2)
                }
            )
        
        return {
            "success": success,
            "message": "Connection test completed" if success else "Connection test failed",
            "latency_ms": round(latency_ms, 2)
        }
    except Exception as e:
        logger.error(f"Error testing peer connection: {e}")
        # Only log to audit if explicitly requested (manual tests)
        if log_to_audit:
            audit_log.log(
                action=AuditAction.PEER_SYNC_CONNECTION_TEST,
                username=username,
                request=request,
                success=False,
                error=str(e),
                details={"peer": test_request.peer}
            )
        raise HTTPException(status_code=500, detail=f"Error testing peer connection: {str(e)}")


@app.get("/api/v1/peer-sync/check-monitor-ip")
async def check_monitor_ip_peer(
    request: Request, 
    ip: str, 
    port: Optional[int] = None
):
    """Check monitor IP status (for split-brain protection)"""
    # Verify peer signature
    try:
        peer_x25519_pub, peer_ip = await verify_peer_signature(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Peer authentication error in check-monitor-ip: {e}")
        raise HTTPException(status_code=403, detail="Peer authentication failed")
    
    try:
        from src.internal_ip_monitor import get_internal_ip_monitor
        from src.config_manager import get_config_manager
        
        monitor = get_internal_ip_monitor()
        config_manager = get_config_manager()
        config = config_manager.load_config()
        
        # Get peer name from config
        peer_sync_config = config.get('peer_sync', {})
        peer_keys_config = peer_sync_config.get('peer_keys', {})
        
        # Find peer name by IP
        peer_name = peer_ip
        if peer_ip in peer_keys_config:
            peer_name = peer_keys_config[peer_ip].get('name', peer_ip)
        
        # Check monitor IP
        check_result = await monitor.check_internal_ip_reachable(
            ip,
            port=port or 80,
            check_method="ping",
            timeout=5
        )
        
        return {
            "alive": check_result.get("reachable", False),
            "check_method": check_result.get("check_method", "ping"),
            "response_time_ms": check_result.get("response_time", 0) * 1000 if check_result.get("response_time") else 0,
            "peer_name": peer_name
        }
    except Exception as e:
        logger.error(f"Error checking monitor IP: {e}")
        raise HTTPException(status_code=500, detail=f"Error checking monitor IP: {str(e)}")


# Peer-to-Peer Sync Endpoints (for peer communication)

@app.get("/api/v1/sync/local-ips")
async def get_sync_local_ips(request: Request):
    """Get local_ips.yaml for peer sync (encrypted) - Peer-to-Peer endpoint"""
    # Verify peer signature
    try:
        peer_x25519_pub, peer_ip = await verify_peer_signature(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Peer authentication error in get_sync_local_ips: {e}")
        raise HTTPException(status_code=403, detail="Peer authentication failed")
    
    try:
        from src.peer_sync import get_peer_sync
        import base64
        import json
        import hmac
        import hashlib
        
        storage = get_local_ip_storage()
        data = storage._load_storage()
        generation = data.get('generation', {})
        
        # Get our peer sync instance
        peer_sync = get_peer_sync()
        if not peer_sync.x25519_private_key or not peer_sync.x25519_public_key:
            raise HTTPException(status_code=500, detail="X25519 keys not available")
        
        # Encrypt config with peer's public key (ECDH)
        encrypted_result = peer_sync._encrypt_config(data, peer_x25519_pub)
        encrypted_data_b64 = encrypted_result["encrypted_data"]
        nonce_b64 = encrypted_result["nonce"]
        
        # Sign encrypted data with our public key (HMAC-SHA256)
        sig_data = f"{encrypted_data_b64}:{nonce_b64}".encode()
        signature = peer_sync._sign_data(sig_data)
        
        # Get our public key as Base64
        our_public_key_b64 = peer_sync.get_public_key_base64()
        
        response = Response(
            content=json.dumps({
                "encrypted_data": encrypted_data_b64,
                "nonce": nonce_b64,
                "generation": generation
            }),
            media_type="application/json",
            headers={
                "X-Peer-Public-Key": our_public_key_b64,
                "X-Peer-Signature": signature
            }
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting sync local-ips: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting sync local-ips: {str(e)}")


@app.post("/api/v1/sync/local-ips")
async def receive_sync_local_ips(request: Request):
    """Receive local_ips.yaml from peer (encrypted) - Peer-to-Peer endpoint"""
    # Verify peer signature first (before reading body)
    try:
        peer_x25519_pub, peer_ip = await verify_peer_signature(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Peer authentication error in receive_sync_local_ips: {e}")
        raise HTTPException(status_code=403, detail="Peer authentication failed")
    
    try:
        from src.peer_sync import get_peer_sync, is_newer
        import base64
        import json
        
        # Read request body
        body = await request.body()
        sync_data = json.loads(body.decode('utf-8'))
        
        # Get encrypted data
        encrypted_data = sync_data.get("encrypted_data", "")
        nonce = sync_data.get("nonce", "")
        remote_gen = sync_data.get('generation', {})
        response_signature = request.headers.get("X-Peer-Signature", "")
        peer_public_key_b64 = request.headers.get("X-Peer-Public-Key", "")
        
        if not encrypted_data or not nonce:
            raise HTTPException(status_code=400, detail="Missing encrypted_data or nonce")
        
        if not response_signature:
            raise HTTPException(status_code=400, detail="Missing signature")
        
        # Use provided public key or cached one
        if peer_public_key_b64:
            try:
                peer_public_key_bytes = base64.b64decode(peer_public_key_b64)
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import x25519
                peer_x25519_pub = serialization.load_pem_public_key(peer_public_key_bytes)
                if not isinstance(peer_x25519_pub, x25519.X25519PublicKey):
                    raise ValueError("Invalid X25519 public key type")
            except Exception as e:
                logger.warning(f"Failed to decode peer public key: {e}")
                # Use cached public key from verify_peer_signature
        
        # Verify signature of encrypted data with peer's public key
        sig_data = f"{encrypted_data}:{nonce}".encode()
        try:
            from src.peer_auth import verify_peer_signature_for_body
            if not await verify_peer_signature_for_body(request, body, peer_x25519_pub, response_signature):
                raise HTTPException(status_code=403, detail="Invalid signature for encrypted data")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Signature verification failed for encrypted data: {e}")
            raise HTTPException(status_code=403, detail="Invalid signature for encrypted data")
        
        # Decrypt config with derived shared secret (ECDH)
        peer_sync = get_peer_sync()
        remote_data = peer_sync._decrypt_config(encrypted_data, nonce, peer_x25519_pub)
        
        # Get local config
        storage = get_local_ip_storage()
        local_data = storage._load_storage()
        local_gen = local_data.get('generation', {})
        
        # Check if peer is newer
        if is_newer(local_gen, remote_gen, local_data, remote_data):
            # Complete config takeover
            storage._storage = remote_data
            storage._save_storage()
            logger.info(f"Config merged from peer {peer_ip}")
            return {"success": True, "merged": True}
        
        return {"success": True, "merged": False}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error receiving sync local-ips: {e}")
        raise HTTPException(status_code=500, detail=f"Error receiving sync local-ips: {str(e)}")


@app.get("/api/v1/sync/config-status")
async def get_config_status(request: Request):
    """Get config status (generation + hash) - Peer-to-Peer endpoint"""
    # Verify peer signature first
    try:
        peer_x25519_pub, peer_ip = await verify_peer_signature(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Peer authentication error in get_config_status: {e}")
        raise HTTPException(status_code=403, detail="Peer authentication failed")
    
    try:
        import hashlib
        from datetime import datetime
        
        storage = get_local_ip_storage()
        local_data = storage._load_storage()
        local_gen = local_data.get('generation', {})
        
        # Calculate hash of config content (local_ips.yaml)
        # Serialize the config to get a consistent representation
        config_str = yaml.dump(local_data, default_flow_style=False, allow_unicode=True, sort_keys=True)
        config_hash = hashlib.sha256(config_str.encode('utf-8')).hexdigest()[:8]  # First 8 chars
        
        # Get file modification time
        storage_path = storage.storage_path
        if storage_path.exists():
            file_mtime = storage_path.stat().st_mtime
            timestamp_str = datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')
        else:
            timestamp_str = None
        
        return {
            "generation": local_gen,
            "config_hash": config_hash,
            "timestamp": timestamp_str
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting config status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting config status: {str(e)}")


# Peer Sync NTP Endpoints (for peer communication)

@app.get("/api/v1/sync/peer-sync-ntp")
async def get_sync_peer_sync_ntp(request: Request):
    """Get peer_sync_ntp.yaml for peer sync (encrypted) - Peer-to-Peer endpoint"""
    # Verify peer signature
    try:
        peer_x25519_pub, peer_ip = await verify_peer_signature(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Peer authentication error in get_sync_peer_sync_ntp: {e}")
        raise HTTPException(status_code=403, detail="Peer authentication failed")
    
    try:
        from src.peer_sync import get_peer_sync
        import base64
        import json
        
        ntp_storage = get_peer_sync_ntp_storage()
        data = ntp_storage._load_storage()
        generation = data.get('generation', {})
        
        # Get our peer sync instance
        peer_sync = get_peer_sync()
        if not peer_sync.x25519_private_key or not peer_sync.x25519_public_key:
            raise HTTPException(status_code=500, detail="X25519 keys not available")
        
        # Encrypt config with peer's public key (ECDH)
        encrypted_result = peer_sync._encrypt_config(data, peer_x25519_pub)
        encrypted_data_b64 = encrypted_result["encrypted_data"]
        nonce_b64 = encrypted_result["nonce"]
        
        # Sign encrypted data with our public key (HMAC-SHA256)
        sig_data = f"{encrypted_data_b64}:{nonce_b64}".encode()
        signature = peer_sync._sign_data(sig_data)
        
        # Get our public key as Base64
        our_public_key_b64 = peer_sync.get_public_key_base64()
        
        response = Response(
            content=json.dumps({
                "encrypted_data": encrypted_data_b64,
                "nonce": nonce_b64,
                "generation": generation
            }),
            media_type="application/json",
            headers={
                "X-Peer-Public-Key": our_public_key_b64,
                "X-Peer-Signature": signature
            }
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting sync peer-sync-ntp: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting sync peer-sync-ntp: {str(e)}")


@app.post("/api/v1/sync/peer-sync-ntp")
async def receive_sync_peer_sync_ntp(request: Request):
    """Receive peer_sync_ntp.yaml from peer (encrypted) - Peer-to-Peer endpoint"""
    # Verify peer signature first (before reading body)
    try:
        peer_x25519_pub, peer_ip = await verify_peer_signature(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Peer authentication error in receive_sync_peer_sync_ntp: {e}")
        raise HTTPException(status_code=403, detail="Peer authentication failed")
    
    try:
        from src.peer_sync import get_peer_sync, is_newer
        import base64
        import json
        
        # Read request body
        body = await request.body()
        sync_data = json.loads(body.decode('utf-8'))
        
        # Get encrypted data
        encrypted_data = sync_data.get("encrypted_data", "")
        nonce = sync_data.get("nonce", "")
        remote_gen = sync_data.get('generation', {})
        response_signature = request.headers.get("X-Peer-Signature", "")
        peer_public_key_b64 = request.headers.get("X-Peer-Public-Key", "")
        
        if not encrypted_data or not nonce:
            raise HTTPException(status_code=400, detail="Missing encrypted_data or nonce")
        
        if not response_signature:
            raise HTTPException(status_code=400, detail="Missing signature")
        
        # Use provided public key or cached one
        if not peer_x25519_pub:
            raise HTTPException(status_code=400, detail="Missing peer public key")
        
        # Verify signature of POST request (same as local-ips endpoint)
        try:
            from src.peer_auth import verify_peer_signature_for_body
            if not await verify_peer_signature_for_body(request, body, peer_x25519_pub, response_signature):
                raise HTTPException(status_code=403, detail="Invalid signature for POST request")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Signature verification failed for POST request: {e}")
            raise HTTPException(status_code=403, detail="Invalid signature for POST request")
        
        # Decrypt config
        remote_data = peer_sync._decrypt_config(encrypted_data, nonce, peer_x25519_pub)
        remote_data["generation"] = remote_gen  # Ensure generation is included
        
        # Get local config
        ntp_storage = get_peer_sync_ntp_storage()
        local_data = ntp_storage._load_storage()
        local_gen = local_data.get('generation', {})
        
        # Check if peer is newer
        if is_newer(local_gen, remote_gen, local_data, remote_data):
            # Complete config takeover
            ntp_storage.set_config_from_peer(remote_data)
            logger.info(f"NTP config merged from peer {peer_ip}")
            return {"success": True, "merged": True}
        
        return {"success": True, "merged": False}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error receiving sync peer-sync-ntp: {e}")
        raise HTTPException(status_code=500, detail=f"Error receiving sync peer-sync-ntp: {str(e)}")


@app.get("/api/v1/peer-sync/ntp-config")
async def get_peer_sync_ntp_config(request: Request):
    """Get NTP configuration from peer_sync_ntp.yaml"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        ntp_storage = get_peer_sync_ntp_storage()
        ntp_config = ntp_storage.get_ntp_config()
        return ntp_config
    except Exception as e:
        logger.error(f"Error getting peer-sync NTP config: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting peer-sync NTP configuration: {str(e)}")


@app.put("/api/v1/peer-sync/ntp-config")
async def update_peer_sync_ntp_config(request: Request):
    """Update NTP configuration in peer_sync_ntp.yaml and trigger sync"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    
    try:
        body = await request.json()
        ntp_enabled = body.get("ntp_enabled", False)
        ntp_server = body.get("ntp_server", "pool.ntp.org")
        timezone = body.get("timezone", "UTC")
        
        ntp_storage = get_peer_sync_ntp_storage()
        ntp_storage.set_ntp_config(ntp_enabled, ntp_server, timezone)
        
        audit_log.log(
            action=AuditAction.PEER_SYNC_CONFIG_UPDATE,
            username=username,
            request=request,
            success=True,
            details={
                "ntp_enabled": ntp_enabled,
                "ntp_server": ntp_server,
                "timezone": timezone,
                "message": "NTP configuration updated"
            }
        )
        
        # Trigger auto-sync to push NTP config to all peers
        await trigger_auto_sync_if_enabled()
        
        return {"success": True, "message": "NTP configuration updated and synced"}
    except Exception as e:
        logger.error(f"Error updating peer-sync NTP config: {e}")
        audit_log.log(
            action=AuditAction.PEER_SYNC_CONFIG_UPDATE,
            username=username,
            request=request,
            success=False,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Error updating peer-sync NTP configuration: {str(e)}")


@app.get("/api/v1/peer-sync/current-time")
async def get_current_time(request: Request):
    """Get current server time in configured timezone"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        from datetime import datetime
        try:
            from zoneinfo import ZoneInfo
        except ImportError:
            # Fallback for Python < 3.9
            try:
                import pytz
                ZoneInfo = pytz.timezone
            except ImportError:
                # No timezone support, use UTC
                ZoneInfo = None
        
        # Get timezone from peer_sync_ntp.yaml
        ntp_storage = get_peer_sync_ntp_storage()
        ntp_config = ntp_storage.get_ntp_config()
        timezone_str = ntp_config.get('timezone', 'UTC')
        
        # Get current time in configured timezone
        try:
            if ZoneInfo:
                tz = ZoneInfo(timezone_str)
                current_time = datetime.now(tz)
            else:
                # No timezone support, use UTC
                current_time = datetime.utcnow()
                timezone_str = 'UTC'
            
            time_str = current_time.strftime('%Y-%m-%d %H:%M:%S')
            timezone_name = current_time.strftime('%Z') if hasattr(current_time, 'tzinfo') and current_time.tzinfo else timezone_str
        except Exception as e:
            logger.warning(f"Error parsing timezone {timezone_str}: {e}")
            # Fallback to UTC
            current_time = datetime.utcnow()
            time_str = current_time.strftime('%Y-%m-%d %H:%M:%S')
            timezone_name = 'UTC'
            timezone_str = 'UTC'
        
        return {
            "current_time": time_str,
            "timezone": timezone_str,
            "timezone_name": timezone_name,
            "timestamp": current_time.timestamp()
        }
    except Exception as e:
        logger.error(f"Error getting current time: {e}")
        # Fallback to UTC
        from datetime import datetime
        current_time = datetime.utcnow()
        return {
            "current_time": current_time.strftime('%Y-%m-%d %H:%M:%S'),
            "timezone": "UTC",
            "timezone_name": "UTC",
            "timestamp": current_time.timestamp()
        }


@app.get("/api/v1/peer-sync/own-config-status")
async def get_own_config_status(request: Request):
    """Get own config status (Last Modified timestamp) - for authenticated users only"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        from datetime import datetime
        
        storage = get_local_ip_storage()
        storage_path = storage.storage_path
        
        # Get file modification time
        if storage_path.exists():
            file_mtime = storage_path.stat().st_mtime
            timestamp_str = datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')
        else:
            timestamp_str = None
        
        return {
            "timestamp": timestamp_str
        }
    except Exception as e:
        logger.error(f"Error getting own config status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting own config status: {str(e)}")


@app.get("/api/v1/peer-sync/get-peer-config-status")
async def get_peer_config_status(request: Request, peer: str):
    """Get config status from a specific peer (for UI)"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        from src.peer_sync import get_peer_sync
        
        peer_sync = get_peer_sync()
        peer_ip = peer.split(':')[0]
        
        # Check if we have peer's public key
        if peer_ip not in peer_sync.peer_x25519_keys:
            raise HTTPException(status_code=400, detail=f"Peer {peer_ip} not configured")
        
        # Use peer_sync to query config status (it handles signing)
        client = await peer_sync._get_client()
        our_public_key_b64 = peer_sync.get_public_key_base64()
        
        # Sign request
        url_path = "/api/v1/sync/config-status"
        request_data = f"GET:{url_path}".encode()
        signature = peer_sync._sign_data(request_data)
        
        headers = {
            "X-Peer-Public-Key": our_public_key_b64,
            "X-Peer-Signature": signature
        }
        
        url = f"http://{peer}{url_path}"
        response = await client.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPException(status_code=response.status_code, detail=f"Failed to get config status from peer: {response.status_code}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting peer config status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting peer config status: {str(e)}")


@app.post("/api/v1/peer-sync/pull-config")
async def pull_config_from_peer(request: Request, peer: str):
    """Pull config from a specific peer and overwrite local config"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = request.session.get("username", "admin")
    audit_log = get_audit_log()
    
    try:
        from src.peer_sync import get_peer_sync
        from src.local_ip_storage import get_local_ip_storage
        
        peer_sync = get_peer_sync()
        storage = get_local_ip_storage()
        
        # Pull config from peer
        config_data = await peer_sync.pull_config_from_peer(peer)
        
        if config_data is None:
            audit_log.log(
                action=AuditAction.PEER_SYNC_PULL_CONFIG,
                username=username,
                request=request,
                success=False,
                error="Failed to pull config from peer",
                details={"peer": peer}
            )
            raise HTTPException(status_code=500, detail="Failed to pull config from peer")
        
        # Overwrite local config
        storage.set_config_from_peer(config_data)
        
        # Log success
        audit_log.log(
            action=AuditAction.PEER_SYNC_PULL_CONFIG,
            username=username,
            request=request,
            success=True,
            details={
                "peer": peer,
                "peer_name": peer_sync.peer_names.get(peer.split(":")[0], peer)
            }
        )
        
        return {
            "success": True,
            "message": f"Config successfully pulled from {peer_sync.peer_names.get(peer.split(':')[0], peer)}",
            "peer": peer
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error pulling config from peer: {e}")
        audit_log.log(
            action=AuditAction.PEER_SYNC_PULL_CONFIG,
            username=username,
            request=request,
            success=False,
            error=str(e),
            details={"peer": peer}
        )
        raise HTTPException(status_code=500, detail=f"Error pulling config from peer: {str(e)}")


@app.get("/api/v1/peer-sync/find-newest-config")
async def find_newest_config(request: Request):
    """Find peer with newest config (only reachable peers)"""
    if not request.session.get("authenticated", False):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        from src.peer_sync import get_peer_sync
        
        peer_sync = get_peer_sync()
        result = await peer_sync.find_newest_config_peer()
        
        if result is None:
            return {
                "found": False,
                "message": "No reachable peers found or no peers configured"
            }
        
        return {
            "found": True,
            "peer": result["peer"],
            "peer_ip": result["peer_ip"],
            "peer_name": result["peer_name"],
            "timestamp": result["timestamp_str"]
        }
    except Exception as e:
        logger.error(f"Error finding newest config: {e}")
        raise HTTPException(status_code=500, detail=f"Error finding newest config: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    config = get_config_manager()
    cfg = config.load_config()
    server_config = cfg.get('server', {})
    host = server_config.get('host', '0.0.0.0')  # Default: listen on all interfaces (access control via IP whitelist/blacklist)
    port = server_config.get('port', 8000)
    uvicorn.run(app, host=host, port=port)

