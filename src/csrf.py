"""CSRF Protection using Double-Submit Cookie Pattern for FastAPI"""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from fastapi.responses import Response, JSONResponse
import secrets
import logging

logger = logging.getLogger(__name__)

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"

class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware using Double-Submit Cookie Pattern.
    
    This middleware:
    1. Generates a CSRF token and stores it in an HttpOnly cookie
    2. Validates that the token in the cookie matches the token in the header
    3. Only protects unsafe HTTP methods (POST, PUT, PATCH, DELETE)
    
    The token is also made available via meta tag in HTML pages for JavaScript access.
    """
    
    def __init__(self, app, secure_cookies: bool = False, skip_paths: list = None):
        """
        Initialize CSRF Middleware.
        
        Args:
            app: The ASGI application
            secure_cookies: Set to True if using HTTPS (cookies will be Secure)
            skip_paths: List of path prefixes to skip CSRF validation
        """
        super().__init__(app)
        self.secure_cookies = secure_cookies
        self.skip_paths = skip_paths or []
    
    def _should_skip_csrf(self, request: Request) -> bool:
        """Check if CSRF validation should be skipped for this request"""
        # Skip GET, HEAD, OPTIONS
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        
        # Skip specific paths
        for skip_path in self.skip_paths:
            if request.url.path.startswith(skip_path):
                return True
        
        return False
    
    async def dispatch(self, request: Request, call_next):
        """Process request and validate CSRF token"""
        # Get or generate CSRF token from cookie
        csrf_token = request.cookies.get(CSRF_COOKIE_NAME)
        
        if not csrf_token:
            # Generate new token if not present
            csrf_token = secrets.token_urlsafe(32)
        
        # Store token in request state for HTML injection (available before response)
        request.state.csrf_token = csrf_token
        
        # Validate CSRF token for unsafe methods
        if not self._should_skip_csrf(request):
            header_token = request.headers.get(CSRF_HEADER_NAME)
            
            if not header_token:
                logger.warning(f"CSRF validation failed: Missing token header for {request.url.path}")
                return JSONResponse(
                    content={"error": "CSRF token validation failed", "message": "Missing CSRF token"},
                    status_code=403
                )
            
            # Constant-time comparison to prevent timing attacks
            import hmac
            if not hmac.compare_digest(csrf_token.encode('utf-8'), header_token.encode('utf-8')):
                logger.warning(f"CSRF validation failed: Token mismatch for {request.url.path}")
                return JSONResponse(
                    content={"error": "CSRF token validation failed", "message": "Invalid CSRF token"},
                    status_code=403
                )
        
        # Process request
        response = await call_next(request)
        
        # Set CSRF token cookie if not already set or if token was regenerated
        # Use HttpOnly=False so JavaScript can read it, but we'll also use meta tag
        # Secure=True only if HTTPS is used
        response.set_cookie(
            CSRF_COOKIE_NAME,
            csrf_token,
            httponly=False,  # Allow JS to read for header injection
            samesite="lax",  # Match session cookie setting
            secure=self.secure_cookies,  # Set to True in production with HTTPS
            max_age=3600 * 24  # 24 hours
        )
        
        return response

