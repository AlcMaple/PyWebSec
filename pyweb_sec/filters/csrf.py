"""
CSRF (Cross-Site Request Forgery) protection filter for PyWebSec.
"""

import hmac
import hashlib
import time
import os
import base64
from typing import Dict, Optional, Tuple, Any

class CSRFFilter:
    """
    Filter for protecting against Cross-Site Request Forgery (CSRF) attacks.
    """
    
    def __init__(self, logger=None, secret_key=None, token_expiry=3600):
        """
        Initialize the CSRF filter.
        
        Args:
            logger: Optional logger instance.
            secret_key: Secret key for token generation. If None, a random key is generated.
            token_expiry: Token expiry time in seconds. Default is 1 hour.
        """
        self.logger = logger
        self.secret_key = secret_key or os.urandom(32)
        self.token_expiry = token_expiry
    
    def generate_token(self, session_id: str) -> str:
        """
        Generate a CSRF token for a session.
        
        Args:
            session_id: Session identifier.
            
        Returns:
            A base64-encoded CSRF token.
        """
        # Current timestamp (used for expiry check)
        timestamp = str(int(time.time()))
        
        # Create a unique token using HMAC
        h = hmac.new(
            key=self.secret_key,
            msg=(session_id + timestamp).encode('utf-8'),
            digestmod=hashlib.sha256
        )
        digest = h.digest()
        
        # Combine timestamp and digest, and encode as base64
        token = base64.urlsafe_b64encode(timestamp.encode('utf-8') + b':' + digest)
        return token.decode('utf-8')
    
    def validate_token(self, session_id: str, token: str) -> bool:
        """
        Validate a CSRF token.
        
        Args:
            session_id: Session identifier.
            token: CSRF token to validate.
            
        Returns:
            True if token is valid, False otherwise.
        """
        if not token:
            return False
        
        try:
            # Decode the token
            decoded = base64.urlsafe_b64decode(token.encode('utf-8'))
            parts = decoded.split(b':', 1)
            
            if len(parts) != 2:
                return False
            
            timestamp_bytes, digest = parts
            timestamp = timestamp_bytes.decode('utf-8')
            
            # Check if token has expired
            if int(time.time()) - int(timestamp) > self.token_expiry:
                if self.logger:
                    self.logger.log_info("CSRF token expired", {"session_id": session_id})
                return False
            
            # Regenerate the digest for comparison
            h = hmac.new(
                key=self.secret_key,
                msg=(session_id + timestamp).encode('utf-8'),
                digestmod=hashlib.sha256
            )
            expected_digest = h.digest()
            
            # Constant time comparison to prevent timing attacks
            return hmac.compare_digest(digest, expected_digest)
            
        except Exception as e:
            if self.logger:
                self.logger.log_error(f"CSRF token validation error: {str(e)}", 
                                     {"session_id": session_id})
            return False
    
    def check_request(self, request_method: str, request_params: Dict[str, Any], 
                     session_id: str, token_field: str = '_csrf_token') -> Tuple[bool, Optional[str]]:
        """
        Check a request for CSRF protection.
        
        Args:
            request_method: HTTP method (GET, POST, etc.).
            request_params: Request parameters.
            session_id: Session identifier.
            token_field: Parameter name for the CSRF token.
            
        Returns:
            A tuple of (is_csrf_valid, reason).
        """
        # CSRF check only applies to state-changing requests (POST, PUT, DELETE, etc.)
        if request_method.upper() in ('GET', 'HEAD', 'OPTIONS'):
            return True, None
        
        # Check if token exists in request
        token = request_params.get(token_field)
        if not token:
            if self.logger:
                self.logger.log_attack(
                    "CSRF",
                    "Missing CSRF token",
                    {"session_id": session_id, "method": request_method}
                )
            return False, "Missing CSRF token"
        
        # Validate token
        if not self.validate_token(session_id, token):
            if self.logger:
                self.logger.log_attack(
                    "CSRF",
                    "Invalid CSRF token",
                    {"session_id": session_id, "method": request_method}
                )
            return False, "Invalid CSRF token"
        
        return True, None