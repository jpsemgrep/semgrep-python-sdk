"""
Custom exceptions for the Semgrep SDK.
"""

from typing import Optional, Any, Dict


class SemgrepError(Exception):
    """Base exception for all Semgrep SDK errors."""
    
    def __init__(
        self, 
        message: str, 
        code: Optional[str] = None, 
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(SemgrepError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, code="AUTH_ERROR")


class ValidationError(SemgrepError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None):
        details = {"field": field} if field else {}
        super().__init__(message, code="VALIDATION_ERROR", details=details)


class RateLimitError(SemgrepError):
    """Raised when API rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        details = {"retry_after": retry_after} if retry_after else {}
        super().__init__(message, code="RATE_LIMIT_ERROR", details=details)


class NotFoundError(SemgrepError):
    """Raised when a resource is not found."""
    
    def __init__(self, message: str = "Resource not found", resource_type: Optional[str] = None):
        details = {"resource_type": resource_type} if resource_type else {}
        super().__init__(message, code="NOT_FOUND_ERROR", details=details)


class ServerError(SemgrepError):
    """Raised when the Semgrep server returns an error."""
    
    def __init__(self, message: str = "Server error", status_code: Optional[int] = None):
        details = {"status_code": status_code} if status_code else {}
        super().__init__(message, code="SERVER_ERROR", details=details)


class ScanError(SemgrepError):
    """Raised when a scan operation fails."""
    
    def __init__(self, message: str, scan_id: Optional[str] = None):
        details = {"scan_id": scan_id} if scan_id else {}
        super().__init__(message, code="SCAN_ERROR", details=details)


class ConfigurationError(SemgrepError):
    """Raised when there's a configuration issue."""
    
    def __init__(self, message: str, config_key: Optional[str] = None):
        details = {"config_key": config_key} if config_key else {}
        super().__init__(message, code="CONFIGURATION_ERROR", details=details) 