"""
Semgrep Python SDK

A comprehensive Python SDK for the Semgrep API that makes it easy to interact
with Semgrep's security scanning capabilities programmatically.
"""

__version__ = "0.1.0"
__author__ = "Semgrep SDK Contributors"
__email__ = "support@semgrep.com"

from .client import SemgrepClient, AsyncSemgrepClient
from .models import (
    Repository,
    Scan,
    Finding,
    ScanConfig,
    Ruleset,
    Organization,
    User,
    ScanStatus,
    FindingSeverity,
)
from .exceptions import (
    SemgrepError,
    AuthenticationError,
    ValidationError,
    RateLimitError,
    NotFoundError,
    ServerError,
)

__all__ = [
    # Clients
    "SemgrepClient",
    "AsyncSemgrepClient",
    
    # Models
    "Repository",
    "Scan",
    "Finding",
    "ScanConfig",
    "Ruleset",
    "Organization",
    "User",
    "ScanStatus",
    "FindingSeverity",
    
    # Exceptions
    "SemgrepError",
    "AuthenticationError",
    "ValidationError",
    "RateLimitError",
    "NotFoundError",
    "ServerError",
] 