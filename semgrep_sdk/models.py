"""
Pydantic models for Semgrep API data structures.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union
try:
    from pydantic import BaseModel, Field, validator, HttpUrl
except ImportError:
    raise ImportError("pydantic library is required. Install with: pip install pydantic")


class ScanStatus(str, Enum):
    """Enumeration of possible scan statuses."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    """Enumeration of finding severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Location(BaseModel):
    """Location information for a finding."""
    path: str = Field(..., description="File path where the finding was found")
    start_line: int = Field(..., description="Starting line number")
    end_line: int = Field(..., description="Ending line number")
    start_column: Optional[int] = Field(None, description="Starting column number")
    end_column: Optional[int] = Field(None, description="Ending column number")
    snippet: Optional[str] = Field(None, description="Code snippet around the finding")


class Finding(BaseModel):
    """Represents a security finding from a Semgrep scan."""
    id: str = Field(..., description="Unique identifier for the finding")
    rule_id: str = Field(..., description="ID of the rule that triggered this finding")
    message: str = Field(..., description="Human-readable message describing the finding")
    severity: FindingSeverity = Field(..., description="Severity level of the finding")
    location: Location = Field(..., description="Location information for the finding")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    created_at: Optional[datetime] = Field(None, description="When the finding was created")
    fixed: Optional[bool] = Field(None, description="Whether the finding has been fixed")


class ScanConfig(BaseModel):
    """Configuration for a Semgrep scan."""
    ruleset: str = Field(..., description="Ruleset to use for scanning")
    branch: Optional[str] = Field(None, description="Branch to scan")
    exclude_patterns: Optional[List[str]] = Field(None, description="Patterns to exclude")
    include_patterns: Optional[List[str]] = Field(None, description="Patterns to include")
    timeout: Optional[int] = Field(300, description="Scan timeout in seconds")
    max_target_bytes: Optional[int] = Field(None, description="Maximum target bytes to scan")
    respect_gitignore: Optional[bool] = Field(True, description="Whether to respect .gitignore")
    baseline_ref: Optional[str] = Field(None, description="Baseline reference for comparison")
    
    @validator('timeout')
    def validate_timeout(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Timeout must be positive')
        return v


class Scan(BaseModel):
    """Represents a Semgrep scan."""
    id: str = Field(..., description="Unique identifier for the scan")
    repository_id: str = Field(..., description="ID of the repository being scanned")
    status: ScanStatus = Field(..., description="Current status of the scan")
    config: ScanConfig = Field(..., description="Configuration used for the scan")
    findings: Optional[List[Finding]] = Field(None, description="Findings from the scan")
    created_at: datetime = Field(..., description="When the scan was created")
    started_at: Optional[datetime] = Field(None, description="When the scan started")
    completed_at: Optional[datetime] = Field(None, description="When the scan completed")
    error_message: Optional[str] = Field(None, description="Error message if scan failed")
    progress: Optional[float] = Field(None, description="Scan progress (0-100)")
    
    @validator('progress')
    def validate_progress(cls, v):
        if v is not None and (v < 0 or v > 100):
            raise ValueError('Progress must be between 0 and 100')
        return v


class Repository(BaseModel):
    """Represents a repository in Semgrep."""
    id: str = Field(..., description="Unique identifier for the repository")
    name: str = Field(..., description="Name of the repository")
    url: HttpUrl = Field(..., description="URL of the repository")
    organization_id: Optional[str] = Field(None, description="ID of the organization")
    created_at: datetime = Field(..., description="When the repository was created")
    updated_at: Optional[datetime] = Field(None, description="When the repository was last updated")
    last_scan_at: Optional[datetime] = Field(None, description="When the repository was last scanned")
    scan_count: Optional[int] = Field(0, description="Number of scans performed")
    finding_count: Optional[int] = Field(0, description="Number of findings found")
    is_active: Optional[bool] = Field(True, description="Whether the repository is active")


class Ruleset(BaseModel):
    """Represents a Semgrep ruleset."""
    id: str = Field(..., description="Unique identifier for the ruleset")
    name: str = Field(..., description="Name of the ruleset")
    description: Optional[str] = Field(None, description="Description of the ruleset")
    rules: List[Dict[str, Any]] = Field(..., description="Rules in the ruleset")
    created_at: datetime = Field(..., description="When the ruleset was created")
    updated_at: Optional[datetime] = Field(None, description="When the ruleset was last updated")
    is_public: Optional[bool] = Field(False, description="Whether the ruleset is public")
    organization_id: Optional[str] = Field(None, description="ID of the organization")


class Organization(BaseModel):
    """Represents a Semgrep organization."""
    id: str = Field(..., description="Unique identifier for the organization")
    name: str = Field(..., description="Name of the organization")
    slug: str = Field(..., description="URL slug for the organization")
    created_at: datetime = Field(..., description="When the organization was created")
    updated_at: Optional[datetime] = Field(None, description="When the organization was last updated")
    repository_count: Optional[int] = Field(0, description="Number of repositories")
    member_count: Optional[int] = Field(0, description="Number of members")
    plan: Optional[str] = Field(None, description="Subscription plan")


class User(BaseModel):
    """Represents a Semgrep user."""
    id: str = Field(..., description="Unique identifier for the user")
    username: str = Field(..., description="Username of the user")
    email: str = Field(..., description="Email address of the user")
    name: Optional[str] = Field(None, description="Full name of the user")
    created_at: datetime = Field(..., description="When the user was created")
    updated_at: Optional[datetime] = Field(None, description="When the user was last updated")
    is_active: Optional[bool] = Field(True, description="Whether the user is active")
    organization_ids: Optional[List[str]] = Field(None, description="IDs of organizations the user belongs to")


class ScanRequest(BaseModel):
    """Request model for creating a new scan."""
    repository_url: HttpUrl = Field(..., description="URL of the repository to scan")
    config: ScanConfig = Field(..., description="Configuration for the scan")
    organization_id: Optional[str] = Field(None, description="ID of the organization")


class ScanResponse(BaseModel):
    """Response model for scan operations."""
    scan: Scan = Field(..., description="The created scan")
    message: Optional[str] = Field(None, description="Additional message")


class PaginatedResponse(BaseModel):
    """Generic paginated response model."""
    data: List[Any] = Field(..., description="List of items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_prev: bool = Field(..., description="Whether there are previous pages")


class RepositoryListResponse(PaginatedResponse):
    """Paginated response for repository lists."""
    data: List[Repository] = Field(..., description="List of repositories")


class ScanListResponse(PaginatedResponse):
    """Paginated response for scan lists."""
    data: List[Scan] = Field(..., description="List of scans")


class FindingListResponse(PaginatedResponse):
    """Paginated response for finding lists."""
    data: List[Finding] = Field(..., description="List of findings")


class RulesetListResponse(PaginatedResponse):
    """Paginated response for ruleset lists."""
    data: List[Ruleset] = Field(..., description="List of rulesets")


class OrganizationListResponse(PaginatedResponse):
    """Paginated response for organization lists."""
    data: List[Organization] = Field(..., description="List of organizations") 