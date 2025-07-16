"""
Tests for the Semgrep SDK client.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from semgrep_sdk import SemgrepClient, AsyncSemgrepClient
from semgrep_sdk.models import (
    Repository, Scan, Finding, ScanConfig, Ruleset, Organization, User,
    ScanStatus, FindingSeverity, Location
)
from semgrep_sdk.exceptions import (
    SemgrepError, AuthenticationError, ValidationError, RateLimitError,
    NotFoundError, ServerError, ScanError
)


class TestSemgrepClient:
    """Test cases for the synchronous Semgrep client."""
    
    def test_client_initialization(self):
        """Test client initialization with API token."""
        client = SemgrepClient(api_token="test-token")
        assert client.api_token == "test-token"
        assert client.base_url == "https://semgrep.dev/api/v1"
        assert client.timeout == 30
        assert client.max_retries == 3
    
    def test_client_initialization_without_token(self):
        """Test client initialization without API token raises error."""
        with pytest.raises(AuthenticationError):
            SemgrepClient()
    
    def test_client_initialization_with_custom_config(self):
        """Test client initialization with custom configuration."""
        client = SemgrepClient(
            api_token="test-token",
            base_url="https://custom.semgrep.dev/api/v1",
            timeout=60,
            max_retries=5
        )
        assert client.base_url == "https://custom.semgrep.dev/api/v1"
        assert client.timeout == 60
        assert client.max_retries == 5
    
    @patch('semgrep_sdk.client.requests.Session')
    def test_list_repositories(self, mock_session):
        """Test listing repositories."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "id": "repo1",
                    "name": "Test Repo",
                    "url": "https://github.com/test/repo",
                    "created_at": "2023-01-01T00:00:00Z",
                    "scan_count": 5,
                    "finding_count": 10
                }
            ],
            "total": 1,
            "page": 1,
            "per_page": 100,
            "has_next": False,
            "has_prev": False
        }
        mock_session.return_value.request.return_value = mock_response
        
        client = SemgrepClient(api_token="test-token")
        response = client.list_repositories()
        
        assert len(response.data) == 1
        assert response.data[0].id == "repo1"
        assert response.data[0].name == "Test Repo"
        assert response.total == 1
    
    @patch('semgrep_sdk.client.requests.Session')
    def test_get_repository(self, mock_session):
        """Test getting a specific repository."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "repo1",
            "name": "Test Repo",
            "url": "https://github.com/test/repo",
            "created_at": "2023-01-01T00:00:00Z",
            "scan_count": 5,
            "finding_count": 10
        }
        mock_session.return_value.request.return_value = mock_response
        
        client = SemgrepClient(api_token="test-token")
        repo = client.get_repository("repo1")
        
        assert repo.id == "repo1"
        assert repo.name == "Test Repo"
        assert repo.scan_count == 5
    
    @patch('semgrep_sdk.client.requests.Session')
    def test_scan_repository(self, mock_session):
        """Test starting a repository scan."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "scan1",
            "repository_id": "repo1",
            "status": "pending",
            "config": {
                "ruleset": "p/security-audit",
                "branch": "main"
            },
            "created_at": "2023-01-01T00:00:00Z",
            "findings": []
        }
        mock_session.return_value.request.return_value = mock_response
        
        client = SemgrepClient(api_token="test-token")
        scan = client.scan_repository(
            repo_url="https://github.com/test/repo",
            ruleset="p/security-audit"
        )
        
        assert scan.id == "scan1"
        assert scan.status == ScanStatus.PENDING
        assert scan.repository_id == "repo1"
    
    @patch('semgrep_sdk.client.requests.Session')
    def test_get_scan(self, mock_session):
        """Test getting a specific scan."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "scan1",
            "repository_id": "repo1",
            "status": "completed",
            "config": {
                "ruleset": "p/security-audit",
                "branch": "main"
            },
            "created_at": "2023-01-01T00:00:00Z",
            "completed_at": "2023-01-01T01:00:00Z",
            "findings": [
                {
                    "id": "finding1",
                    "rule_id": "rule1",
                    "message": "Test finding",
                    "severity": "error",
                    "location": {
                        "path": "test.py",
                        "start_line": 10,
                        "end_line": 10,
                        "start_column": 5,
                        "end_column": 15
                    }
                }
            ]
        }
        mock_session.return_value.request.return_value = mock_response
        
        client = SemgrepClient(api_token="test-token")
        scan = client.get_scan("scan1")
        
        assert scan.id == "scan1"
        assert scan.status == ScanStatus.COMPLETED
        assert scan.findings is not None
        assert len(scan.findings) == 1
        assert scan.findings[0].rule_id == "rule1"
    
    @patch('semgrep_sdk.client.requests.Session')
    def test_authentication_error(self, mock_session):
        """Test handling of authentication errors."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_session.return_value.request.return_value = mock_response
        
        client = SemgrepClient(api_token="invalid-token")
        
        with pytest.raises(AuthenticationError):
            client.get_current_user()
    
    @patch('semgrep_sdk.client.requests.Session')
    def test_not_found_error(self, mock_session):
        """Test handling of not found errors."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.return_value.request.return_value = mock_response
        
        client = SemgrepClient(api_token="test-token")
        
        with pytest.raises(NotFoundError):
            client.get_repository("nonexistent")
    
    @patch('semgrep_sdk.client.requests.Session')
    def test_rate_limit_error(self, mock_session):
        """Test handling of rate limit errors."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "60"}
        mock_session.return_value.request.return_value = mock_response
        
        client = SemgrepClient(api_token="test-token")
        
        with pytest.raises(RateLimitError) as exc_info:
            client.get_current_user()
        
        assert exc_info.value.details["retry_after"] == 60


class TestAsyncSemgrepClient:
    """Test cases for the asynchronous Semgrep client."""
    
    @pytest.mark.asyncio
    async def test_async_client_initialization(self):
        """Test async client initialization."""
        client = AsyncSemgrepClient(api_token="test-token")
        assert client.api_token == "test-token"
        assert client.base_url == "https://semgrep.dev/api/v1"
    
    @pytest.mark.asyncio
    async def test_async_client_context_manager(self):
        """Test async client context manager."""
        async with AsyncSemgrepClient(api_token="test-token") as client:
            assert client.session is not None
            assert client.api_token == "test-token"
    
    @pytest.mark.asyncio
    @patch('semgrep_sdk.client.aiohttp.ClientSession')
    async def test_async_list_repositories(self, mock_session):
        """Test async listing of repositories."""
        # Mock response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.json = Mock(return_value={
            "data": [
                {
                    "id": "repo1",
                    "name": "Test Repo",
                    "url": "https://github.com/test/repo",
                    "created_at": "2023-01-01T00:00:00Z",
                    "scan_count": 5,
                    "finding_count": 10
                }
            ],
            "total": 1,
            "page": 1,
            "per_page": 100,
            "has_next": False,
            "has_prev": False
        })
        
        mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__.return_value = mock_response
        
        async with AsyncSemgrepClient(api_token="test-token") as client:
            response = await client.list_repositories()
            
            assert len(response.data) == 1
            assert response.data[0].id == "repo1"
            assert response.total == 1


class TestModels:
    """Test cases for the data models."""
    
    def test_scan_config_validation(self):
        """Test ScanConfig validation."""
        # Valid config
        config = ScanConfig(ruleset="p/security-audit")
        assert config.ruleset == "p/security-audit"
        assert config.timeout == 300  # Default value
        
        # Test timeout validation
        with pytest.raises(ValueError):
            ScanConfig(ruleset="p/security-audit", timeout=0)
        
        with pytest.raises(ValueError):
            ScanConfig(ruleset="p/security-audit", timeout=-1)
    
    def test_scan_validation(self):
        """Test Scan validation."""
        scan_data = {
            "id": "scan1",
            "repository_id": "repo1",
            "status": "completed",
            "config": {
                "ruleset": "p/security-audit",
                "branch": "main"
            },
            "created_at": "2023-01-01T00:00:00Z",
            "progress": 100
        }
        
        scan = Scan(**scan_data)
        assert scan.id == "scan1"
        assert scan.status == ScanStatus.COMPLETED
        assert scan.progress == 100
        
        # Test progress validation
        scan_data["progress"] = 150
        with pytest.raises(ValueError):
            Scan(**scan_data)
        
        scan_data["progress"] = -10
        with pytest.raises(ValueError):
            Scan(**scan_data)
    
    def test_finding_creation(self):
        """Test Finding model creation."""
        finding_data = {
            "id": "finding1",
            "rule_id": "rule1",
            "message": "Test finding",
            "severity": "error",
            "location": {
                "path": "test.py",
                "start_line": 10,
                "end_line": 10,
                "start_column": 5,
                "end_column": 15,
                "snippet": "print('test')"
            }
        }
        
        finding = Finding(**finding_data)
        assert finding.id == "finding1"
        assert finding.rule_id == "rule1"
        assert finding.severity == FindingSeverity.ERROR
        assert finding.location.path == "test.py"
        assert finding.location.start_line == 10


class TestExceptions:
    """Test cases for custom exceptions."""
    
    def test_semgrep_error(self):
        """Test SemgrepError creation."""
        error = SemgrepError("Test error", code="TEST_ERROR", details={"key": "value"})
        assert error.message == "Test error"
        assert error.code == "TEST_ERROR"
        assert error.details == {"key": "value"}
    
    def test_authentication_error(self):
        """Test AuthenticationError creation."""
        error = AuthenticationError("Invalid token")
        assert error.message == "Invalid token"
        assert error.code == "AUTH_ERROR"
    
    def test_validation_error(self):
        """Test ValidationError creation."""
        error = ValidationError("Invalid input", field="email")
        assert error.message == "Invalid input"
        assert error.code == "VALIDATION_ERROR"
        assert error.details["field"] == "email"
    
    def test_rate_limit_error(self):
        """Test RateLimitError creation."""
        error = RateLimitError("Rate limit exceeded", retry_after=60)
        assert error.message == "Rate limit exceeded"
        assert error.code == "RATE_LIMIT_ERROR"
        assert error.details["retry_after"] == 60 