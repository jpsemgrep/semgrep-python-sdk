"""
Main client classes for interacting with the Semgrep API.
"""

import asyncio
import json
import os
from typing import List, Optional, Dict, Any, Union
from urllib.parse import urljoin, urlencode

import aiohttp
import requests
from pydantic import ValidationError

from .exceptions import (
    SemgrepError,
    AuthenticationError,
    ValidationError as SDKValidationError,
    RateLimitError,
    NotFoundError,
    ServerError,
    ScanError,
)
from .models import (
    Repository,
    Scan,
    Finding,
    ScanConfig,
    Ruleset,
    Organization,
    User,
    ScanRequest,
    ScanResponse,
    RepositoryListResponse,
    ScanListResponse,
    FindingListResponse,
    RulesetListResponse,
    OrganizationListResponse,
)


class BaseClient:
    """Base class for Semgrep API clients."""
    
    def __init__(
        self,
        api_token: Optional[str] = None,
        base_url: str = "https://semgrep.dev/api/v1",
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.api_token = api_token or os.getenv("SEMGREP_API_TOKEN")
        if not self.api_token:
            raise AuthenticationError("API token is required. Set SEMGREP_API_TOKEN environment variable or pass api_token parameter.")
        
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = None
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests."""
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "User-Agent": "semgrep-python-sdk/0.1.0",
        }
    
    def _handle_response(self, response) -> Dict[str, Any]:
        """Handle API response and raise appropriate exceptions."""
        if response.status_code == 401:
            raise AuthenticationError("Invalid API token")
        elif response.status_code == 403:
            raise AuthenticationError("Insufficient permissions")
        elif response.status_code == 404:
            raise NotFoundError("Resource not found")
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(retry_after=int(retry_after) if retry_after else None)
        elif response.status_code >= 500:
            raise ServerError(f"Server error: {response.status_code}")
        elif response.status_code >= 400:
            try:
                error_data = response.json()
                message = error_data.get("message", "Bad request")
            except:
                message = f"Bad request: {response.status_code}"
            raise SemgrepError(message, code=f"HTTP_{response.status_code}")
        
        try:
            return response.json()
        except json.JSONDecodeError:
            raise SemgrepError("Invalid JSON response from server")
        
        # This should never be reached, but mypy needs it
        raise SemgrepError("Unexpected response handling")


class SemgrepClient(BaseClient):
    """Synchronous client for the Semgrep API."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.session = requests.Session()
        self.session.headers.update(self._get_headers())
    
    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make an HTTP request to the Semgrep API."""
        url = urljoin(self.base_url, endpoint)
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=self.timeout,
                )
                return self._handle_response(response)
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    raise SemgrepError(f"Request failed: {e}")
                continue
    
    # Repository Operations
    def list_repositories(
        self,
        organization_id: Optional[str] = None,
        page: int = 1,
        per_page: int = 100,
    ) -> RepositoryListResponse:
        """List repositories."""
        params = {"page": page, "per_page": per_page}
        if organization_id:
            params["organization_id"] = organization_id
        
        response = self._request("GET", "/repositories", params=params)
        return RepositoryListResponse(**response)
    
    def get_repository(self, repo_id: str) -> Repository:
        """Get a specific repository."""
        response = self._request("GET", f"/repositories/{repo_id}")
        return Repository(**response)
    
    def create_repository(
        self,
        name: str,
        url: str,
        organization_id: Optional[str] = None,
    ) -> Repository:
        """Create a new repository."""
        data = {"name": name, "url": url}
        if organization_id:
            data["organization_id"] = organization_id
        
        response = self._request("POST", "/repositories", json_data=data)
        return Repository(**response)
    
    def delete_repository(self, repo_id: str) -> bool:
        """Delete a repository."""
        self._request("DELETE", f"/repositories/{repo_id}")
        return True
    
    # Scan Operations
    def scan_repository(
        self,
        repo_url: str,
        ruleset: str,
        branch: Optional[str] = None,
        organization_id: Optional[str] = None,
        config: Optional[ScanConfig] = None,
    ) -> Scan:
        """Start a scan on a repository."""
        if config is None:
            config = ScanConfig(ruleset=ruleset, branch=branch)
        
        scan_request = ScanRequest(
            repository_url=repo_url,
            config=config,
            organization_id=organization_id,
        )
        
        response = self._request("POST", "/scans", json_data=scan_request.dict())
        return Scan(**response)
    
    def get_scan(self, scan_id: str) -> Scan:
        """Get a specific scan."""
        response = self._request("GET", f"/scans/{scan_id}")
        return Scan(**response)
    
    def get_scan_status(self, scan_id: str) -> str:
        """Get the status of a scan."""
        scan = self.get_scan(scan_id)
        return scan.status
    
    def get_scan_results(self, scan_id: str) -> List[Finding]:
        """Get results from a completed scan."""
        scan = self.get_scan(scan_id)
        if scan.status != "completed":
            raise ScanError(f"Scan {scan_id} is not completed (status: {scan.status})")
        return scan.findings or []
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        self._request("POST", f"/scans/{scan_id}/cancel")
        return True
    
    def list_scans(
        self,
        repository_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 100,
    ) -> ScanListResponse:
        """List scans."""
        params = {"page": page, "per_page": per_page}
        if repository_id:
            params["repository_id"] = repository_id
        if organization_id:
            params["organization_id"] = organization_id
        if status:
            params["status"] = status
        
        response = self._request("GET", "/scans", params=params)
        return ScanListResponse(**response)
    
    # Ruleset Operations
    def list_rulesets(
        self,
        organization_id: Optional[str] = None,
        page: int = 1,
        per_page: int = 100,
    ) -> RulesetListResponse:
        """List rulesets."""
        params = {"page": page, "per_page": per_page}
        if organization_id:
            params["organization_id"] = organization_id
        
        response = self._request("GET", "/rulesets", params=params)
        return RulesetListResponse(**response)
    
    def get_ruleset(self, ruleset_id: str) -> Ruleset:
        """Get a specific ruleset."""
        response = self._request("GET", f"/rulesets/{ruleset_id}")
        return Ruleset(**response)
    
    def create_ruleset(
        self,
        name: str,
        rules: List[Dict[str, Any]],
        description: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> Ruleset:
        """Create a custom ruleset."""
        data = {"name": name, "rules": rules}
        if description:
            data["description"] = description
        if organization_id:
            data["organization_id"] = organization_id
        
        response = self._request("POST", "/rulesets", json_data=data)
        return Ruleset(**response)
    
    # Organization Operations
    def list_organizations(
        self,
        page: int = 1,
        per_page: int = 100,
    ) -> OrganizationListResponse:
        """List organizations."""
        params = {"page": page, "per_page": per_page}
        response = self._request("GET", "/organizations", params=params)
        return OrganizationListResponse(**response)
    
    def get_organization(self, org_id: str) -> Organization:
        """Get a specific organization."""
        response = self._request("GET", f"/organizations/{org_id}")
        return Organization(**response)
    
    def create_organization(self, name: str) -> Organization:
        """Create a new organization."""
        response = self._request("POST", "/organizations", json_data={"name": name})
        return Organization(**response)
    
    # User Operations
    def get_current_user(self) -> User:
        """Get the current authenticated user."""
        response = self._request("GET", "/user")
        return User(**response)
    
    def close(self):
        """Close the client session."""
        if self.session:
            self.session.close()


class AsyncSemgrepClient(BaseClient):
    """Asynchronous client for the Semgrep API."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            headers=self._get_headers(),
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make an async HTTP request to the Semgrep API."""
        if not self.session:
            raise SemgrepError("Client not initialized. Use async with statement.")
        
        url = urljoin(self.base_url, endpoint)
        
        for attempt in range(self.max_retries):
            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json_data,
                ) as response:
                    if response.status == 401:
                        raise AuthenticationError("Invalid API token")
                    elif response.status == 403:
                        raise AuthenticationError("Insufficient permissions")
                    elif response.status == 404:
                        raise NotFoundError("Resource not found")
                    elif response.status == 429:
                        retry_after = response.headers.get("Retry-After")
                        raise RateLimitError(retry_after=int(retry_after) if retry_after else None)
                    elif response.status >= 500:
                        raise ServerError(f"Server error: {response.status}")
                    elif response.status >= 400:
                        try:
                            error_data = await response.json()
                            message = error_data.get("message", "Bad request")
                        except:
                            message = f"Bad request: {response.status}"
                        raise SemgrepError(message, code=f"HTTP_{response.status}")
                    
                    return await response.json()
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    raise SemgrepError(f"Request failed: {e}")
                continue
        
        # This should never be reached, but mypy needs it
        raise SemgrepError("Unexpected async request handling")
    
    # Async versions of all methods from SemgrepClient
    async def list_repositories(
        self,
        organization_id: Optional[str] = None,
        page: int = 1,
        per_page: int = 100,
    ) -> RepositoryListResponse:
        """List repositories."""
        params = {"page": page, "per_page": per_page}
        if organization_id:
            params["organization_id"] = organization_id
        
        response = await self._request("GET", "/repositories", params=params)
        return RepositoryListResponse(**response)
    
    async def get_repository(self, repo_id: str) -> Repository:
        """Get a specific repository."""
        response = await self._request("GET", f"/repositories/{repo_id}")
        return Repository(**response)
    
    async def create_repository(
        self,
        name: str,
        url: str,
        organization_id: Optional[str] = None,
    ) -> Repository:
        """Create a new repository."""
        data = {"name": name, "url": url}
        if organization_id:
            data["organization_id"] = organization_id
        
        response = await self._request("POST", "/repositories", json_data=data)
        return Repository(**response)
    
    async def delete_repository(self, repo_id: str) -> bool:
        """Delete a repository."""
        await self._request("DELETE", f"/repositories/{repo_id}")
        return True
    
    async def scan_repository(
        self,
        repo_url: str,
        ruleset: str,
        branch: Optional[str] = None,
        organization_id: Optional[str] = None,
        config: Optional[ScanConfig] = None,
    ) -> Scan:
        """Start a scan on a repository."""
        if config is None:
            config = ScanConfig(ruleset=ruleset, branch=branch)
        
        scan_request = ScanRequest(
            repository_url=repo_url,
            config=config,
            organization_id=organization_id,
        )
        
        response = await self._request("POST", "/scans", json_data=scan_request.dict())
        return Scan(**response)
    
    async def get_scan(self, scan_id: str) -> Scan:
        """Get a specific scan."""
        response = await self._request("GET", f"/scans/{scan_id}")
        return Scan(**response)
    
    async def get_scan_status(self, scan_id: str) -> str:
        """Get the status of a scan."""
        scan = await self.get_scan(scan_id)
        return scan.status
    
    async def get_scan_results(self, scan_id: str) -> List[Finding]:
        """Get results from a completed scan."""
        scan = await self.get_scan(scan_id)
        if scan.status != "completed":
            raise ScanError(f"Scan {scan_id} is not completed (status: {scan.status})")
        return scan.findings or []
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        await self._request("POST", f"/scans/{scan_id}/cancel")
        return True
    
    async def list_scans(
        self,
        repository_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 100,
    ) -> ScanListResponse:
        """List scans."""
        params = {"page": page, "per_page": per_page}
        if repository_id:
            params["repository_id"] = repository_id
        if organization_id:
            params["organization_id"] = organization_id
        if status:
            params["status"] = status
        
        response = await self._request("GET", "/scans", params=params)
        return ScanListResponse(**response)
    
    async def list_rulesets(
        self,
        organization_id: Optional[str] = None,
        page: int = 1,
        per_page: int = 100,
    ) -> RulesetListResponse:
        """List rulesets."""
        params = {"page": page, "per_page": per_page}
        if organization_id:
            params["organization_id"] = organization_id
        
        response = await self._request("GET", "/rulesets", params=params)
        return RulesetListResponse(**response)
    
    async def get_ruleset(self, ruleset_id: str) -> Ruleset:
        """Get a specific ruleset."""
        response = await self._request("GET", f"/rulesets/{ruleset_id}")
        return Ruleset(**response)
    
    async def create_ruleset(
        self,
        name: str,
        rules: List[Dict[str, Any]],
        description: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> Ruleset:
        """Create a custom ruleset."""
        data = {"name": name, "rules": rules}
        if description:
            data["description"] = description
        if organization_id:
            data["organization_id"] = organization_id
        
        response = await self._request("POST", "/rulesets", json_data=data)
        return Ruleset(**response)
    
    async def list_organizations(
        self,
        page: int = 1,
        per_page: int = 100,
    ) -> OrganizationListResponse:
        """List organizations."""
        params = {"page": page, "per_page": per_page}
        response = await self._request("GET", "/organizations", params=params)
        return OrganizationListResponse(**response)
    
    async def get_organization(self, org_id: str) -> Organization:
        """Get a specific organization."""
        response = await self._request("GET", f"/organizations/{org_id}")
        return Organization(**response)
    
    async def create_organization(self, name: str) -> Organization:
        """Create a new organization."""
        response = await self._request("POST", "/organizations", json_data={"name": name})
        return Organization(**response)
    
    async def get_current_user(self) -> User:
        """Get the current authenticated user."""
        response = await self._request("GET", "/user")
        return User(**response) 