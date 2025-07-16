"""
Utility functions for the Semgrep SDK.
"""

import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

from .client import SemgrepClient, AsyncSemgrepClient
from .models import Scan, Finding, ScanConfig, Repository
from .exceptions import SemgrepError, ScanError


def wait_for_scan_completion(
    client: SemgrepClient,
    scan_id: str,
    timeout: int = 3600,
    poll_interval: int = 5,
    verbose: bool = False,
) -> Scan:
    """
    Wait for a scan to complete.
    
    Args:
        client: Semgrep client instance
        scan_id: ID of the scan to wait for
        timeout: Maximum time to wait in seconds
        poll_interval: How often to check status in seconds
        verbose: Whether to print status updates
    
    Returns:
        Completed scan object
        
    Raises:
        ScanError: If scan fails or times out
    """
    start_time = datetime.now()
    
    while True:
        if datetime.now() - start_time > timedelta(seconds=timeout):
            raise ScanError(f"Scan {scan_id} timed out after {timeout} seconds")
        
        try:
            scan = client.get_scan(scan_id)
            
            if verbose:
                print(f"Scan {scan_id}: {scan.status} ({scan.progress or 0}%)")
            
            if scan.status == "completed":
                return scan
            elif scan.status in ["failed", "cancelled"]:
                raise ScanError(f"Scan {scan_id} {scan.status}: {scan.error_message}")
            
            time.sleep(poll_interval)
            
        except Exception as e:
            if verbose:
                print(f"Error checking scan status: {e}")
            time.sleep(poll_interval)


async def wait_for_scan_completion_async(
    client: AsyncSemgrepClient,
    scan_id: str,
    timeout: int = 3600,
    poll_interval: int = 5,
    verbose: bool = False,
) -> Scan:
    """
    Wait for a scan to complete (async version).
    
    Args:
        client: Async Semgrep client instance
        scan_id: ID of the scan to wait for
        timeout: Maximum time to wait in seconds
        poll_interval: How often to check status in seconds
        verbose: Whether to print status updates
    
    Returns:
        Completed scan object
        
    Raises:
        ScanError: If scan fails or times out
    """
    start_time = datetime.now()
    
    while True:
        if datetime.now() - start_time > timedelta(seconds=timeout):
            raise ScanError(f"Scan {scan_id} timed out after {timeout} seconds")
        
        try:
            scan = await client.get_scan(scan_id)
            
            if verbose:
                print(f"Scan {scan_id}: {scan.status} ({scan.progress or 0}%)")
            
            if scan.status == "completed":
                return scan
            elif scan.status in ["failed", "cancelled"]:
                raise ScanError(f"Scan {scan_id} {scan.status}: {scan.error_message}")
            
            await asyncio.sleep(poll_interval)
            
        except Exception as e:
            if verbose:
                print(f"Error checking scan status: {e}")
            await asyncio.sleep(poll_interval)


def scan_multiple_repositories(
    client: SemgrepClient,
    repo_urls: List[str],
    ruleset: str,
    branch: Optional[str] = None,
    organization_id: Optional[str] = None,
    wait_for_completion: bool = True,
    max_concurrent: int = 5,
) -> List[Scan]:
    """
    Scan multiple repositories concurrently.
    
    Args:
        client: Semgrep client instance
        repo_urls: List of repository URLs to scan
        ruleset: Ruleset to use for scanning
        branch: Branch to scan
        organization_id: Organization ID
        wait_for_completion: Whether to wait for all scans to complete
        max_concurrent: Maximum number of concurrent scans
    
    Returns:
        List of scan objects
    """
    scans = []
    
    # Start scans in batches
    for i in range(0, len(repo_urls), max_concurrent):
        batch = repo_urls[i:i + max_concurrent]
        batch_scans = []
        
        for repo_url in batch:
            try:
                scan = client.scan_repository(
                    repo_url=repo_url,
                    ruleset=ruleset,
                    branch=branch,
                    organization_id=organization_id,
                )
                batch_scans.append(scan)
                print(f"Started scan {scan.id} for {repo_url}")
            except Exception as e:
                print(f"Failed to start scan for {repo_url}: {e}")
        
        if wait_for_completion:
            # Wait for batch to complete
            for scan in batch_scans:
                try:
                    completed_scan = wait_for_scan_completion(client, scan.id)
                    scans.append(completed_scan)
                except Exception as e:
                    print(f"Scan {scan.id} failed: {e}")
        else:
            scans.extend(batch_scans)
    
    return scans


async def scan_multiple_repositories_async(
    client: AsyncSemgrepClient,
    repo_urls: List[str],
    ruleset: str,
    branch: Optional[str] = None,
    organization_id: Optional[str] = None,
    wait_for_completion: bool = True,
    max_concurrent: int = 5,
) -> List[Scan]:
    """
    Scan multiple repositories concurrently (async version).
    
    Args:
        client: Async Semgrep client instance
        repo_urls: List of repository URLs to scan
        ruleset: Ruleset to use for scanning
        branch: Branch to scan
        organization_id: Organization ID
        wait_for_completion: Whether to wait for all scans to complete
        max_concurrent: Maximum number of concurrent scans
    
    Returns:
        List of scan objects
    """
    scans = []
    
    # Start scans in batches
    for i in range(0, len(repo_urls), max_concurrent):
        batch = repo_urls[i:i + max_concurrent]
        batch_scans = []
        
        # Start batch of scans
        tasks = []
        for repo_url in batch:
            task = client.scan_repository(
                repo_url=repo_url,
                ruleset=ruleset,
                branch=branch,
                organization_id=organization_id,
            )
            tasks.append(task)
        
        try:
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    print(f"Failed to start scan for {batch[j]}: {result}")
                else:
                    batch_scans.append(result)
                    print(f"Started scan {getattr(result, 'id', 'unknown')} for {batch[j]}")
        except Exception as e:
            print(f"Failed to start batch: {e}")
        
        if wait_for_completion:
            # Wait for batch to complete
            wait_tasks = []
            for scan in batch_scans:
                task = wait_for_scan_completion_async(client, scan.id)
                wait_tasks.append(task)
            
            try:
                completed_scans = await asyncio.gather(*wait_tasks, return_exceptions=True)
                for scan in completed_scans:
                    if isinstance(scan, Exception):
                        print(f"Scan failed: {scan}")
                    else:
                        scans.append(scan)
            except Exception as e:
                print(f"Failed to wait for batch completion: {e}")
        else:
            scans.extend(batch_scans)
    
    return scans


def export_findings_to_json(
    findings: List[Finding],
    output_file: Union[str, Path],
    include_metadata: bool = True,
) -> None:
    """
    Export findings to a JSON file.
    
    Args:
        findings: List of findings to export
        output_file: Path to output file
        include_metadata: Whether to include metadata in export
    """
    output_path = Path(output_file)
    
    data = []
    for finding in findings:
        finding_data = {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "message": finding.message,
            "severity": finding.severity.value,
            "location": {
                "path": finding.location.path,
                "start_line": finding.location.start_line,
                "end_line": finding.location.end_line,
                "start_column": finding.location.start_column,
                "end_column": finding.location.end_column,
                "snippet": finding.location.snippet,
            },
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
            "fixed": finding.fixed,
        }
        
        if include_metadata and finding.metadata:
            finding_data["metadata"] = finding.metadata
        
        data.append(finding_data)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Exported {len(findings)} findings to {output_path}")


def export_findings_to_csv(
    findings: List[Finding],
    output_file: Union[str, Path],
) -> None:
    """
    Export findings to a CSV file.
    
    Args:
        findings: List of findings to export
        output_file: Path to output file
    """
    import csv
    
    output_path = Path(output_file)
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow([
            "ID", "Rule ID", "Message", "Severity", "File", "Start Line",
            "End Line", "Start Column", "End Column", "Created At", "Fixed"
        ])
        
        # Write data
        for finding in findings:
            writer.writerow([
                finding.id,
                finding.rule_id,
                finding.message,
                finding.severity.value,
                finding.location.path,
                finding.location.start_line,
                finding.location.end_line,
                finding.location.start_column or "",
                finding.location.end_column or "",
                finding.created_at.isoformat() if finding.created_at else "",
                "Yes" if finding.fixed else "No",
            ])
    
    print(f"Exported {len(findings)} findings to {output_path}")


def create_custom_ruleset_from_file(
    client: SemgrepClient,
    name: str,
    rules_file: Union[str, Path],
    description: Optional[str] = None,
    organization_id: Optional[str] = None,
) -> str:
    """
    Create a custom ruleset from a YAML file.
    
    Args:
        client: Semgrep client instance
        name: Name for the ruleset
        rules_file: Path to YAML file containing rules
        description: Description for the ruleset
        organization_id: Organization ID
    
    Returns:
        Ruleset ID
    """
    import yaml
    
    rules_path = Path(rules_file)
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")
    
    with open(rules_path, 'r') as f:
        rules_data = yaml.safe_load(f)
    
    if not isinstance(rules_data, list):
        raise ValueError("Rules file must contain a list of rules")
    
    try:
        ruleset = client.create_ruleset(
            name=name,
            rules=rules_data,
            description=description,
            organization_id=organization_id,
        )
        print(f"Created ruleset '{name}' with ID: {ruleset.id}")
        return ruleset.id
    except Exception as e:
        raise SemgrepError(f"Failed to create ruleset: {e}")


def get_findings_summary(findings: List[Finding]) -> Dict[str, Any]:
    """
    Get a summary of findings by severity and rule.
    
    Args:
        findings: List of findings
    
    Returns:
        Summary dictionary
    """
    summary = {
        "total": len(findings),
        "by_severity": {},
        "by_rule": {},
        "by_file": {},
    }
    
    for finding in findings:
        # By severity
        severity = finding.severity.value
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        
        # By rule
        rule_id = finding.rule_id
        summary["by_rule"][rule_id] = summary["by_rule"].get(rule_id, 0) + 1
        
        # By file
        file_path = finding.location.path
        summary["by_file"][file_path] = summary["by_file"].get(file_path, 0) + 1
    
    return summary


def filter_findings(
    findings: List[Finding],
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    file_pattern: Optional[str] = None,
    fixed: Optional[bool] = None,
) -> List[Finding]:
    """
    Filter findings based on criteria.
    
    Args:
        findings: List of findings to filter
        severity: Filter by severity level
        rule_id: Filter by rule ID
        file_pattern: Filter by file path pattern
        fixed: Filter by fixed status
    
    Returns:
        Filtered list of findings
    """
    import fnmatch
    
    filtered = findings
    
    if severity:
        filtered = [f for f in filtered if f.severity.value == severity]
    
    if rule_id:
        filtered = [f for f in filtered if f.rule_id == rule_id]
    
    if file_pattern:
        filtered = [f for f in filtered if fnmatch.fnmatch(f.location.path, file_pattern)]
    
    if fixed is not None:
        filtered = [f for f in filtered if f.fixed == fixed]
    
    return filtered 