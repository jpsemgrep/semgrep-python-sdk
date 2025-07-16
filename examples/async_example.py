#!/usr/bin/env python3
"""
Async usage example for the Semgrep Python SDK.

This example demonstrates:
1. Using the async client
2. Concurrent scanning of multiple repositories
3. Async context management
4. Error handling in async operations
"""

import asyncio
import os
from semgrep_sdk import AsyncSemgrepClient, ScanConfig
from semgrep_sdk.utils import scan_multiple_repositories_async, export_findings_to_json


async def main():
    # Set your API token
    api_token = os.getenv("SEMGREP_API_TOKEN")
    if not api_token:
        print("Please set SEMGREP_API_TOKEN environment variable")
        return
    
    # List of repositories to scan
    repositories = [
        "https://github.com/username/repo1",
        "https://github.com/username/repo2",
        "https://github.com/username/repo3",
        # Add more repositories as needed
    ]
    
    ruleset = "p/security-audit"
    
    # Use async context manager for proper resource management
    async with AsyncSemgrepClient(api_token=api_token) as client:
        try:
            # Get current user information
            print("=== Current User ===")
            user = await client.get_current_user()
            print(f"Username: {user.username}")
            print(f"Email: {user.email}")
            print()
            
            # List organizations
            print("=== Organizations ===")
            orgs_response = await client.list_organizations(per_page=5)
            print(f"Found {orgs_response.total} organizations")
            
            for org in orgs_response.data:
                print(f"- {org.name} ({org.slug})")
            print()
            
            # Scan multiple repositories concurrently
            print("=== Concurrent Scanning ===")
            print(f"Scanning {len(repositories)} repositories with ruleset: {ruleset}")
            
            # Create custom scan configuration
            config = ScanConfig(
                ruleset=ruleset,
                branch="main",
                exclude_patterns=["**/test/**", "**/vendor/**"],
                include_patterns=["**/*.py", "**/*.js"],
                timeout=300
            )
            
            # Scan repositories concurrently
            completed_scans = await scan_multiple_repositories_async(
                client=client,
                repo_urls=repositories,
                ruleset=ruleset,
                wait_for_completion=True,
                max_concurrent=3  # Limit concurrent scans
            )
            
            print(f"\nCompleted {len(completed_scans)} scans")
            
            # Process results
            all_findings = []
            for scan in completed_scans:
                if scan.findings:
                    all_findings.extend(scan.findings)
                    print(f"Scan {scan.id}: {len(scan.findings)} findings")
                else:
                    print(f"Scan {scan.id}: No findings")
            
            if all_findings:
                print(f"\nTotal findings across all scans: {len(all_findings)}")
                
                # Export all findings
                export_findings_to_json(all_findings, "async_scan_results.json")
                print("All findings exported to async_scan_results.json")
                
                # Show summary by severity
                severity_counts = {}
                for finding in all_findings:
                    severity = finding.severity.value
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                print("\n=== Overall Summary ===")
                for severity, count in severity_counts.items():
                    print(f"{severity}: {count}")
            else:
                print("No security issues found across all repositories!")
        
        except Exception as e:
            print(f"Error: {e}")


async def individual_scan_example():
    """Example of scanning a single repository with async client."""
    api_token = os.getenv("SEMGREP_API_TOKEN")
    if not api_token:
        print("Please set SEMGREP_API_TOKEN environment variable")
        return
    
    async with AsyncSemgrepClient(api_token=api_token) as client:
        try:
            repo_url = "https://github.com/username/example-repo"
            ruleset = "p/security-audit"
            
            print(f"Starting scan of {repo_url}")
            
            # Start scan
            scan = await client.scan_repository(
                repo_url=repo_url,
                ruleset=ruleset,
                branch="main"
            )
            
            print(f"Scan started: {scan.id}")
            
            # Poll for completion
            while True:
                scan = await client.get_scan(scan.id)
                print(f"Status: {scan.status} ({scan.progress or 0}%)")
                
                if scan.status == "completed":
                    break
                elif scan.status in ["failed", "cancelled"]:
                    print(f"Scan failed: {scan.error_message}")
                    return
                
                await asyncio.sleep(10)  # Wait 10 seconds before checking again
            
            # Get results
            findings = await client.get_scan_results(scan.id)
            print(f"Found {len(findings)} issues")
            
            if findings:
                for finding in findings[:3]:  # Show first 3 findings
                    print(f"- [{finding.severity.value}] {finding.rule_id}: {finding.message}")
        
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    # Run the main example
    asyncio.run(main())
    
    # Uncomment to run individual scan example
    # asyncio.run(individual_scan_example()) 