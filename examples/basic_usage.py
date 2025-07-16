#!/usr/bin/env python3
"""
Basic usage example for the Semgrep Python SDK.

This example demonstrates:
1. Setting up authentication
2. Listing repositories
3. Starting a scan
4. Getting scan results
5. Basic error handling
"""

import os
from semgrep_sdk import SemgrepClient, ScanConfig
from semgrep_sdk.utils import wait_for_scan_completion, export_findings_to_json


def main():
    # Set your API token (you can also use environment variable SEMGREP_API_TOKEN)
    api_token = os.getenv("SEMGREP_API_TOKEN")
    if not api_token:
        print("Please set SEMGREP_API_TOKEN environment variable")
        return
    
    # Initialize the client
    client = SemgrepClient(api_token=api_token)
    
    try:
        # Get current user information
        print("=== Current User ===")
        user = client.get_current_user()
        print(f"Username: {user.username}")
        print(f"Email: {user.email}")
        print()
        
        # List repositories
        print("=== Repositories ===")
        repos_response = client.list_repositories(per_page=5)
        print(f"Found {repos_response.total} repositories")
        
        for repo in repos_response.data:
            print(f"- {repo.name}: {repo.url}")
        print()
        
        # List available rulesets
        print("=== Available Rulesets ===")
        rulesets_response = client.list_rulesets(per_page=5)
        print(f"Found {rulesets_response.total} rulesets")
        
        for ruleset in rulesets_response.data:
            print(f"- {ruleset.name}: {ruleset.description or 'No description'}")
        print()
        
        # Example: Scan a repository (replace with actual repo URL)
        repo_url = "https://github.com/username/example-repo"  # Replace with actual repo
        ruleset = "p/security-audit"  # Replace with actual ruleset
        
        print(f"=== Starting Scan ===")
        print(f"Repository: {repo_url}")
        print(f"Ruleset: {ruleset}")
        
        # Create custom scan configuration
        config = ScanConfig(
            ruleset=ruleset,
            branch="main",
            exclude_patterns=["**/test/**", "**/vendor/**"],
            include_patterns=["**/*.py", "**/*.js"],
            timeout=300
        )
        
        # Start the scan
        scan = client.scan_repository(
            repo_url=repo_url,
            ruleset=ruleset,
            config=config
        )
        
        print(f"Scan started with ID: {scan.id}")
        print(f"Status: {scan.status}")
        
        # Wait for scan completion
        print("Waiting for scan to complete...")
        completed_scan = wait_for_scan_completion(
            client=client,
            scan_id=scan.id,
            timeout=1800,  # 30 minutes
            verbose=True
        )
        
        print(f"Scan completed! Status: {completed_scan.status}")
        
        # Get findings
        findings = completed_scan.findings or []
        print(f"Found {len(findings)} issues")
        
        if findings:
            # Display findings summary
            print("\n=== Findings Summary ===")
            severity_counts = {}
            for finding in findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in severity_counts.items():
                print(f"{severity}: {count}")
            
            # Display first few findings
            print("\n=== Sample Findings ===")
            for i, finding in enumerate(findings[:5]):
                print(f"{i+1}. [{finding.severity.value}] {finding.rule_id}")
                print(f"   Message: {finding.message}")
                print(f"   File: {finding.location.path}:{finding.location.start_line}")
                print()
            
            # Export findings to JSON
            export_findings_to_json(findings, "scan_results.json")
            print("Findings exported to scan_results.json")
        else:
            print("No security issues found!")
        
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        # Clean up
        client.close()


if __name__ == "__main__":
    main() 