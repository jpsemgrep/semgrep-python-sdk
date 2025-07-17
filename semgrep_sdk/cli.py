"""
Command-line interface for the Semgrep SDK.
"""

import json
import os
import sys
from typing import Optional

try:
    import click
except ImportError:
    click = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    Console = Table = Progress = SpinnerColumn = TextColumn = Panel = Text = None

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

from .client import SemgrepClient
from .exceptions import SemgrepError, AuthenticationError
from .models import ScanStatus, FindingSeverity

# Check for required dependencies
if click is None:
    raise ImportError("click library is required for CLI. Install with: pip install click")
if Console is None:
    raise ImportError("rich library is required for CLI. Install with: pip install rich")

console = Console()


def get_client() -> SemgrepClient:
    """Get a configured Semgrep client."""
    api_token = os.getenv("SEMGREP_API_TOKEN")
    if not api_token:
        console.print("[red]Error: SEMGREP_API_TOKEN environment variable not set[/red]")
        console.print("Please set your Semgrep API token:")
        console.print("export SEMGREP_API_TOKEN='your-api-token'")
        sys.exit(1)
    
    try:
        return SemgrepClient(api_token=api_token)
    except AuthenticationError as e:
        console.print(f"[red]Authentication error: {e}[/red]")
        sys.exit(1)


def display_table(data, headers, title: Optional[str] = None):
    """Display data in a formatted table."""
    if title:
        console.print(f"\n[bold blue]{title}[/bold blue]")
    
    if not data:
        console.print("[yellow]No data to display[/yellow]")
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    for header in headers:
        table.add_column(header)
    
    for row in data:
        table.add_row(*[str(cell) for cell in row])
    
    console.print(table)


def display_findings_table(findings, title: Optional[str] = None):
    """Display findings in a formatted table with severity colors."""
    if title:
        console.print(f"\n[bold blue]{title}[/bold blue]")
    
    if not findings:
        console.print("[yellow]No findings to display[/yellow]")
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Rule ID")
    table.add_column("Message")
    table.add_column("File")
    table.add_column("Line")
    
    for finding in findings:
        severity_style = {
            FindingSeverity.INFO: "blue",
            FindingSeverity.WARNING: "yellow",
            FindingSeverity.ERROR: "red",
            FindingSeverity.CRITICAL: "bold red",
        }.get(finding.severity, "white")
        
        table.add_row(
            f"[{severity_style}]{finding.severity.value}[/{severity_style}]",
            finding.rule_id,
            finding.message[:50] + "..." if len(finding.message) > 50 else finding.message,
            finding.location.path,
            str(finding.location.start_line),
        )
    
    console.print(table)


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Semgrep Python SDK - Command Line Interface."""
    pass


@main.group()
def auth():
    """Authentication commands."""
    pass


@auth.command()
@click.option("--token", prompt="Enter your Semgrep API token", hide_input=True)
def set_token(token):
    """Set your Semgrep API token."""
    # In a real implementation, you might want to store this securely
    # For now, we'll just validate it
    try:
        client = SemgrepClient(api_token=token)
        user = client.get_current_user()
        console.print(f"[green]✓ Authentication successful![/green]")
        console.print(f"Welcome, {user.username}!")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("1. Set the environment variable: export SEMGREP_API_TOKEN='your-token'")
        console.print("2. Or use the --token option with other commands")
    except Exception as e:
        console.print(f"[red]✗ Authentication failed: {e}[/red]")


@main.group()
def repos():
    """Repository management commands."""
    pass


@repos.command()
@click.option("--org-id", help="Filter by organization ID")
@click.option("--page", default=1, help="Page number")
@click.option("--per-page", default=100, help="Items per page")
def list_repos(org_id, page, per_page):
    """List repositories."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching repositories...", total=None)
        try:
            response = client.list_repositories(
                organization_id=org_id,
                page=page,
                per_page=per_page,
            )
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    data = []
    for repo in response.data:
        data.append([
            repo.id,
            repo.name,
            str(repo.url),
            repo.scan_count,
            repo.finding_count,
            repo.created_at.strftime("%Y-%m-%d"),
        ])
    
    display_table(
        data,
        ["ID", "Name", "URL", "Scans", "Findings", "Created"],
        f"Repositories (Page {page}, {len(response.data)} of {response.total})"
    )


@repos.command()
@click.argument("repo_id")
def get(repo_id):
    """Get repository details."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching repository...", total=None)
        try:
            repo = client.get_repository(repo_id)
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    console.print(Panel(
        f"[bold]Repository Details[/bold]\n\n"
        f"ID: {repo.id}\n"
        f"Name: {repo.name}\n"
        f"URL: {repo.url}\n"
        f"Organization ID: {repo.organization_id or 'N/A'}\n"
        f"Created: {repo.created_at}\n"
        f"Last Scan: {repo.last_scan_at or 'Never'}\n"
        f"Scan Count: {repo.scan_count}\n"
        f"Finding Count: {repo.finding_count}\n"
        f"Active: {'Yes' if repo.is_active else 'No'}",
        title="Repository Information"
    ))


@repos.command()
@click.option("--name", required=True, help="Repository name")
@click.option("--url", required=True, help="Repository URL")
@click.option("--org-id", help="Organization ID")
def create(name, url, org_id):
    """Create a new repository."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Creating repository...", total=None)
        try:
            repo = client.create_repository(name=name, url=url, organization_id=org_id)
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    console.print(f"[green]✓ Repository created successfully![/green]")
    console.print(f"ID: {repo.id}")
    console.print(f"Name: {repo.name}")
    console.print(f"URL: {repo.url}")


@main.group()
def scans():
    """Scan management commands."""
    pass


@scans.command()
@click.option("--repo-url", required=True, help="Repository URL to scan")
@click.option("--ruleset", required=True, help="Ruleset to use")
@click.option("--branch", help="Branch to scan")
@click.option("--org-id", help="Organization ID")
@click.option("--wait", is_flag=True, help="Wait for scan completion")
def start(repo_url, ruleset, branch, org_id, wait):
    """Start a new scan."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Starting scan...", total=None)
        try:
            scan = client.scan_repository(
                repo_url=repo_url,
                ruleset=ruleset,
                branch=branch,
                organization_id=org_id,
            )
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    console.print(f"[green]✓ Scan started successfully![/green]")
    console.print(f"Scan ID: {scan.id}")
    console.print(f"Status: {scan.status}")
    console.print(f"Repository: {repo_url}")
    console.print(f"Ruleset: {ruleset}")
    
    if wait:
        console.print("\n[bold]Waiting for scan completion...[/bold]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            
            while True:
                try:
                    scan = client.get_scan(scan.id)
                    if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                        progress.update(task, completed=True)
                        break
                    import time
                    time.sleep(5)  # Poll every 5 seconds
                except Exception as e:
                    progress.update(task, completed=True)
                    console.print(f"[red]Error checking scan status: {e}[/red]")
                    return
        
        if scan.status == ScanStatus.COMPLETED:
            console.print(f"[green]✓ Scan completed![/green]")
            findings = scan.findings or []
            console.print(f"Found {len(findings)} issues")
            
            if findings:
                display_findings_table(findings, "Scan Results")
        else:
            console.print(f"[red]✗ Scan {scan.status}: {scan.error_message or 'Unknown error'}[/red]")


@scans.command()
@click.argument("scan_id")
def status(scan_id):
    """Get scan status."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching scan status...", total=None)
        try:
            scan = client.get_scan(scan_id)
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    status_color = {
        ScanStatus.PENDING: "yellow",
        ScanStatus.RUNNING: "blue",
        ScanStatus.COMPLETED: "green",
        ScanStatus.FAILED: "red",
        ScanStatus.CANCELLED: "red",
    }.get(scan.status, "white")
    
    console.print(Panel(
        f"[bold]Scan Status[/bold]\n\n"
        f"ID: {scan.id}\n"
        f"Status: [{status_color}]{scan.status}[/{status_color}]\n"
        f"Repository ID: {scan.repository_id}\n"
        f"Created: {scan.created_at}\n"
        f"Started: {scan.started_at or 'Not started'}\n"
        f"Completed: {scan.completed_at or 'Not completed'}\n"
        f"Progress: {scan.progress or 0}%\n"
        f"Findings: {len(scan.findings or [])}\n"
        f"Error: {scan.error_message or 'None'}",
        title="Scan Information"
    ))


@scans.command()
@click.argument("scan_id")
def results(scan_id):
    """Get scan results."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching scan results...", total=None)
        try:
            findings = client.get_scan_results(scan_id)
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    if findings:
        display_findings_table(findings, f"Scan Results for {scan_id}")
        
        # Summary
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
        
        console.print("\n[bold]Summary:[/bold]")
        for severity, count in severity_counts.items():
            console.print(f"  {severity}: {count}")
    else:
        console.print("[green]✓ No findings detected![/green]")


@scans.command()
@click.option("--repo-id", help="Filter by repository ID")
@click.option("--org-id", help="Filter by organization ID")
@click.option("--status", help="Filter by status")
@click.option("--page", default=1, help="Page number")
@click.option("--per-page", default=100, help="Items per page")
def list_scans(repo_id, org_id, status, page, per_page):
    """List scans."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching scans...", total=None)
        try:
            response = client.list_scans(
                repository_id=repo_id,
                organization_id=org_id,
                status=status,
                page=page,
                per_page=per_page,
            )
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    data = []
    for scan in response.data:
        data.append([
            scan.id,
            scan.repository_id,
            scan.status,
            len(scan.findings or []),
            scan.created_at.strftime("%Y-%m-%d %H:%M"),
        ])
    
    display_table(
        data,
        ["ID", "Repository ID", "Status", "Findings", "Created"],
        f"Scans (Page {page}, {len(response.data)} of {response.total})"
    )


@main.group()
def rulesets():
    """Ruleset management commands."""
    pass


@rulesets.command()
@click.option("--org-id", help="Filter by organization ID")
@click.option("--page", default=1, help="Page number")
@click.option("--per-page", default=100, help="Items per page")
def list_rulesets(org_id, page, per_page):
    """List rulesets."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching rulesets...", total=None)
        try:
            response = client.list_rulesets(
                organization_id=org_id,
                page=page,
                per_page=per_page,
            )
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    data = []
    for ruleset in response.data:
        data.append([
            ruleset.id,
            ruleset.name,
            ruleset.description or "N/A",
            len(ruleset.rules),
            "Yes" if ruleset.is_public else "No",
            ruleset.created_at.strftime("%Y-%m-%d"),
        ])
    
    display_table(
        data,
        ["ID", "Name", "Description", "Rules", "Public", "Created"],
        f"Rulesets (Page {page}, {len(response.data)} of {response.total})"
    )


@main.group()
def orgs():
    """Organization management commands."""
    pass


@orgs.command()
@click.option("--page", default=1, help="Page number")
@click.option("--per-page", default=100, help="Items per page")
def list(page, per_page):
    """List organizations."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching organizations...", total=None)
        try:
            response = client.list_organizations(page=page, per_page=per_page)
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    data = []
    for org in response.data:
        data.append([
            org.id,
            org.name,
            org.slug,
            org.repository_count,
            org.member_count,
            org.plan or "N/A",
            org.created_at.strftime("%Y-%m-%d"),
        ])
    
    display_table(
        data,
        ["ID", "Name", "Slug", "Repos", "Members", "Plan", "Created"],
        f"Organizations (Page {page}, {len(response.data)} of {response.total})"
    )


@main.command()
def user():
    """Get current user information."""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching user information...", total=None)
        try:
            user = client.get_current_user()
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]Error: {e}[/red]")
            return
    
    console.print(Panel(
        f"[bold]User Information[/bold]\n\n"
        f"ID: {user.id}\n"
        f"Username: {user.username}\n"
        f"Email: {user.email}\n"
        f"Name: {user.name or 'N/A'}\n"
        f"Created: {user.created_at}\n"
        f"Active: {'Yes' if user.is_active else 'No'}\n"
        f"Organizations: {len(user.organization_ids or [])}",
        title="Current User"
    ))


if __name__ == "__main__":
    main() 