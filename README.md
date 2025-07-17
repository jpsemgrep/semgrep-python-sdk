# Semgrep Python SDK

A comprehensive Python SDK for the Semgrep API that makes it easy to interact with Semgrep's security scanning capabilities programmatically.

## Features

- **Complete API Coverage**: All Semgrep API endpoints supported
- **Type Safety**: Full type hints and Pydantic models for all data structures
- **Easy Authentication**: Simple token-based authentication
- **Async Support**: Both synchronous and asynchronous client options
- **Rich CLI**: Command-line interface for common operations
- **Comprehensive Examples**: Extensive documentation and examples

## Installation

This SDK is not available on PyPI yet. You have two options to use it:

### Option 1: Install from Local Directory (Recommended)

1. **Clone or download this repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/semgrep-python-sdk.git
   cd semgrep-python-sdk
   ```

2. **Install using the automated script** (easiest):
   ```bash
   python install.py
   ```

3. **OR install manually**:
   ```bash
   # Install dependencies first
   pip install -r requirements.txt
   
   # Install the package in development mode (recommended)
   pip install -e .
   
   # OR install normally
   pip install .
   ```

### Option 2: Install Dependencies Only

If you want to use the code directly without installing the package:

1. **Clone or download this repository**
2. **Install only the required dependencies**:
   ```bash
   pip install requests pydantic typing-extensions python-dateutil click rich tabulate aiohttp
   ```
3. **Use the modules directly**:
   ```python
   from semgrep_sdk.client import SemgrepClient
   from semgrep_sdk.models import ScanConfig
   ```

### Note
- This package is **NOT** available on PyPI (pip install semgrep-sdk won't work)
- You must have the source code locally to use this SDK
- The package will only be available in your local environment, not globally

### Verify Installation
After installation, you can test that everything works:
```bash
python test_installation.py
```

## Quick Start

### Basic Usage

```python
from semgrep_sdk import SemgrepClient

# Initialize client with your API token
client = SemgrepClient(api_token="your-api-token")

# Scan a repository
scan_result = client.scan_repository(
    repo_url="https://github.com/username/repo",
    ruleset="p/security-audit"
)

# Get scan results
for finding in scan_result.findings:
    print(f"Found {finding.rule_id} at {finding.location}")
```

### Authentication

```python
# Using environment variable
import os
client = SemgrepClient(api_token=os.getenv("SEMGREP_API_TOKEN"))

# Or directly
client = SemgrepClient(api_token="your-api-token")
```

## Core Features

### Repository Management

```python
# List all repositories
repos = client.list_repositories()

# Get repository details
repo = client.get_repository(repo_id="repo-id")

# Create a new repository
new_repo = client.create_repository(
    name="my-repo",
    url="https://github.com/username/repo"
)
```

### Scanning

```python
# Scan with custom rules
scan = client.scan_repository(
    repo_url="https://github.com/username/repo",
    ruleset="p/security-audit",
    branch="main"
)

# Get scan status
status = client.get_scan_status(scan_id=scan.id)

# Get scan results
results = client.get_scan_results(scan_id=scan.id)
```

### Rule Management

```python
# List available rulesets
rulesets = client.list_rulesets()

# Get ruleset details
ruleset = client.get_ruleset(ruleset_id="p/security-audit")

# Create custom ruleset
custom_ruleset = client.create_ruleset(
    name="my-custom-rules",
    rules=[
        {
            "id": "custom-rule-1",
            "pattern": "password = \"...\"",
            "message": "Hardcoded password detected"
        }
    ]
)
```

### Organization Management

```python
# List organizations
orgs = client.list_organizations()

# Get organization details
org = client.get_organization(org_id="org-id")

# Create organization
new_org = client.create_organization(name="my-org")
```

## CLI Usage

The SDK includes a command-line interface for common operations:

```bash
# Authenticate
semgrep-sdk auth --token your-api-token

# List repositories
semgrep-sdk repos list

# Scan a repository
semgrep-sdk scan --repo https://github.com/username/repo --ruleset p/security-audit

# Get scan results
semgrep-sdk results --scan-id scan-id
```

## Advanced Usage

### Async Client

```python
import asyncio
from semgrep_sdk import AsyncSemgrepClient

async def main():
    client = AsyncSemgrepClient(api_token="your-api-token")
    
    # Concurrent scans
    tasks = [
        client.scan_repository(repo_url=repo) 
        for repo in ["repo1", "repo2", "repo3"]
    ]
    
    results = await asyncio.gather(*tasks)
    return results

asyncio.run(main())
```

### Custom Configuration

```python
from semgrep_sdk import SemgrepClient, ScanConfig

# Custom scan configuration
config = ScanConfig(
    ruleset="p/security-audit",
    branch="develop",
    exclude_patterns=["**/test/**", "**/vendor/**"],
    include_patterns=["**/*.py", "**/*.js"],
    timeout=300
)

client = SemgrepClient(api_token="your-api-token")
scan = client.scan_repository(
    repo_url="https://github.com/username/repo",
    config=config
)
```

### Error Handling

```python
from semgrep_sdk import SemgrepError, SemgrepClient

client = SemgrepClient(api_token="your-api-token")

try:
    scan = client.scan_repository(repo_url="invalid-repo")
except SemgrepError as e:
    print(f"Semgrep error: {e.message}")
    print(f"Error code: {e.code}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## API Reference

### Core Classes

- `SemgrepClient`: Main synchronous client
- `AsyncSemgrepClient`: Asynchronous client
- `ScanConfig`: Configuration for scans
- `Repository`: Repository data model
- `Scan`: Scan data model
- `Finding`: Security finding data model

### Main Methods

#### Repository Operations
- `list_repositories()`: Get all repositories
- `get_repository(repo_id)`: Get specific repository
- `create_repository(name, url)`: Create new repository
- `delete_repository(repo_id)`: Delete repository

#### Scanning Operations
- `scan_repository(repo_url, ruleset)`: Start a scan
- `get_scan_status(scan_id)`: Get scan status
- `get_scan_results(scan_id)`: Get scan results
- `cancel_scan(scan_id)`: Cancel running scan

#### Rule Management
- `list_rulesets()`: Get available rulesets
- `get_ruleset(ruleset_id)`: Get ruleset details
- `create_ruleset(name, rules)`: Create custom ruleset

#### Organization Management
- `list_organizations()`: Get organizations
- `get_organization(org_id)`: Get organization details
- `create_organization(name)`: Create organization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Troubleshooting

### Import Errors
If you see import errors like "No module named 'requests'" or "No module named 'pydantic'", you need to install the dependencies:

```bash
pip install -r requirements.txt
```

### CLI Not Working
If the CLI commands don't work, make sure you have the required dependencies:

```bash
pip install click rich tabulate
```

### Authentication Errors
Make sure you have set your Semgrep API token:

```bash
export SEMGREP_API_TOKEN="your-api-token"
```

## Support

- Documentation: [https://semgrep.dev/docs](https://semgrep.dev/docs)
- API Reference: [https://semgrep.dev/api](https://semgrep.dev/api)
- Issues: [GitHub Issues](https://github.com/semgrep/semgrep-python-sdk/issues) 