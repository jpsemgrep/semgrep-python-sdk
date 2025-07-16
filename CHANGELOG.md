# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Semgrep Python SDK
- Complete API coverage for Semgrep endpoints
- Synchronous and asynchronous client implementations
- Comprehensive data models with Pydantic validation
- Rich command-line interface with progress indicators
- Utility functions for common operations
- Full test suite with mocking
- Type hints throughout the codebase
- Comprehensive documentation and examples

### Features
- **Client Classes**: `SemgrepClient` and `AsyncSemgrepClient`
- **Repository Management**: List, get, create, delete repositories
- **Scan Operations**: Start scans, monitor progress, get results
- **Ruleset Management**: List, get, create custom rulesets
- **Organization Management**: List, get, create organizations
- **User Operations**: Get current user information
- **CLI Interface**: Full command-line interface with subcommands
- **Utility Functions**: Export findings, wait for completion, batch operations
- **Error Handling**: Comprehensive exception hierarchy
- **Data Models**: Complete Pydantic models for all API responses

### Technical Details
- Python 3.8+ support
- Async/await support with aiohttp
- Type safety with mypy configuration
- Code formatting with black and isort
- Linting with flake8
- Testing with pytest and pytest-asyncio
- Coverage reporting
- Modern packaging with pyproject.toml

## [0.1.0] - 2024-01-01

### Added
- Initial release
- Basic client functionality
- Core API endpoints
- CLI interface
- Documentation 