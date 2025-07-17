#!/usr/bin/env python3
"""
Test script to verify the Semgrep SDK installation.
Run this after installation to make sure everything works.
"""

import sys


def test_imports():
    """Test that all modules can be imported."""
    print("🧪 Testing imports...")
    
    try:
        from semgrep_sdk import SemgrepClient, AsyncSemgrepClient
        print("✅ Client classes imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import client classes: {e}")
        return False
    
    try:
        from semgrep_sdk.models import Repository, Scan, Finding, ScanConfig
        print("✅ Data models imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import data models: {e}")
        return False
    
    try:
        from semgrep_sdk.exceptions import SemgrepError, AuthenticationError
        print("✅ Exceptions imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import exceptions: {e}")
        return False
    
    try:
        from semgrep_sdk.utils import wait_for_scan_completion, export_findings_to_json
        print("✅ Utility functions imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import utility functions: {e}")
        return False
    
    return True


def test_client_creation():
    """Test that clients can be created (without API token)."""
    print("\n🧪 Testing client creation...")
    
    try:
        # This should fail with authentication error, not import error
        from semgrep_sdk import SemgrepClient
        client = SemgrepClient(api_token="invalid-token")
        print("✅ Client created successfully")
    except ImportError as e:
        print(f"❌ Import error when creating client: {e}")
        return False
    except Exception as e:
        # This is expected - we're using an invalid token
        if "authentication" in str(e).lower() or "token" in str(e).lower():
            print("✅ Client creation test passed (expected authentication error)")
            return True
        else:
            print(f"❌ Unexpected error when creating client: {e}")
            return False
    
    return True


def test_cli_import():
    """Test that CLI can be imported."""
    print("\n🧪 Testing CLI import...")
    
    try:
        from semgrep_sdk.cli import main
        print("✅ CLI imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import CLI: {e}")
        return False
    
    return True


def main():
    print("🚀 Semgrep Python SDK Installation Test")
    print("=" * 45)
    
    all_tests_passed = True
    
    # Test imports
    if not test_imports():
        all_tests_passed = False
    
    # Test client creation
    if not test_client_creation():
        all_tests_passed = False
    
    # Test CLI import
    if not test_cli_import():
        all_tests_passed = False
    
    print("\n" + "=" * 45)
    if all_tests_passed:
        print("🎉 All tests passed! Installation is working correctly.")
        print("\n📋 Next steps:")
        print("1. Set your Semgrep API token:")
        print("   export SEMGREP_API_TOKEN='your-api-token'")
        print("2. Try the basic example:")
        print("   python examples/basic_usage.py")
        print("3. Or use the CLI:")
        print("   semgrep-sdk --help")
    else:
        print("❌ Some tests failed. Please check your installation.")
        print("Try running: python install.py")
        sys.exit(1)


if __name__ == "__main__":
    main() 