#!/usr/bin/env python3
"""
Simple installation script for the Semgrep Python SDK.
This script helps install the package and its dependencies.
"""

import subprocess
import sys
import os


def run_command(command, description):
    """Run a command and handle errors."""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Error: {e.stderr}")
        return False


def main():
    print("🚀 Semgrep Python SDK Installation")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not os.path.exists("setup.py"):
        print("❌ Error: setup.py not found. Please run this script from the project root directory.")
        sys.exit(1)
    
    # Install dependencies first
    print("\n📦 Installing dependencies...")
    if not run_command("pip install -r requirements.txt", "Installing dependencies"):
        print("❌ Failed to install dependencies. Please check your pip installation.")
        sys.exit(1)
    
    # Install the package
    print("\n📦 Installing Semgrep SDK...")
    install_mode = input("Install in development mode? (y/n, default: y): ").lower().strip()
    
    if install_mode in ['', 'y', 'yes']:
        command = "pip install -e ."
        description = "Installing Semgrep SDK in development mode"
    else:
        command = "pip install ."
        description = "Installing Semgrep SDK"
    
    if not run_command(command, description):
        print("❌ Failed to install Semgrep SDK.")
        sys.exit(1)
    
    # Test the installation
    print("\n🧪 Testing installation...")
    test_code = """
import sys
try:
    from semgrep_sdk import SemgrepClient
    print("✅ SemgrepClient imported successfully")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)
"""
    
    try:
        subprocess.run([sys.executable, "-c", test_code], check=True)
        print("✅ Installation test passed!")
    except subprocess.CalledProcessError:
        print("❌ Installation test failed!")
        sys.exit(1)
    
    print("\n🎉 Installation completed successfully!")
    print("\n📋 Next steps:")
    print("1. Set your Semgrep API token:")
    print("   export SEMGREP_API_TOKEN='your-api-token'")
    print("2. Try the basic example:")
    print("   python examples/basic_usage.py")
    print("3. Or use the CLI:")
    print("   semgrep-sdk --help")
    
    print("\n📚 For more information, see the README.md file.")


if __name__ == "__main__":
    main() 