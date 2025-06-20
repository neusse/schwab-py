#!/usr/bin/env python
"""
Simple Schwab Token Analyzer
Checks your Schwab API token and tests the connection

Usage:
    python schwab_simple.py                 # Basic check
    python schwab_simple.py --updates       # Check for package updates too
"""

import json
import time
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    import httpx
    from schwab.auth import client_from_token_file
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Install with: pip install schwab-py httpx")
    sys.exit(1)


class TokenChecker:
    """Simple class to check and analyze Schwab API tokens"""
    
    def __init__(self):
        self.refresh_warning_time = 300  # warn when 5 minutes left
        
        # Packages we care about
        self.important_packages = [
            'schwab-py', 'httpx', 'authlib', 'flask', 
            'urllib3', 'websockets', 'certifi', 'packaging'
        ]
    
    def load_token(self, token_file):
        """Load token from file and return the data"""
        if not os.path.exists(token_file):
            raise Exception(f"Token file not found: {token_file}")
        
        with open(token_file, 'r') as f:
            data = json.load(f)
        
        if 'token' not in data or 'creation_timestamp' not in data:
            raise Exception("Invalid token file format")
        
        return data
    
    def analyze_token(self, token_data):
        """Analyze the token and return useful info"""
        now = int(time.time())
        token = token_data['token']
        created = token_data['creation_timestamp']
        
        # Calculate times
        age = now - created
        expires_at = token.get('expires_at', 0)
        time_left = expires_at - now
        
        # Check status
        is_expired = time_left <= 0
        needs_refresh = time_left <= self.refresh_warning_time
        
        return {
            'created': created,
            'age_seconds': age,
            'expires_at': expires_at,
            'time_left': time_left,
            'is_expired': is_expired,
            'needs_refresh': needs_refresh,
            'refresh_token': token['refresh_token'],
            'access_token': token['access_token'],
            'token_type': token['token_type'],
            'scope': token['scope']
        }
    
    def format_time(self, seconds):
        """Convert seconds to human readable time"""
        if seconds < 0:
            seconds = abs(seconds)
        
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        return f"{days} days, {hours} hours, {minutes} minutes, {secs} seconds"
    
    def format_timestamp(self, timestamp):
        """Convert timestamp to readable date"""
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def get_package_version(self, package_name):
        """Get installed version of a package"""
        try:
            import importlib.metadata as metadata
            return metadata.version(package_name)
        except:
            return "not installed"
    
    def get_latest_version(self, package_name):
        """Get latest version from PyPI (if possible)"""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            with httpx.Client(timeout=5) as client:
                response = client.get(url)
                data = response.json()
                return data["info"]["version"]
        except:
            return None
    
    def check_packages(self, check_updates=False):
        """Check all important packages"""
        print("=== PACKAGE CHECK ===")
        print(f"Python version: {sys.version.split()[0]}")
        print()
        
        updates_available = []
        
        for pkg in self.important_packages:
            installed = self.get_package_version(pkg)
            line = f"{pkg:15} {installed}"
            
            if check_updates and installed != "not installed":
                latest = self.get_latest_version(pkg)
                if latest:
                    if latest != installed:
                        line += f" → {latest} (UPDATE AVAILABLE!)"
                        updates_available.append((pkg, installed, latest))
                    else:
                        line += f" (up to date)"
                else:
                    line += f" (couldn't check)"
            
            print(line)
        
        if updates_available:
            print(f"\n{len(updates_available)} packages can be updated:")
            for pkg, old, new in updates_available:
                print(f"  pip install --upgrade {pkg}")
    
    def print_token_info(self, analysis):
        """Print token analysis in a readable format"""
        print("\n=== TOKEN INFO ===")
        
        print(f"Created: {self.format_timestamp(analysis['created'])}")
        print(f"Age: {self.format_time(analysis['age_seconds'])}")
        
        # Show masked tokens for security
        refresh = analysis['refresh_token']
        access = analysis['access_token']
        print(f"Refresh Token: ...{refresh[-8:]}")
        print(f"Access Token:  ...{access[-8:]}")
        print(f"Token Type: {analysis['token_type']}")
        print(f"Scope: {analysis['scope']}")
        
        print(f"\nExpires: {self.format_timestamp(analysis['expires_at'])}")
        print(f"Time Left: {self.format_time(analysis['time_left'])}")
        
        if analysis['is_expired']:
            print("❌ TOKEN IS EXPIRED!")
        elif analysis['needs_refresh']:
            print("⚠️  TOKEN EXPIRES SOON - Consider refreshing")
        else:
            print("✅ Token is good")
    
    def test_api(self, api_key, app_secret, token_file):
        """Test if the API is working"""
        print("\n=== API TEST ===")
        
        try:
            # Create client
            print("Creating client...")
            start_time = time.time()
            client = client_from_token_file(
                api_key=api_key,
                app_secret=app_secret,
                token_path=str(token_file)
            )
            
            # Test with a quote
            print("Getting TSLA quote...")
            quote_start = time.time()
            response = client.get_quote('TSLA')
            quote_time = time.time() - quote_start
            
            if response.status_code == 200:
                data = response.json()
                price = data['TSLA']['regular']['regularMarketLastPrice']
                print(f"✅ Success! TSLA price: ${price}")
                print(f"Quote took: {quote_time:.2f} seconds")
                print(f"Total time: {time.time() - start_time:.2f} seconds")
            else:
                print(f"❌ API Error: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error: {e}")


def main():
    """Main function - keeps it simple"""
    
    # Simple argument handling
    check_updates = '--updates' in sys.argv or '-u' in sys.argv
    
    # Get settings from environment
    api_key = os.getenv("schwab_api_key")
    app_secret = os.getenv("schwab_app_secret") 
    token_path = os.getenv("schwab_token_path")
    
    if not all([api_key, app_secret, token_path]):
        print("❌ Missing environment variables:")
        print("   schwab_api_key")
        print("   schwab_app_secret") 
        print("   schwab_token_path")
        return
    
    try:
        # Do the work
        checker = TokenChecker()
        
        # Check packages first
        checker.check_packages(check_updates)
        
        # Load and analyze token
        token_data = checker.load_token(token_path)
        analysis = checker.analyze_token(token_data)
        checker.print_token_info(analysis)
        
        # Test the API if token looks good
        if not analysis['is_expired']:
            checker.test_api(api_key, app_secret, token_path)
        else:
            print("\n⏭️  Skipping API test - token is expired")
            
        if not check_updates:
            print(f"\n💡 Use 'python {sys.argv[0]} --updates' to check for package updates")
            
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
