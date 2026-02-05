#!/usr/bin/env python3
"""
Quick health check for all scrapers
Run this before deployment to verify scrapers are working
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def check_environment():
    """Check if required environment variables are set"""
    print("=" * 70)
    print("CHECKING ENVIRONMENT")
    print("=" * 70)
    
    required = {
        'HACKERONE_TOKEN': os.getenv('HACKERONE_TOKEN'),
        'BUGCROWD_TOKEN': os.getenv('BUGCROWD_TOKEN'),
        'NVD_API_KEY': os.getenv('NVD_API_KEY')
    }
    
    all_set = True
    for key, value in required.items():
        status = "✓" if value else "✗"
        importance = "(required)" if key == 'HACKERONE_TOKEN' else "(optional)"
        print(f"{status} {key}: {'SET' if value else 'NOT SET'} {importance}")
        
        if key == 'HACKERONE_TOKEN' and not value:
            all_set = False
    
    print()
    return all_set

def test_imports():
    """Test if all required modules can be imported"""
    print("=" * 70)
    print("CHECKING IMPORTS")
    print("=" * 70)
    
    modules_to_test = [
        ('src.collectors.hackerone_scraper', 'HackerOneScraper'),
        ('src.collectors.bugcrowd_scraper', 'BugcrowdScraper'),
        ('src.collectors.cve_collector', 'CVECollector'),
        ('src.collectors.data_sources', 'VulnerabilityReport'),
    ]
    
    all_imported = True
    
    for module_name, class_name in modules_to_test:
        try:
            module = __import__(module_name, fromlist=[class_name])
            cls = getattr(module, class_name)
            print(f"✓ {module_name}.{class_name}")
        except ImportError as e:
            print(f"✗ {module_name}.{class_name} - Error: {e}")
            all_imported = False
        except AttributeError as e:
            print(f"✗ {module_name}.{class_name} - Class not found: {e}")
            all_imported = False
    
    print()
    return all_imported

def test_scraper_initialization():
    """Test if scrapers can be initialized"""
    print("=" * 70)
    print("TESTING SCRAPER INITIALIZATION")
    print("=" * 70)
    
    all_initialized = True
    
    # Test HackerOne
    try:
        from src.collectors.hackerone_scraper import HackerOneScraper
        scraper = HackerOneScraper(api_token="test_token")
        print("✓ HackerOneScraper initialized")
    except Exception as e:
        print(f"✗ HackerOneScraper failed: {e}")
        all_initialized = False
    
    # Test Bugcrowd
    try:
        from src.collectors.bugcrowd_scraper import BugcrowdScraper
        scraper = BugcrowdScraper(api_token="test_token")
        print("✓ BugcrowdScraper initialized")
    except Exception as e:
        print(f"✗ BugcrowdScraper failed: {e}")
        all_initialized = False
    
    # Test CVE
    try:
        from src.collectors.cve_collector import CVECollector
        collector = CVECollector(api_key="test_key")
        print("✓ CVECollector initialized")
    except Exception as e:
        print(f"✗ CVECollector failed: {e}")
        all_initialized = False
    
    print()
    return all_initialized

def main():
    """Run all health checks"""
    print("\n" + "=" * 70)
    print("BUGPREDICT AI - SCRAPER HEALTH CHECK")
    print("=" * 70)
    print()
    
    results = {
        'environment': check_environment(),
        'imports': test_imports(),
        'initialization': test_scraper_initialization()
    }
    
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    for check, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{check.upper()}: {status}")
    
    all_pass = all(results.values())
    
    print()
    if all_pass:
        print("🎉 All basic health checks passed!")
        print("Ready to test live scraping.")
    else:
        print("⚠️  Some checks failed. Please fix issues before proceeding.")
    
    print()
    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
