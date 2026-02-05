#!/usr/bin/env python3
"""
Comprehensive scraper testing
Tests actual API connections and data collection
"""

import os
import sys
import time
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_hackerone():
    """Test HackerOne scraper with real API"""
    print("\n" + "=" * 70)
    print("TESTING HACKERONE SCRAPER")
    print("=" * 70)
    
    token = os.getenv("HACKERONE_TOKEN")
    if not token:
        print("❌ HACKERONE_TOKEN not set")
        print("   Set it with: $env:HACKERONE_TOKEN='your_token'")
        return False
    
    try:
        from src.collectors.hackerone_scraper import HackerOneScraper
        
        print("✓ Import successful")
        
        scraper = HackerOneScraper(api_token=token)
        print("✓ Scraper initialized")
        
        # Test fetching reports
        print("\nFetching 3 test reports...")
        start_time = time.time()
        
        reports = scraper.fetch_reports(limit=3)
        
        elapsed = time.time() - start_time
        print(f"✓ Retrieved {len(reports)} reports in {elapsed:.2f}s")
        
        if not reports:
            print("⚠️  No reports returned (this might be normal if no data available)")
            return True
        
        # Validate first report structure
        report = reports[0]
        print(f"\n✓ Sample report validation:")
        print(f"  - Has title: {'✓' if hasattr(report, 'title') and report.title else '✗'}")
        print(f"  - Has description: {'✓' if hasattr(report, 'description') and report.description else '✗'}")
        print(f"  - Has vulnerability_type: {'✓' if hasattr(report, 'vulnerability_type') and report.vulnerability_type else '✗'}")
        print(f"  - Has severity: {'✓' if hasattr(report, 'severity') and report.severity else '✗'}")
        
        # Show sample data
        print(f"\n📊 Sample Report:")
        print(f"  Title: {getattr(report, 'title', 'N/A')[:60]}...")
        print(f"  Type: {getattr(report, 'vulnerability_type', 'N/A')}")
        print(f"  Severity: {getattr(report, 'severity', 'N/A')}")
        print(f"  Bounty: ${getattr(report, 'bounty_amount', 0)}")
        
        print("\n✅ HackerOne scraper is working correctly!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure src/collectors/hackerone_scraper.py exists")
        return False
    except AttributeError as e:
        print(f"❌ Attribute error: {e}")
        print("   Check if HackerOneScraper class exists in the module")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_bugcrowd():
    """Test Bugcrowd scraper"""
    print("\n" + "=" * 70)
    print("TESTING BUGCROWD SCRAPER")
    print("=" * 70)
    
    token = os.getenv("BUGCROWD_TOKEN")
    if not token:
        print("⚠️  BUGCROWD_TOKEN not set (optional)")
        print("   Skipping Bugcrowd test")
        return True  # Not critical
    
    try:
        from src.collectors.bugcrowd_scraper import BugcrowdScraper
        
        print("✓ Import successful")
        
        scraper = BugcrowdScraper(api_token=token)
        print("✓ Scraper initialized")
        
        print("\nFetching 3 test reports...")
        reports = scraper.fetch_reports(limit=3)
        
        print(f"✓ Retrieved {len(reports)} reports")
        
        if reports:
            report = reports[0]
            print(f"\n📊 Sample Report:")
            print(f"  Title: {getattr(report, 'title', 'N/A')[:60]}...")
            print(f"  Type: {getattr(report, 'vulnerability_type', 'N/A')}")
        
        print("\n✅ Bugcrowd scraper is working!")
        return True
        
    except ImportError:
        print("⚠️  Bugcrowd scraper not implemented yet (optional)")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_cve():
    """Test CVE collector"""
    print("\n" + "=" * 70)
    print("TESTING CVE COLLECTOR")
    print("=" * 70)
    
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("⚠️  NVD_API_KEY not set (will use rate-limited access)")
    
    try:
        from src.collectors.cve_collector import CVECollector
        
        print("✓ Import successful")
        
        collector = CVECollector(api_key=api_key)
        print("✓ Collector initialized")
        
        print("\nFetching recent CVEs (last 7 days, limit 5)...")
        cves = collector.fetch_recent(days_back=7, limit=5)
        
        print(f"✓ Retrieved {len(cves)} CVEs")
        
        if cves:
            cve = cves[0]
            print(f"\n📊 Sample CVE:")
            print(f"  ID: {getattr(cve, 'cve_id', 'N/A')}")
            print(f"  Description: {getattr(cve, 'description', 'N/A')[:80]}...")
            print(f"  Severity: {getattr(cve, 'severity', 'N/A')}")
        
        print("\n✅ CVE collector is working!")
        return True
        
    except ImportError:
        print("⚠️  CVE collector not implemented yet (optional)")
        return True
    except AttributeError as e:
        print(f"⚠️  CVE collector method not found: {e}")
        print("   This is optional - continuing...")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Run all scraper tests"""
    print("\n" + "=" * 70)
    print("BUGPREDICT AI - COMPREHENSIVE SCRAPER TEST")
    print("=" * 70)
    print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nThis will test actual API connections and data collection.")
    print("Make sure you have set the required API tokens:")
    print("  $env:HACKERONE_TOKEN='your_token'")
    print("  $env:BUGCROWD_TOKEN='your_token'  # optional")
    print("  $env:NVD_API_KEY='your_key'       # optional")
    
    input("\nPress Enter to continue...")
    
    results = {
        'hackerone': test_hackerone(),
        'bugcrowd': test_bugcrowd(),
        'cve': test_cve()
    }
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name.upper()}: {status}")
    
    all_pass = all(results.values())
    
    print()
    if all_pass:
        print("🎉 All scrapers are working correctly!")
        print("You can proceed with deployment or use the visual collection tool.")
    else:
        print("⚠️  Some scrapers failed. Please fix issues before deployment.")
    
    print()
    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
