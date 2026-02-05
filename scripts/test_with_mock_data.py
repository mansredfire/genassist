#!/usr/bin/env python3
"""
Test visual collection with realistic mock data
Generates fake vulnerability reports that look like real HackerOne data
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import random
import time
from datetime import datetime, timedelta
from src.collectors.data_sources import VulnerabilityReport
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Realistic vulnerability data
VULNERABILITIES = {
    'SQL Injection': {
        'titles': [
            'SQL Injection in user search endpoint allows data extraction',
            'Blind SQL injection in login form bypasses authentication',
            'Second-order SQL injection via profile update',
            'Time-based SQL injection in API filtering'
        ],
        'severity': ['critical', 'high'],
        'bounties': (1000, 5000),
        'cwe': 'CWE-89'
    },
    'XSS': {
        'titles': [
            'Stored XSS in comment section leads to account takeover',
            'Reflected XSS in search parameter',
            'DOM-based XSS via URL fragment',
            'Persistent XSS through SVG file upload'
        ],
        'severity': ['high', 'medium'],
        'bounties': (500, 3000),
        'cwe': 'CWE-79'
    },
    'IDOR': {
        'titles': [
            'IDOR allows access to other users private messages',
            'Insecure direct object reference in document download',
            'IDOR in API endpoint exposes user data',
            'Authorization bypass via parameter manipulation'
        ],
        'severity': ['critical', 'high'],
        'bounties': (800, 4000),
        'cwe': 'CWE-639'
    },
    'SSRF': {
        'titles': [
            'SSRF via image upload allows internal network scanning',
            'Server-Side Request Forgery in URL preview feature',
            'SSRF in webhook integration leads to AWS metadata access',
            'Blind SSRF through PDF generation service'
        ],
        'severity': ['critical', 'high'],
        'bounties': (1500, 6000),
        'cwe': 'CWE-918'
    },
    'CSRF': {
        'titles': [
            'CSRF token not validated on password change',
            'Cross-site request forgery in account deletion',
            'Missing CSRF protection on admin actions',
            'CSRF allows unauthorized API key generation'
        ],
        'severity': ['medium', 'high'],
        'bounties': (300, 2000),
        'cwe': 'CWE-352'
    },
    'Authentication Bypass': {
        'titles': [
            'JWT signature verification bypass leads to admin access',
            'Race condition in 2FA allows authentication bypass',
            'OAuth misconfiguration enables account takeover',
            'Session fixation vulnerability in login flow'
        ],
        'severity': ['critical', 'high'],
        'bounties': (2000, 8000),
        'cwe': 'CWE-287'
    },
    'RCE': {
        'titles': [
            'Remote code execution via unsafe deserialization',
            'Command injection in file processing service',
            'Template injection leads to RCE',
            'Unsafe eval() in Node.js backend allows RCE'
        ],
        'severity': ['critical'],
        'bounties': (5000, 15000),
        'cwe': 'CWE-78'
    },
    'XXE': {
        'titles': [
            'XML External Entity injection in document parser',
            'XXE via SVG file upload exposes internal files',
            'Blind XXE through SOAP API',
            'XXE in SAML authentication leads to SSRF'
        ],
        'severity': ['high', 'critical'],
        'bounties': (1000, 5000),
        'cwe': 'CWE-611'
    },
    'Information Disclosure': {
        'titles': [
            'Sensitive data exposure in API response',
            'Debug mode enabled in production exposes stack traces',
            'Git directory accessible reveals source code',
            'GraphQL introspection enabled exposes schema'
        ],
        'severity': ['low', 'medium', 'high'],
        'bounties': (200, 1500),
        'cwe': 'CWE-200'
    },
    'Path Traversal': {
        'titles': [
            'Directory traversal in file download allows reading /etc/passwd',
            'Path traversal via zip file extraction',
            'Local file inclusion through template parameter',
            'Unrestricted file upload with path traversal'
        ],
        'severity': ['medium', 'high'],
        'bounties': (500, 3000),
        'cwe': 'CWE-22'
    }
}

COMPANIES = [
    {'name': 'Tesla', 'domain': 'tesla.com', 'program': 'tesla'},
    {'name': 'Apple', 'domain': 'apple.com', 'program': 'apple'},
    {'name': 'GitHub', 'domain': 'github.com', 'program': 'github'},
    {'name': 'Slack', 'domain': 'slack.com', 'program': 'slack'},
    {'name': 'Mozilla', 'domain': 'mozilla.org', 'program': 'mozilla'},
    {'name': 'Shopify', 'domain': 'shopify.com', 'program': 'shopify'},
    {'name': 'Gitlab', 'domain': 'gitlab.com', 'program': 'gitlab'},
    {'name': 'Coinbase', 'domain': 'coinbase.com', 'program': 'coinbase'},
    {'name': 'Twitter', 'domain': 'twitter.com', 'program': 'twitter'},
    {'name': 'Uber', 'domain': 'uber.com', 'program': 'uber'}
]

TECH_STACKS = [
    ['React', 'Node.js', 'PostgreSQL', 'Redis'],
    ['Vue.js', 'Django', 'MySQL', 'MongoDB'],
    ['Angular', 'Java', 'Oracle', 'Elasticsearch'],
    ['React Native', 'Python', 'PostgreSQL', 'AWS'],
    ['Flutter', 'Go', 'Cassandra', 'Kubernetes'],
    ['Next.js', 'Express', 'Redis', 'Docker'],
]

def generate_mock_report(report_id: int) -> VulnerabilityReport:
    """Generate a single realistic mock vulnerability report"""
    
    # Select random vulnerability type
    vuln_type = random.choice(list(VULNERABILITIES.keys()))
    vuln_data = VULNERABILITIES[vuln_type]
    
    # Select random company
    company = random.choice(COMPANIES)
    
    # Select severity and bounty
    severity = random.choice(vuln_data['severity'])
    bounty_min, bounty_max = vuln_data['bounties']
    bounty = random.randint(bounty_min, bounty_max)
    
    # Adjust bounty based on severity
    if severity == 'critical':
        bounty = int(bounty * 1.5)
    elif severity == 'low':
        bounty = int(bounty * 0.5)
    
    # Generate dates
    days_ago = random.randint(1, 365)
    disclosed_date = datetime.now() - timedelta(days=days_ago)
    reported_date = disclosed_date - timedelta(days=random.randint(30, 180))
    
    # Select title
    title = random.choice(vuln_data['titles'])
    
    # Select tech stack
    tech_stack = random.choice(TECH_STACKS)
    
    # CVSS score based on severity
    cvss_scores = {
        'critical': (9.0, 10.0),
        'high': (7.0, 8.9),
        'medium': (4.0, 6.9),
        'low': (0.1, 3.9)
    }
    cvss_min, cvss_max = cvss_scores[severity]
    cvss_score = round(random.uniform(cvss_min, cvss_max), 1)
    
    # Create report
    report = VulnerabilityReport(
        report_id=f"h1_{report_id}",
        platform='hackerone',
        target_domain=company['domain'],
        target_company=company['name'],
        target_program=company['program'],
        vulnerability_type=vuln_type,
        severity=severity,
        cvss_score=cvss_score,
        technology_stack=tech_stack,
        endpoint=f"/api/v{random.randint(1,3)}/{random.choice(['users', 'data', 'files', 'auth', 'admin'])}",
        http_method=random.choice(['GET', 'POST', 'PUT', 'DELETE']),
        vulnerability_location=random.choice(['API', 'Web Application', 'Mobile App', 'GraphQL']),
        description=title,
        steps_to_reproduce=[],
        impact=f"{severity.capitalize()} security impact - {vuln_type}",
        remediation='Apply security patch and validate input',
        reported_date=reported_date,
        disclosed_date=disclosed_date,
        bounty_amount=bounty,
        researcher_reputation=random.randint(50, 5000),
        authentication_required=random.choice([True, False]),
        privileges_required=random.choice(['none', 'user', 'admin']),
        user_interaction=random.choice([True, False]),
        complexity=random.choice(['low', 'medium', 'high']),
        tags=[],
        owasp_category='A03:2021 - Injection',
        cwe_id=vuln_data['cwe'],
        raw_data={}
    )
    
    return report

def generate_mock_reports(count: int = 50) -> list:
    """Generate multiple mock reports"""
    
    console.print(f"\n[bold cyan]🔧 Generating {count} realistic mock vulnerability reports...[/bold cyan]\n")
    
    reports = []
    
    for i in range(count):
        report = generate_mock_report(i + 1)
        reports.append(report)
        
        # Show progress
        if (i + 1) % 10 == 0:
            console.print(f"  Generated {i + 1}/{count} reports...")
    
    console.print(f"\n[bold green]✅ Successfully generated {len(reports)} mock reports![/bold green]\n")
    
    return reports

def display_report_summary(reports: list):
    """Display a summary of generated reports"""
    
    # Count by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for report in reports:
        severity_counts[report.severity] = severity_counts.get(report.severity, 0) + 1
    
    # Count by vulnerability type
    vuln_counts = {}
    for report in reports:
        vuln_counts[report.vulnerability_type] = vuln_counts.get(report.vulnerability_type, 0) + 1
    
    # Count by company
    company_counts = {}
    for report in reports:
        company_counts[report.target_company] = company_counts.get(report.target_company, 0) + 1
    
    # Display severity distribution
    console.print("[bold]📊 Severity Distribution:[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="cyan")
    table.add_column("Count", justify="right", style="green")
    table.add_column("Percentage", justify="right", style="yellow")
    
    total = len(reports)
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        percentage = (count / total * 100) if total > 0 else 0
        table.add_row(severity.capitalize(), str(count), f"{percentage:.1f}%")
    
    console.print(table)
    console.print()
    
    # Display top vulnerability types
    console.print("[bold]🎯 Top Vulnerability Types:[/bold]")
    top_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for vuln, count in top_vulns:
        console.print(f"  • {vuln}: {count}")
    console.print()
    
    # Display top companies
    console.print("[bold]🏢 Top Companies:[/bold]")
    top_companies = sorted(company_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for company, count in top_companies:
        console.print(f"  • {company}: {count}")
    console.print()
    
    # Display sample reports
    console.print("[bold]📋 Sample Reports:[/bold]")
    for i, report in enumerate(reports[:5], 1):
        severity_color = {
            'critical': 'red',
            'high': 'yellow',
            'medium': 'blue',
            'low': 'green'
        }.get(report.severity, 'white')
        
        console.print(f"  {i}. [{severity_color}][{report.severity.upper()}][/{severity_color}] "
                     f"{report.vulnerability_type} in {report.target_company} - ${report.bounty_amount}")
    
    console.print()

def test_with_visual_collector(reports: list):
    """Test the visual collector with mock data"""
    
    console.print("[bold cyan]🚀 Testing Visual Collector with Mock Data...[/bold cyan]\n")
    
    # Import the visual collector
    try:
        from scripts.collect_data_visual import VisualCollector
        
        collector = VisualCollector()
        
        # Simulate streaming reports
        console.print("Simulating live data collection...\n")
        
        for report in reports[:10]:  # Test with first 10
            # Add to collector
            report.source = 'HackerOne (Mock)'
            report.time = datetime.now().strftime('%H:%M:%S')
            
            collector.collected_reports.append(report.__dict__)
            collector.stats['total'] += 1
            collector.stats['hackerone'] += 1
            
            if report.severity in collector.stats:
                collector.stats[report.severity] += 1
            
            time.sleep(0.2)  # Simulate delay
        
        console.print(f"[bold green]✅ Visual collector test complete![/bold green]")
        console.print(f"   Processed {len(reports[:10])} mock reports\n")
        
    except ImportError as e:
        console.print(f"[yellow]⚠️  Could not import visual collector: {e}[/yellow]")
        console.print("   This is okay - the mock data is ready to use!\n")

def main():
    """Main entry point"""
    
    console.print()
    console.print(Panel.fit(
        "[bold white]🤖 BugPredict AI[/bold white]\n"
        "[cyan]Mock Data Generator[/cyan]\n\n"
        "Generates realistic vulnerability reports for testing",
        border_style="blue"
    ))
    console.print()
    
    # Generate reports
    reports = generate_mock_reports(count=50)
    
    # Display summary
    display_report_summary(reports)
    
    # Test visual collector
    test_with_visual_collector(reports)
    
    # Save to file
    import json
    from pathlib import Path
    
    output_dir = Path('data/raw')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"mock_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    # Convert reports to dict for JSON serialization
    reports_dict = []
    for report in reports:
        report_dict = {
            'report_id': report.report_id,
            'platform': report.platform,
            'target_domain': report.target_domain,
            'target_company': report.target_company,
            'target_program': report.target_program,
            'vulnerability_type': report.vulnerability_type,
            'severity': report.severity,
            'cvss_score': report.cvss_score,
            'technology_stack': report.technology_stack,
            'endpoint': report.endpoint,
            'http_method': report.http_method,
            'vulnerability_location': report.vulnerability_location,
            'description': report.description,
            'bounty_amount': report.bounty_amount,
            'researcher_reputation': report.researcher_reputation,
            'authentication_required': report.authentication_required,
            'privileges_required': report.privileges_required,
            'user_interaction': report.user_interaction,
            'complexity': report.complexity,
            'owasp_category': report.owasp_category,
            'cwe_id': report.cwe_id,
            'reported_date': report.reported_date.isoformat() if report.reported_date else None,
            'disclosed_date': report.disclosed_date.isoformat() if report.disclosed_date else None
        }
        reports_dict.append(report_dict)
    
    with open(output_file, 'w') as f:
        json.dump(reports_dict, f, indent=2)
    
    console.print(f"[bold cyan]💾 Saved mock data to:[/bold cyan] {output_file}\n")
    console.print("[bold green]✨ Mock data generation complete![/bold green]")
    console.print("\nYou can now use this data for:")
    console.print("  • Training ML models")
    console.print("  • Testing the analysis pipeline")
    console.print("  • Demonstrating the visual UI")
    console.print("  • Development and debugging\n")

if __name__ == "__main__":
    main()
