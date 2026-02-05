"""HackerOne data collector - Production Implementation"""

import requests
import time
import re
from typing import List, Optional, Dict, Any
from datetime import datetime
from bs4 import BeautifulSoup

from .data_sources import DataCollector, VulnerabilityReport


class HackerOneCollector(DataCollector):
    """
    Collects disclosed vulnerability reports from HackerOne
    
    Uses the public Hacktivity feed and HackerOne's public API
    """
    
    BASE_URL = "https://hackerone.com"
    API_URL = "https://api.hackerone.com/v1"
    
    def __init__(self, api_token: Optional[str] = None, username: Optional[str] = None):
        super().__init__()
        self.api_token = api_token
        self.username = username
        self.session = requests.Session()
        
        if api_token and username:
            # Use API authentication
            self.session.auth = (username, api_token)
            self.session.headers.update({
                'Accept': 'application/json'
            })
    
    def collect(self, limit: int = 1000, use_cache: bool = True) -> List[VulnerabilityReport]:
        """
        Collect disclosed reports from HackerOne
        
        Args:
            limit: Maximum number of reports to collect
            use_cache: Whether to use cached data if available
            
        Returns:
            List of VulnerabilityReport objects
        """
        
        # Try to load from cache
        if use_cache:
            cached = self.load_cache('hackerone_reports.pkl')
            if cached and len(cached) >= limit:
                return cached[:limit]
        
        print(f"Collecting up to {limit} reports from HackerOne...")
        
        reports = []
        
        if self.api_token:
            # Use authenticated API
            reports = self._collect_via_api(limit)
        else:
            # Use public Hacktivity feed
            reports = self._collect_via_hacktivity(limit)
        
        # Cache the results
        if reports:
            self.save_cache(reports, 'hackerone_reports.pkl')
        
        return reports
    
    def _collect_via_api(self, limit: int) -> List[VulnerabilityReport]:
        """Collect reports using HackerOne API"""
        
        reports = []
        page = 1
        per_page = 100
        
        while len(reports) < limit:
            try:
                # Get reports page
                response = self.session.get(
                    f"{self.API_URL}/hackers/reports",
                    params={
                        'page[size]': per_page,
                        'page[number]': page,
                        'filter[state][]': 'disclosed'
                    },
                    timeout=30
                )
                
                response.raise_for_status()
                data = response.json()
                
                if not data.get('data'):
                    break
                
                for report_data in data['data']:
                    report = self._normalize_api_report(report_data)
                    if report:
                        reports.append(report)
                    
                    if len(reports) >= limit:
                        break
                
                page += 1
                time.sleep(1)  # Rate limiting
                
                print(f"Collected {len(reports)}/{limit} reports...")
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching reports: {e}")
                break
        
        return reports
    
    def _collect_via_hacktivity(self, limit: int) -> List[VulnerabilityReport]:
        """Collect reports from public Hacktivity feed"""
        
        reports = []
        page = 1
        
        while len(reports) < limit:
            try:
                # Hacktivity JSON endpoint
                response = self.session.get(
                    f"{self.BASE_URL}/hacktivity.json",
                    params={
                        'queryString': '',
                        'page': page,
                        'filter': 'disclosed',
                        'orderBy': 'latest_disclosable_activity_at'
                    },
                    timeout=30
                )
                
                response.raise_for_status()
                data = response.json()
                
                if not data.get('reports'):
                    break
                
                for report_data in data['reports']:
                    report = self._normalize_hacktivity_report(report_data)
                    if report:
                        reports.append(report)
                    
                    if len(reports) >= limit:
                        break
                
                page += 1
                time.sleep(2)  # Be nice to their servers
                
                print(f"Collected {len(reports)}/{limit} reports...")
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching Hacktivity: {e}")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                break
        
        return reports
    
    def _normalize_api_report(self, data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize HackerOne API report to standard format"""
        
        try:
            attributes = data.get('attributes', {})
            relationships = data.get('relationships', {})
            
            # Extract basic info
            report_id = data.get('id', '')
            title = attributes.get('title', '')
            
            # Extract weakness
            weakness = relationships.get('weakness', {}).get('data', {})
            weakness_name = weakness.get('attributes', {}).get('name', '') if weakness else ''
            
            # Extract vulnerability type
            vuln_type = self.extract_vulnerability_type(title, weakness_name)
            
            # Extract severity
            severity_rating = attributes.get('severity_rating', 'none')
            cvss_score = self._extract_cvss_from_severity(severity_rating)
            
            # Extract team info
            team = relationships.get('team', {}).get('data', {})
            team_attrs = team.get('attributes', {}) if team else {}
            
            # Extract bounty
            bounty_amount = 0.0
            total_awarded = attributes.get('total_awarded_amount', 0)
            if total_awarded:
                bounty_amount = float(total_awarded)
            
            # Extract dates
            disclosed_at = attributes.get('disclosed_at')
            created_at = attributes.get('created_at')
            
            # Extract reporter info
            reporter = relationships.get('reporter', {}).get('data', {})
            reporter_attrs = reporter.get('attributes', {}) if reporter else {}
            reputation = reporter_attrs.get('reputation', 0)
            
            return VulnerabilityReport(
                report_id=report_id,
                platform='hackerone',
                target_domain=self._extract_domain_from_scope(attributes),
                target_company=team_attrs.get('name', ''),
                target_program=team_attrs.get('handle', ''),
                vulnerability_type=vuln_type,
                severity=severity_rating.lower(),
                cvss_score=cvss_score,
                technology_stack=self.extract_technologies(title),
                endpoint='',
                http_method='',
                vulnerability_location=self._determine_location(title),
                description=title,
                steps_to_reproduce=[],
                impact='',
                remediation='',
                reported_date=self._parse_date(created_at),
                disclosed_date=self._parse_date(disclosed_at),
                bounty_amount=bounty_amount,
                researcher_reputation=reputation,
                authentication_required=self._requires_auth(title),
                privileges_required=self._extract_privileges(title),
                user_interaction=self._requires_interaction(title),
                complexity=self._estimate_complexity(title),
                tags=[],
                owasp_category=self._map_to_owasp(vuln_type),
                cwe_id=self._extract_cwe(weakness_name),
                raw_data=data
            )
            
        except Exception as e:
            print(f"Error normalizing API report: {e}")
            return None
    
    def _normalize_hacktivity_report(self, data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize Hacktivity report to standard format"""
        
        try:
            # Extract basic info
            report_id = str(data.get('id', ''))
            title = data.get('title', '')
            
            # Extract weakness
            weakness = data.get('weakness', {})
            weakness_name = weakness.get('name', '') if weakness else ''
            
            # Extract vulnerability type
            vuln_type = self.extract_vulnerability_type(title, weakness_name)
            
            # Extract severity
            severity_rating = data.get('severity_rating', 'none')
            if not severity_rating:
                severity_rating = 'none'
            
            cvss_score = self._extract_cvss_from_severity(severity_rating)
            
            # Extract team info
            team = data.get('team', {})
            team_name = team.get('name', '') if team else ''
            team_handle = team.get('handle', '') if team else ''
            
            # Extract bounty
            bounty_amount = 0.0
            if data.get('total_awarded_amount'):
                bounty_amount = float(data['total_awarded_amount'])
            
            # Extract dates
            disclosed_at = data.get('disclosed_at')
            created_at = data.get('created_at')
            
            # Extract reporter info
            reporter = data.get('reporter', {})
            reputation = reporter.get('reputation', 0) if reporter else 0
            
            # Extract structured scope
            scope = data.get('structured_scope', {})
            asset_identifier = scope.get('asset_identifier', '') if scope else ''
            
            return VulnerabilityReport(
                report_id=report_id,
                platform='hackerone',
                target_domain=asset_identifier,
                target_company=team_name,
                target_program=team_handle,
                vulnerability_type=vuln_type,
                severity=severity_rating.lower(),
                cvss_score=cvss_score,
                technology_stack=self.extract_technologies(title),
                endpoint=self._extract_endpoint(title),
                http_method=self._extract_method(title),
                vulnerability_location=self._determine_location(title),
                description=title,
                steps_to_reproduce=[],
                impact='',
                remediation='',
                reported_date=self._parse_date(created_at),
                disclosed_date=self._parse_date(disclosed_at),
                bounty_amount=bounty_amount,
                researcher_reputation=reputation,
                authentication_required=self._requires_auth(title),
                privileges_required=self._extract_privileges(title),
                user_interaction=self._requires_interaction(title),
                complexity=self._estimate_complexity(title),
                tags=[],
                owasp_category=self._map_to_owasp(vuln_type),
                cwe_id=self._extract_cwe(weakness_name),
                raw_data=data
            )
            
        except Exception as e:
            print(f"Error normalizing Hacktivity report: {e}")
            return None
    
    def _extract_cvss_from_severity(self, severity: str) -> float:
        """Convert severity rating to approximate CVSS score"""
        severity_map = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'none': 0.0
        }
        return severity_map.get(severity.lower(), 0.0)
    
    def _extract_domain_from_scope(self, attributes: Dict[str, Any]) -> str:
        """Extract domain from structured scope"""
        # Try to get from attributes or relationships
        return ''
    
    def _extract_endpoint(self, text: str) -> str:
        """Extract API endpoint from text"""
        endpoint_pattern = r'(/api/[^\s]+|/v\d+/[^\s]+)'
        match = re.search(endpoint_pattern, text, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def _extract_method(self, text: str) -> str:
        """Extract HTTP method from text"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        for method in methods:
            if method in text.upper():
                return method
        return ''
    
    def _determine_location(self, text: str) -> str:
        """Determine vulnerability location"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['api', 'endpoint', 'rest']):
            return 'API'
        elif any(word in text_lower for word in ['graphql', 'query', 'mutation']):
            return 'GraphQL'
        elif any(word in text_lower for word in ['parameter', 'param', 'query string']):
            return 'URL Parameter'
        elif any(word in text_lower for word in ['header', 'cookie']):
            return 'HTTP Header'
        elif any(word in text_lower for word in ['form', 'input', 'field']):
            return 'Form Input'
        else:
            return 'Web Application'
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            return None
    
    def _requires_auth(self, text: str) -> bool:
        """Check if vulnerability requires authentication"""
        auth_keywords = ['authenticated', 'logged in', 'after login', 'auth required']
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in auth_keywords)
    
    def _extract_privileges(self, text: str) -> str:
        """Extract privilege level required"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['admin', 'administrator']):
            return 'admin'
        elif any(word in text_lower for word in ['user', 'authenticated']):
            return 'user'
        else:
            return 'none'
    
    def _requires_interaction(self, text: str) -> bool:
        """Check if user interaction is required"""
        interaction_keywords = ['click', 'visit', 'open', 'user interaction', 'victim']
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in interaction_keywords)
    
    def _estimate_complexity(self, text: str) -> str:
        """Estimate exploitation complexity"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['race condition', 'timing', 'complex']):
            return 'high'
        elif any(word in text_lower for word in ['simple', 'basic', 'trivial']):
            return 'low'
        else:
            return 'medium'
    
    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map vulnerability type to OWASP Top 10 category"""
        owasp_map = {
            'SQL Injection': 'A03:2021 – Injection',
            'XSS': 'A03:2021 – Injection',
            'CSRF': 'A01:2021 – Broken Access Control',
            'IDOR': 'A01:2021 – Broken Access Control',
            'Authentication Bypass': 'A07:2021 – Identification and Authentication Failures',
            'SSRF': 'A10:2021 – Server-Side Request Forgery',
            'XXE': 'A05:2021 – Security Misconfiguration',
            'File Upload': 'A04:2021 – Insecure Design',
            'RCE': 'A03:2021 – Injection',
            'LFI': 'A01:2021 – Broken Access Control',
            'Open Redirect': 'A01:2021 – Broken Access Control'
        }
        return owasp_map.get(vuln_type, 'Other')
    
    def _extract_cwe(self, weakness_name: str) -> str:
        """Extract CWE ID from weakness name"""
        if not weakness_name:
            return ''
        
        # Try to extract CWE-XXX pattern
        cwe_match = re.search(r'CWE-(\d+)', weakness_name, re.IGNORECASE)
        if cwe_match:
            return f"CWE-{cwe_match.group(1)}"
        
        # Map common weaknesses to CWE IDs
        cwe_map = {
            'SQL Injection': 'CWE-89',
            'Cross-site Scripting': 'CWE-79',
            'CSRF': 'CWE-352',
            'Path Traversal': 'CWE-22',
            'Command Injection': 'CWE-77',
            'XXE': 'CWE-611',
            'SSRF': 'CWE-918',
            'Insecure Direct Object Reference': 'CWE-639'
        }
        
        for weakness, cwe in cwe_map.items():
            if weakness.lower() in weakness_name.lower():
                return cwe
        
        return ''


# For backward compatibility with existing code
class HackerOneScraper(HackerOneCollector):
    """Alias for HackerOneCollector to maintain compatibility"""
    
    def fetch_reports(self, limit: int = 100) -> List[VulnerabilityReport]:
        """Fetch reports (alias for collect method)"""
        return self.collect(limit=limit, use_cache=True)
    
    def fetch_reports_stream(self, limit: int = 100):
        """Stream reports one by one for visual display"""
        reports = self.collect(limit=limit, use_cache=False)
        for report in reports:
            yield report
