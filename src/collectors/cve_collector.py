"""CVE/NVD data collector - Production Implementation"""

import requests
import time
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json

from .data_sources import DataCollector, VulnerabilityReport


class CVECollector(DataCollector):
    """
    Collects CVE data from NIST National Vulnerability Database (NVD)
    
    Uses NVD's REST API v2.0
    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    
    Note: Requires API key for higher rate limits
    Without key: 5 requests per 30 seconds
    With key: 50 requests per 30 seconds
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__()
        self.api_key = api_key
        self.session = requests.Session()
        
        # Set headers
        self.session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'BugPredict-AI/1.0'
        })
        
        if api_key:
            self.session.headers.update({
                'apiKey': api_key
            })
        
        # Rate limiting
        self.requests_made = 0
        self.rate_limit = 50 if api_key else 5
        self.rate_window = 30  # seconds
        self.last_request_time = None
    
    def collect(self, 
                start_date: datetime,
                end_date: datetime,
                keywords: Optional[List[str]] = None,
                limit: int = 5000,
                use_cache: bool = True) -> List[VulnerabilityReport]:
        """
        Collect CVEs within date range
        
        Args:
            start_date: Start date for CVE search
            end_date: End date for CVE search
            keywords: Optional keywords to filter CVEs (e.g., ['web', 'application'])
            limit: Maximum number of CVEs to collect
            use_cache: Whether to use cached data if available
            
        Returns:
            List of VulnerabilityReport objects
        """
        
        # Try to load from cache
        cache_key = f"cve_{start_date.date()}_{end_date.date()}.pkl"
        if use_cache:
            cached = self.load_cache(cache_key)
            if cached and len(cached) >= limit:
                return cached[:limit]
        
        print(f"Collecting CVEs from {start_date.date()} to {end_date.date()}...")
        
        reports = []
        start_index = 0
        results_per_page = 2000  # Max allowed by NVD API
        
        while len(reports) < limit:
            try:
                # Build query parameters
                params = {
                    'pubStartDate': self._format_date_for_api(start_date),
                    'pubEndDate': self._format_date_for_api(end_date),
                    'resultsPerPage': min(results_per_page, limit - len(reports)),
                    'startIndex': start_index
                }
                
                # Add keyword filtering if provided
                if keywords:
                    # NVD API uses keywordSearch parameter
                    params['keywordSearch'] = ' '.join(keywords)
                
                # Make request with rate limiting
                self._wait_for_rate_limit()
                
                response = self.session.get(
                    self.BASE_URL,
                    params=params,
                    timeout=60
                )
                
                response.raise_for_status()
                data = response.json()
                
                # Extract vulnerabilities
                vulnerabilities = data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    print(f"No more CVEs found (fetched {len(reports)} total)")
                    break
                
                # Process each CVE
                for vuln in vulnerabilities:
                    cve_data = vuln.get('cve', {})
                    report = self._normalize_cve(cve_data)
                    
                    if report:
                        reports.append(report)
                    
                    if len(reports) >= limit:
                        break
                
                print(f"Collected {len(reports)}/{limit} CVEs...")
                
                # Check if there are more results
                total_results = data.get('totalResults', 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                
                start_index += len(vulnerabilities)
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching CVEs: {e}")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                break
        
        # Cache the results
        if reports:
            self.save_cache(reports, cache_key)
        
        print(f"Collected {len(reports)} CVEs total")
        
        return reports[:limit]
    
    def collect_by_cve_ids(self, cve_ids: List[str]) -> List[VulnerabilityReport]:
        """
        Collect specific CVEs by their IDs
        
        Args:
            cve_ids: List of CVE IDs (e.g., ['CVE-2023-12345', 'CVE-2024-67890'])
            
        Returns:
            List of VulnerabilityReport objects
        """
        
        print(f"Collecting {len(cve_ids)} CVEs by ID...")
        
        reports = []
        
        for cve_id in cve_ids:
            try:
                self._wait_for_rate_limit()
                
                response = self.session.get(
                    self.BASE_URL,
                    params={'cveId': cve_id},
                    timeout=30
                )
                
                response.raise_for_status()
                data = response.json()
                
                vulnerabilities = data.get('vulnerabilities', [])
                
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get('cve', {})
                    report = self._normalize_cve(cve_data)
                    
                    if report:
                        reports.append(report)
                
                print(f"Collected {len(reports)}/{len(cve_ids)} CVEs...")
                
            except Exception as e:
                print(f"Error fetching {cve_id}: {e}")
                continue
        
        return reports
    
    def _normalize_cve(self, cve_data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize CVE data to standard VulnerabilityReport format"""
        
        try:
            # Extract CVE ID
            cve_id = cve_data.get('id', '')
            
            # Extract description
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            if not description and descriptions:
                description = descriptions[0].get('value', '')
            
            # Extract vulnerability type from description and CWE
            vuln_type = self._extract_vuln_type_from_cve(cve_data, description)
            
            # Extract CVSS metrics
            cvss_data = self._extract_cvss_data(cve_data)
            
            # Extract vendor and product information
            vendor, product, tech_stack = self._extract_vendor_product(cve_data)
            
            # Extract CWE information
            cwe_id = self._extract_cwe_id(cve_data)
            
            # Extract dates
            published_date = self._parse_nvd_date(cve_data.get('published'))
            modified_date = self._parse_nvd_date(cve_data.get('lastModified'))
            
            # Extract references
            references = cve_data.get('references', [])
            
            # Determine if web-related
            is_web_related = self._is_web_related(description, tech_stack)
            
            if not is_web_related and tech_stack:
                # Skip non-web vulnerabilities unless they're relevant
                return None
            
            # Create report
            report = VulnerabilityReport(
                report_id=cve_id,
                platform='nvd',
                target_domain=vendor,
                target_company=vendor,
                target_program=product,
                vulnerability_type=vuln_type,
                severity=cvss_data['severity'],
                cvss_score=cvss_data['score'],
                technology_stack=tech_stack,
                endpoint='',
                http_method='',
                vulnerability_location=self._determine_location(description, tech_stack),
                description=description,
                steps_to_reproduce=[],
                impact=description[:500],
                remediation='',
                reported_date=published_date,
                disclosed_date=published_date,
                bounty_amount=0.0,
                researcher_reputation=0,
                authentication_required=cvss_data['privileges_required'] != 'NONE',
                privileges_required=cvss_data['privileges_required'].lower(),
                user_interaction=cvss_data['user_interaction'],
                complexity=cvss_data['attack_complexity'].lower(),
                tags=self._extract_tags(cve_data),
                owasp_category=self._map_to_owasp(vuln_type),
                cwe_id=cwe_id,
                raw_data=cve_data
            )
            
            return report
            
        except Exception as e:
            print(f"Error normalizing CVE: {e}")
            return None
    
    def _extract_vuln_type_from_cve(self, cve_data: Dict[str, Any], description: str) -> str:
        """Extract vulnerability type from CVE data"""
        
        # First check CWE
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            for weakness_desc in weakness.get('description', []):
                cwe_value = weakness_desc.get('value', '')
                vuln_type = self._map_cwe_to_vuln_type(cwe_value)
                if vuln_type != 'Other':
                    return vuln_type
        
        # Then check description
        return self.extract_vulnerability_type(description)
    
    def _map_cwe_to_vuln_type(self, cwe: str) -> str:
        """Map CWE ID to vulnerability type"""
        
        cwe_mapping = {
            'CWE-79': 'XSS',
            'CWE-89': 'SQL Injection',
            'CWE-352': 'CSRF',
            'CWE-918': 'SSRF',
            'CWE-94': 'Remote Code Execution',
            'CWE-78': 'Command Injection',
            'CWE-611': 'XXE',
            'CWE-22': 'Path Traversal',
            'CWE-434': 'File Upload',
            'CWE-502': 'Deserialization',
            'CWE-287': 'Authentication Bypass',
            'CWE-284': 'IDOR',
            'CWE-200': 'Information Disclosure',
            'CWE-601': 'Open Redirect'
        }
        
        for cwe_id, vuln_type in cwe_mapping.items():
            if cwe_id in cwe:
                return vuln_type
        
        return 'Other'
    
    def _extract_cvss_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS metrics from CVE data"""
        
        default_cvss = {
            'score': 5.0,
            'severity': 'medium',
            'attack_vector': 'NETWORK',
            'attack_complexity': 'LOW',
            'privileges_required': 'NONE',
            'user_interaction': False,
            'scope': 'UNCHANGED',
            'confidentiality': 'NONE',
            'integrity': 'NONE',
            'availability': 'NONE'
        }
        
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS v3.1 first
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            cvss = cvss_v31[0].get('cvssData', {})
            return {
                'score': cvss.get('baseScore', 5.0),
                'severity': cvss.get('baseSeverity', 'MEDIUM').lower(),
                'attack_vector': cvss.get('attackVector', 'NETWORK'),
                'attack_complexity': cvss.get('attackComplexity', 'LOW'),
                'privileges_required': cvss.get('privilegesRequired', 'NONE'),
                'user_interaction': cvss.get('userInteraction', 'NONE') == 'REQUIRED',
                'scope': cvss.get('scope', 'UNCHANGED'),
                'confidentiality': cvss.get('confidentialityImpact', 'NONE'),
                'integrity': cvss.get('integrityImpact', 'NONE'),
                'availability': cvss.get('availabilityImpact', 'NONE')
            }
        
        # Try CVSS v3.0
        cvss_v30 = metrics.get('cvssMetricV30', [])
        if cvss_v30:
            cvss = cvss_v30[0].get('cvssData', {})
            return {
                'score': cvss.get('baseScore', 5.0),
                'severity': cvss.get('baseSeverity', 'MEDIUM').lower(),
                'attack_vector': cvss.get('attackVector', 'NETWORK'),
                'attack_complexity': cvss.get('attackComplexity', 'LOW'),
                'privileges_required': cvss.get('privilegesRequired', 'NONE'),
                'user_interaction': cvss.get('userInteraction', 'NONE') == 'REQUIRED',
                'scope': cvss.get('scope', 'UNCHANGED'),
                'confidentiality': cvss.get('confidentialityImpact', 'NONE'),
                'integrity': cvss.get('integrityImpact', 'NONE'),
                'availability': cvss.get('availabilityImpact', 'NONE')
            }
        
        # Fall back to CVSS v2
        cvss_v2 = metrics.get('cvssMetricV2', [])
        if cvss_v2:
            cvss = cvss_v2[0].get('cvssData', {})
            score = cvss.get('baseScore', 5.0)
            
            # Convert v2 score to severity
            if score >= 7.0:
                severity = 'high'
            elif score >= 4.0:
                severity = 'medium'
            else:
                severity = 'low'
            
            return {
                'score': score,
                'severity': severity,
                'attack_vector': cvss.get('accessVector', 'NETWORK'),
                'attack_complexity': cvss.get('accessComplexity', 'LOW'),
                'privileges_required': 'NONE' if cvss.get('authentication') == 'NONE' else 'LOW',
                'user_interaction': False,
                'scope': 'UNCHANGED',
                'confidentiality': cvss.get('confidentialityImpact', 'NONE'),
                'integrity': cvss.get('integrityImpact', 'NONE'),
                'availability': cvss.get('availabilityImpact', 'NONE')
            }
        
        return default_cvss
    
    def _extract_vendor_product(self, cve_data: Dict[str, Any]) -> tuple:
        """Extract vendor, product, and technology stack"""
        
        vendor = 'Unknown'
        product = 'Unknown'
        tech_stack = []
        
        configurations = cve_data.get('configurations', [])
        
        for config in configurations:
            nodes = config.get('nodes', [])
            
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                
                for cpe_match in cpe_matches:
                    cpe_uri = cpe_match.get('criteria', '')
                    
                    # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
                    parts = cpe_uri.split(':')
                    
                    if len(parts) >= 5:
                        if vendor == 'Unknown':
                            vendor = parts[3]
                        if product == 'Unknown':
                            product = parts[4]
                        
                        # Add to tech stack
                        tech_name = f"{parts[3]} {parts[4]}"
                        if tech_name not in tech_stack:
                            tech_stack.append(tech_name)
        
        # Also extract from description
        description = ''
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # Add technologies found in description
        tech_from_desc = self.extract_technologies(description)
        tech_stack.extend(tech_from_desc)
        
        # Remove duplicates
        tech_stack = list(set(tech_stack))
        
        return vendor, product, tech_stack
    
    def _extract_cwe_id(self, cve_data: Dict[str, Any]) -> int:
        """Extract CWE ID from CVE data"""
        
        weaknesses = cve_data.get('weaknesses', [])
        
        for weakness in weaknesses:
            for weakness_desc in weakness.get('description', []):
                cwe_value = weakness_desc.get('value', '')
                
                # Extract number from CWE-XXX
                import re
                match = re.search(r'CWE-(\d+)', cwe_value)
                if match:
                    return int(match.group(1))
        
        return 0
    
    def _extract_tags(self, cve_data: Dict[str, Any]) -> List[str]:
        """Extract relevant tags from CVE data"""
        
        tags = []
        
        # Add CWE as tag
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            for weakness_desc in weakness.get('description', []):
                cwe_value = weakness_desc.get('value', '')
                if cwe_value:
                    tags.append(cwe_value)
        
        # Add severity as tag
        metrics = cve_data.get('metrics', {})
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            severity = cvss_v31[0].get('cvssData', {}).get('baseSeverity', '')
            if severity:
                tags.append(severity.lower())
        
        return tags
    
    def _is_web_related(self, description: str, tech_stack: List[str]) -> bool:
        """Determine if CVE is web/application related"""
        
        web_keywords = [
            'web', 'http', 'https', 'browser', 'application',
            'server', 'api', 'rest', 'graphql', 'website',
            'cookie', 'session', 'authentication', 'xss',
            'sql injection', 'csrf', 'ssrf', 'injection'
        ]
        
        description_lower = description.lower()
        
        # Check description
        if any(keyword in description_lower for keyword in web_keywords):
            return True
        
        # Check tech stack
        web_tech = ['apache', 'nginx', 'tomcat', 'iis', 'node', 'django', 
                   'flask', 'rails', 'php', 'java', 'javascript']
        
        for tech in tech_stack:
            if any(web in tech.lower() for web in web_tech):
                return True
        
        return False
    
    def _determine_location(self, description: str, tech_stack: List[str]) -> str:
        """Determine vulnerability location"""
        
        text_lower = description.lower()
        
        if any(word in text_lower for word in ['api', 'rest', 'graphql', 'endpoint']):
            return 'api'
        elif any(word in text_lower for word in ['mobile', 'android', 'ios', 'app']):
            return 'mobile'
        elif any(word in text_lower for word in ['web', 'browser', 'http', 'website']):
            return 'web'
        else:
            return 'other'
    
    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map vulnerability to OWASP Top 10 category"""
        
        owasp_mapping = {
            'XSS': 'A03:2021-Injection',
            'SQL Injection': 'A03:2021-Injection',
            'IDOR': 'A01:2021-Broken Access Control',
            'SSRF': 'A10:2021-Server-Side Request Forgery',
            'Authentication Bypass': 'A07:2021-Identification and Authentication Failures',
            'CSRF': 'A01:2021-Broken Access Control',
            'Information Disclosure': 'A01:2021-Broken Access Control',
            'Remote Code Execution': 'A03:2021-Injection',
            'Business Logic': 'A04:2021-Insecure Design',
            'XXE': 'A03:2021-Injection',
            'Command Injection': 'A03:2021-Injection',
            'Deserialization': 'A08:2021-Software and Data Integrity Failures',
            'Path Traversal': 'A01:2021-Broken Access Control',
            'File Upload': 'A01:2021-Broken Access Control'
        }
        
        return owasp_mapping.get(vuln_type, 'Other')
    
    def _format_date_for_api(self, date: datetime) -> str:
        """Format date for NVD API (ISO 8601)"""
        return date.strftime('%Y-%m-%dT%H:%M:%S.000')
    
    def _parse_nvd_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse NVD date string to datetime"""
        
        if not date_str:
            return None
        
        try:
            # NVD uses ISO 8601 format
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None
    
    def _wait_for_rate_limit(self):
        """Implement rate limiting to respect NVD API limits"""
        
        if self.last_request_time is None:
            self.last_request_time = time.time()
            self.requests_made = 1
            return
        
        current_time = time.time()
        time_elapsed = current_time - self.last_request_time
        
        # If we've made rate_limit requests in less than rate_window seconds, wait
        if self.requests_made >= self.rate_limit and time_elapsed < self.rate_window:
            wait_time = self.rate_window - time_elapsed + 1
            print(f"Rate limit reached, waiting {wait_time:.1f} seconds...")
            time.sleep(wait_time)
            self.requests_made = 0
            self.last_request_time = time.time()
        elif time_elapsed >= self.rate_window:
            # Reset counter if window has passed
            self.requests_made = 0
            self.last_request_time = current_time
        
        self.requests_made += 1
    
    def normalize(self, raw_data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize raw CVE data to standard format"""
        
        return self._normalize_cve(raw_data)
