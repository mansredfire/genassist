"""Bugcrowd data collector - Production Implementation"""

import requests
import time
import re
from typing import List, Optional, Dict, Any
from datetime import datetime
from bs4 import BeautifulSoup

from .data_sources import DataCollector, VulnerabilityReport


class BugcrowdCollector(DataCollector):
    """
    Collects disclosed vulnerability reports from Bugcrowd
    
    Note: Bugcrowd has limited public disclosure compared to HackerOne.
    This collector focuses on publicly available disclosures.
    """
    
    BASE_URL = "https://bugcrowd.com"
    
    def __init__(self, api_token: Optional[str] = None):
        super().__init__()
        self.api_token = api_token
        self.session = requests.Session()
        
        # Set headers to mimic browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        
        if api_token:
            self.session.headers.update({
                'Authorization': f'Token {api_token}'
            })
    
    def collect(self, limit: int = 1000, use_cache: bool = True) -> List[VulnerabilityReport]:
        """
        Collect disclosed reports from Bugcrowd
        
        Args:
            limit: Maximum number of reports to collect
            use_cache: Whether to use cached data if available
            
        Returns:
            List of VulnerabilityReport objects
        """
        
        # Try to load from cache
        if use_cache:
            cached = self.load_cache('bugcrowd_reports.pkl')
            if cached and len(cached) >= limit:
                return cached[:limit]
        
        print(f"Collecting up to {limit} reports from Bugcrowd...")
        
        reports = []
        
        # Bugcrowd has different data sources
        # 1. Hall of Fame pages (public researchers)
        # 2. Public program pages
        # 3. CVE disclosures
        
        # Collect from available public sources
        reports.extend(self._collect_from_public_programs(limit))
        
        # If we have API access, use it
        if self.api_token:
            reports.extend(self._collect_via_api(limit - len(reports)))
        
        # Remove duplicates
        seen_ids = set()
        unique_reports = []
        for report in reports:
            if report.report_id not in seen_ids:
                seen_ids.add(report.report_id)
                unique_reports.append(report)
        
        reports = unique_reports[:limit]
        
        # Cache the results
        if reports:
            self.save_cache(reports, 'bugcrowd_reports.pkl')
        
        print(f"Collected {len(reports)} unique reports from Bugcrowd")
        
        return reports
    
    def _collect_from_public_programs(self, limit: int) -> List[VulnerabilityReport]:
        """
        Collect from publicly accessible Bugcrowd program pages
        
        Note: This scrapes public disclosure pages where available
        """
        
        reports = []
        
        # Known public programs with disclosures
        public_programs = [
            'tesla',
            'apple', 
            'mozilla',
            'github',
            'gitlab',
            'slack',
            'nextcloud'
        ]
        
        for program in public_programs:
            if len(reports) >= limit:
                break
            
            try:
                program_reports = self._scrape_program_disclosures(program)
                reports.extend(program_reports)
                
                time.sleep(2)  # Be respectful
                
            except Exception as e:
                print(f"Error scraping {program}: {e}")
                continue
        
        return reports[:limit]
    
    def _scrape_program_disclosures(self, program_slug: str) -> List[VulnerabilityReport]:
        """Scrape disclosures from a specific program"""
        
        reports = []
        
        try:
            # Try to get program's public disclosure page
            url = f"{self.BASE_URL}/{program_slug}/hall-of-fame"
            
            response = self.session.get(url, timeout=30)
            
            if response.status_code != 200:
                return reports
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse disclosure information
            # Note: Bugcrowd's HTML structure may change
            # This is a best-effort scraping approach
            
            disclosure_elements = soup.find_all('div', class_='disclosure-card')
            
            for element in disclosure_elements:
                try:
                    report = self._parse_disclosure_element(element, program_slug)
                    if report:
                        reports.append(report)
                except Exception as e:
                    print(f"Error parsing disclosure: {e}")
                    continue
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching program disclosures: {e}")
        
        return reports
    
    def _parse_disclosure_element(self, element: Any, program: str) -> Optional[VulnerabilityReport]:
        """Parse a disclosure HTML element into a VulnerabilityReport"""
        
        try:
            # Extract title
            title_elem = element.find('h3') or element.find('h4')
            title = title_elem.text.strip() if title_elem else 'Unknown'
            
            # Extract severity
            severity_elem = element.find('span', class_='severity')
            severity = severity_elem.text.strip().lower() if severity_elem else 'medium'
            
            # Extract bounty amount
            bounty_elem = element.find('span', class_='bounty-amount')
            bounty_amount = 0.0
            if bounty_elem:
                bounty_text = bounty_elem.text.strip()
                # Extract number from text like "$5,000"
                bounty_match = re.search(r'[\d,]+', bounty_text)
                if bounty_match:
                    bounty_amount = float(bounty_match.group().replace(',', ''))
            
            # Extract researcher
            researcher_elem = element.find('a', class_='researcher')
            researcher = researcher_elem.text.strip() if researcher_elem else 'Unknown'
            
            # Extract date
            date_elem = element.find('time')
            disclosed_date = None
            if date_elem and date_elem.get('datetime'):
                disclosed_date = self._parse_date(date_elem['datetime'])
            
            # Determine vulnerability type
            vuln_type = self.extract_vulnerability_type(title)
            
            # Create report
            report = VulnerabilityReport(
                report_id=f"bugcrowd_{program}_{hash(title)}",
                platform='bugcrowd',
                target_domain=self._extract_domain(program),
                target_company=program.capitalize(),
                target_program=program,
                vulnerability_type=vuln_type,
                severity=severity,
                cvss_score=self.map_severity_to_score(severity),
                technology_stack=self.extract_technologies(title),
                endpoint='',
                http_method='',
                vulnerability_location=self._determine_location(title),
                description=title,
                steps_to_reproduce=[],
                impact='',
                remediation='',
                reported_date=disclosed_date,
                disclosed_date=disclosed_date,
                bounty_amount=bounty_amount,
                researcher_reputation=0,
                authentication_required=self._requires_auth(title),
                privileges_required=self._extract_privileges(title),
                user_interaction=self._requires_interaction(title),
                complexity=self._estimate_complexity(title),
                tags=[],
                owasp_category=self._map_to_owasp(vuln_type),
                cwe_id='',
                raw_data={'title': title, 'researcher': researcher}
            )
            
            return report
            
        except Exception as e:
            print(f"Error parsing disclosure element: {e}")
            return None
    
    def _collect_via_api(self, limit: int) -> List[VulnerabilityReport]:
        """
        Collect reports using Bugcrowd API
        
        Note: Bugcrowd's API is more restricted than HackerOne's
        This requires proper API credentials
        """
        
        if not self.api_token:
            return []
        
        reports = []
        
        try:
            # Bugcrowd API endpoint for submissions
            # Note: This is a placeholder - actual endpoint may differ
            url = f"{self.BASE_URL}/api/v2/submissions"
            
            response = self.session.get(
                url,
                params={
                    'state': 'disclosed',
                    'page[size]': 50
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                for submission in data.get('data', []):
                    report = self._normalize_api_submission(submission)
                    if report:
                        reports.append(report)
                    
                    if len(reports) >= limit:
                        break
            
        except requests.exceptions.RequestException as e:
            print(f"Error accessing Bugcrowd API: {e}")
        
        return reports
    
    def _normalize_api_submission(self, data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize Bugcrowd API submission to standard format"""
        
        try:
            attributes = data.get('attributes', {})
            
            # Extract basic info
            submission_id = data.get('id', '')
            title = attributes.get('title', '')
            description = attributes.get('description', '')
            
            # Extract severity
            severity = attributes.get('severity', 'medium')
            if isinstance(severity, dict):
                severity = severity.get('rating', 'medium')
            
            # Extract vulnerability type
            vuln_type = self.extract_vulnerability_type(title + ' ' + description)
            
            # Extract program info
            program = attributes.get('program', {})
            program_name = program.get('name', '') if isinstance(program, dict) else ''
            
            # Extract bounty
            bounty_amount = 0.0
            reward = attributes.get('monetary_rewards', [])
            if reward and isinstance(reward, list) and len(reward) > 0:
                bounty_amount = float(reward[0].get('amount', 0))
            
            # Extract dates
            created_at = attributes.get('created_at')
            disclosed_at = attributes.get('disclosed_at')
            
            return VulnerabilityReport(
                report_id=submission_id,
                platform='bugcrowd',
                target_domain='',
                target_company=program_name,
                target_program=program_name.lower().replace(' ', '-'),
                vulnerability_type=vuln_type,
                severity=severity.lower(),
                cvss_score=self.map_severity_to_score(severity),
                technology_stack=self.extract_technologies(title + ' ' + description),
                endpoint='',
                http_method='',
                vulnerability_location=self._determine_location(title),
                description=title,
                steps_to_reproduce=[],
                impact=description[:500] if description else '',
                remediation='',
                reported_date=self._parse_date(created_at),
                disclosed_date=self._parse_date(disclosed_at),
                bounty_amount=bounty_amount,
                researcher_reputation=0,
                authentication_required=self._requires_auth(title),
                privileges_required=self._extract_privileges(title),
                user_interaction=self._requires_interaction(title),
                complexity=self._estimate_complexity(title),
                tags=[],
                owasp_category=self._map_to_owasp(vuln_type),
                cwe_id='',
                raw_data=data
            )
            
        except Exception as e:
            print(f"Error normalizing Bugcrowd API submission: {e}")
            return None
    
    def _extract_domain(self, program: str) -> str:
        """Extract domain from program slug"""
        
        # Common program slug to domain mapping
        domain_mapping = {
            'tesla': 'tesla.com',
            'apple': 'apple.com',
            'mozilla': 'mozilla.org',
            'github': 'github.com',
            'gitlab': 'gitlab.com',
            'slack': 'slack.com',
            'nextcloud': 'nextcloud.com'
        }
        
        return domain_mapping.get(program, f"{program}.com")
    
    def _determine_location(self, text: str) -> str:
        """Determine vulnerability location"""
        
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['api', 'rest', 'graphql', 'endpoint']):
            return 'api'
        elif any(word in text_lower for word in ['mobile', 'android', 'ios', 'app']):
            return 'mobile'
        else:
            return 'web'
    
    def _requires_auth(self, text: str) -> bool:
        """Determine if authentication is required"""
        
        auth_keywords = ['authenticated', 'logged in', 'requires login', 'auth required',
                        'after login', 'authenticated user']
        text_lower = text.lower()
        
        return any(keyword in text_lower for keyword in auth_keywords)
    
    def _extract_privileges(self, text: str) -> str:
        """Extract required privilege level"""
        
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['admin', 'administrator', 'root']):
            return 'high'
        elif any(word in text_lower for word in ['user', 'authenticated', 'logged in']):
            return 'low'
        else:
            return 'none'
    
    def _requires_interaction(self, text: str) -> bool:
        """Determine if user interaction is required"""
        
        interaction_keywords = ['click', 'visit', 'open', 'user interaction',
                               'victim clicks', 'social engineering']
        text_lower = text.lower()
        
        return any(keyword in text_lower for keyword in interaction_keywords)
    
    def _estimate_complexity(self, text: str) -> str:
        """Estimate exploit complexity"""
        
        complex_keywords = ['race condition', 'timing', 'complex', 'multiple steps']
        simple_keywords = ['simple', 'straightforward', 'direct']
        
        text_lower = text.lower()
        
        if any(keyword in text_lower for keyword in complex_keywords):
            return 'high'
        elif any(keyword in text_lower for keyword in simple_keywords):
            return 'low'
        else:
            return 'medium'
    
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
            'Deserialization': 'A08:2021-Software and Data Integrity Failures'
        }
        
        return owasp_mapping.get(vuln_type, 'Other')
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime"""
        
        if not date_str:
            return None
        
        try:
            # Try ISO format
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            pass
        
        try:
            # Try common date formats
            for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%d %b %Y']:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
        except Exception:
            pass
        
        return None
    
    def normalize(self, raw_data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize raw Bugcrowd data to standard format"""
        
        # Determine data source and normalize accordingly
        if 'attributes' in raw_data:
            return self._normalize_api_submission(raw_data)
        else:
            # Handle scraped data
            return None


# For backward compatibility with existing code
class BugcrowdScraper(BugcrowdCollector):
    """Alias for BugcrowdCollector to maintain compatibility"""
    
    def fetch_reports(self, limit: int = 100) -> List[VulnerabilityReport]:
        """Fetch reports (alias for collect method)"""
        return self.collect(limit=limit, use_cache=True)
    
    def fetch_reports_stream(self, limit: int = 100):
        """Stream reports one by one for visual display"""
        reports = self.collect(limit=limit, use_cache=False)
        for report in reports:
            yield report
