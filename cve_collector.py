# src/collectors/cve_collector.py

import nvdlib

class CVECollector(DataCollector):
    """
    Collects CVE data from NVD (National Vulnerability Database)
    """
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__()
        self.api_key = api_key
    
    def collect(self, 
                start_date: datetime,
                end_date: datetime,
                keywords: List[str] = None) -> List[VulnerabilityReport]:
        """
        Collect CVEs within date range
        """
        reports = []
        
        try:
            cves = nvdlib.searchCVE(
                pubStartDate=start_date,
                pubEndDate=end_date,
                keyword=keywords
            )
            
            for cve in cves:
                normalized = self.normalize(cve)
                if normalized:
                    reports.append(normalized)
        
        except Exception as e:
            print(f"Error collecting CVEs: {e}")
        
        return reports
    
    def normalize(self, cve) -> Optional[VulnerabilityReport]:
        """Normalize CVE to standard format"""
        try:
            return VulnerabilityReport(
                report_id=cve.id,
                platform='nvd',
                target_domain=self._extract_vendor(cve),
                target_company=self._extract_vendor(cve),
                target_program='',
                vulnerability_type=self._extract_vuln_type(cve),
                severity=self._extract_severity(cve),
                cvss_score=self._extract_cvss_score(cve),
                technology_stack=self._extract_tech_stack(cve),
                endpoint='',
                http_method='',
                vulnerability_location=self._extract_location(cve),
                description=cve.cve.description.description_data[0].value,
                steps_to_reproduce=[],
                impact=cve.cve.description.description_data[0].value,
                remediation='',
                reported_date=datetime.fromisoformat(cve.publishedDate),
                disclosed_date=datetime.fromisoformat(cve.publishedDate),
                bounty_amount=0.0,
                researcher_reputation=0,
                authentication_required=self._requires_auth(cve),
                privileges_required=self._extract_privileges(cve),
                user_interaction=self._requires_interaction(cve),
                complexity=self._extract_complexity(cve),
                tags=self._extract_tags(cve),
                owasp_category='',
                cwe_id=self._extract_cwe(cve)
            )
        except Exception as e:
            print(f"Error normalizing CVE: {e}")
            return None
    
    def _extract_vendor(self, cve) -> str:
        """Extract vendor/product information"""
        try:
            if cve.cve.affects.vendor.vendor_data:
                return cve.cve.affects.vendor.vendor_data[0].vendor_name
        except:
            pass
        return ''
    
    def _extract_vuln_type(self, cve) -> str:
        """Extract vulnerability type from CVE"""
        description = cve.cve.description.description_data[0].value.lower()
        
        # Keyword matching
        type_keywords = {
            'XSS': ['cross-site scripting', 'xss'],
            'SQLI': ['sql injection', 'sqli'],
            'RCE': ['remote code execution', 'code execution'],
            'IDOR': ['insecure direct object'],
            'SSRF': ['server-side request forgery', 'ssrf'],
            'XXE': ['xml external entity', 'xxe'],
            'CSRF': ['cross-site request forgery', 'csrf']
        }
        
        for vuln_type, keywords in type_keywords.items():
            if any(keyword in description for keyword in keywords):
                return vuln_type
        
        return 'OTHER'
    
    def _extract_severity(self, cve) -> str:
        """Extract severity rating"""
        try:
            cvss_score = self._extract_cvss_score(cve)
            if cvss_score >= 9.0:
                return 'critical'
            elif cvss_score >= 7.0:
                return 'high'
            elif cvss_score >= 4.0:
                return 'medium'
            else:
                return 'low'
        except:
            return 'none'
    
    def _extract_cvss_score(self, cve) -> float:
        """Extract CVSS score"""
        try:
            if cve.impact.baseMetricV3:
                return cve.impact.baseMetricV3.cvssV3.baseScore
            elif cve.impact.baseMetricV2:
                return cve.impact.baseMetricV2.cvssV2.baseScore
        except:
            pass
        return 0.0
    
    def _extract_tech_stack(self, cve) -> List[str]:
        """Extract technology stack"""
        tech = []
        try:
            if cve.cve.affects.vendor.vendor_data:
                for vendor in cve.cve.affects.vendor.vendor_data:
                    for product in vendor.product.product_data:
                        tech.append(product.product_name)
        except:
            pass
        return tech
    
    def _extract_location(self, cve) -> str:
        """Determine vulnerability location"""
        description = cve.cve.description.description_data[0].value.lower()
        
        if any(word in description for word in ['web', 'browser', 'http']):
            return 'web'
        elif any(word in description for word in ['api', 'rest', 'graphql']):
            return 'api'
        elif any(word in description for word in ['mobile', 'android', 'ios']):
            return 'mobile'
        else:
            return 'other'
    
    def _requires_auth(self, cve) -> bool:
        """Check if authentication is required"""
        try:
            if cve.impact.baseMetricV3:
                return cve.impact.baseMetricV3.cvssV3.privilegesRequired != 'NONE'
        except:
            pass
        return False
    
    def _extract_privileges(self, cve) -> str:
        """Extract required privileges"""
        try:
            if cve.impact.baseMetricV3:
                pr = cve.impact.baseMetricV3.cvssV3.privilegesRequired
                return pr.lower()
        except:
            pass
        return 'none'
    
    def _requires_interaction(self, cve) -> bool:
        """Check if user interaction is required"""
        try:
            if cve.impact.baseMetricV3:
                return cve.impact.baseMetricV3.cvssV3.userInteraction != 'NONE'
        except:
            pass
        return False
    
    def _extract_complexity(self, cve) -> str:
        """Extract attack complexity"""
        try:
            if cve.impact.baseMetricV3:
                return cve.impact.baseMetricV3.cvssV3.attackComplexity.lower()
        except:
            pass
        return 'medium'
    
    def _extract_tags(self, cve) -> List[str]:
        """Extract tags/keywords"""
        tags = []
        try:
            if cve.cve.problemtype:
                for problem in cve.cve.problemtype.problemtype_data:
                    for desc in problem.description:
                        tags.append(desc.value)
        except:
            pass
        return tags
    
    def _extract_cwe(self, cve) -> int:
        """Extract CWE ID"""
        try:
            if cve.cve.problemtype:
                for problem in cve.cve.problemtype.problemtype_data:
                    for desc in problem.description:
                        if desc.value.startswith('CWE-'):
                            return int(desc.value.split('-')[1])
        except:
            pass
        return 0
