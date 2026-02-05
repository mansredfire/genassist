"""Base data source definitions - Production Ready"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class VulnerabilityType(Enum):
    """Enumeration of vulnerability types"""
    XSS = "XSS"
    SQLI = "SQL Injection"
    IDOR = "IDOR"
    SSRF = "SSRF"
    RCE = "Remote Code Execution"
    AUTH_BYPASS = "Authentication Bypass"
    CSRF = "CSRF"
    XXE = "XXE"
    BUSINESS_LOGIC = "Business Logic"
    INFO_DISCLOSURE = "Information Disclosure"
    OPEN_REDIRECT = "Open Redirect"
    FILE_UPLOAD = "File Upload"
    PATH_TRAVERSAL = "Path Traversal"
    DESERIALIZATION = "Deserialization"
    COMMAND_INJECTION = "Command Injection"
    OTHER = "Other"


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class VulnerabilityReport:
    """Standardized vulnerability report structure"""
    
    # Identifiers
    report_id: str
    platform: str  # hackerone, bugcrowd, nvd, github
    
    # Target Information
    target_domain: str
    target_company: str
    target_program: str
    
    # Vulnerability Details
    vulnerability_type: str
    severity: str
    cvss_score: float
    
    # Technical Details
    technology_stack: List[str] = field(default_factory=list)
    endpoint: str = ""
    http_method: str = "GET"
    vulnerability_location: str = "web"  # web, api, mobile, other
    
    # Context
    description: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    
    # Metadata
    reported_date: Optional[datetime] = None
    disclosed_date: Optional[datetime] = None
    bounty_amount: float = 0.0
    researcher_reputation: int = 0
    
    # Additional Features
    authentication_required: bool = False
    privileges_required: str = "none"  # none, low, high
    user_interaction: bool = False
    complexity: str = "medium"  # low, medium, high
    
    # Tags
    tags: List[str] = field(default_factory=list)
    owasp_category: str = ""
    cwe_id: int = 0
    
    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'platform': self.platform,
            'target_domain': self.target_domain,
            'target_company': self.target_company,
            'target_program': self.target_program,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'technology_stack': self.technology_stack,
            'endpoint': self.endpoint,
            'http_method': self.http_method,
            'vulnerability_location': self.vulnerability_location,
            'description': self.description,
            'steps_to_reproduce': self.steps_to_reproduce,
            'impact': self.impact,
            'remediation': self.remediation,
            'reported_date': self.reported_date.isoformat() if self.reported_date else None,
            'disclosed_date': self.disclosed_date.isoformat() if self.disclosed_date else None,
            'bounty_amount': self.bounty_amount,
            'researcher_reputation': self.researcher_reputation,
            'authentication_required': self.authentication_required,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'complexity': self.complexity,
            'tags': self.tags,
            'owasp_category': self.owasp_category,
            'cwe_id': self.cwe_id
        }


class DataCollector:
    """Base class for data collection"""
    
    def __init__(self, cache_dir: str = "data/cache"):
        self.reports = []
        self.cache_dir = cache_dir
        self._setup_cache()
    
    def _setup_cache(self):
        """Setup caching directory"""
        from pathlib import Path
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
    
    def collect(self, limit: int = 1000) -> List[VulnerabilityReport]:
        """Collect vulnerability reports"""
        raise NotImplementedError("Subclasses must implement collect()")
    
    def normalize(self, raw_data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize raw data into standard format"""
        raise NotImplementedError("Subclasses must implement normalize()")
    
    def save_cache(self, reports: List[VulnerabilityReport], filename: str):
        """Save reports to cache"""
        import pickle
        from pathlib import Path
        
        cache_file = Path(self.cache_dir) / filename
        with open(cache_file, 'wb') as f:
            pickle.dump(reports, f)
        
        print(f"Cached {len(reports)} reports to {cache_file}")
    
    def load_cache(self, filename: str) -> Optional[List[VulnerabilityReport]]:
        """Load reports from cache"""
        import pickle
        from pathlib import Path
        
        cache_file = Path(self.cache_dir) / filename
        
        if not cache_file.exists():
            return None
        
        with open(cache_file, 'rb') as f:
            reports = pickle.load(f)
        
        print(f"Loaded {len(reports)} reports from cache")
        return reports
    
    def extract_vulnerability_type(self, text: str, weakness_name: str = "") -> str:
        """Extract vulnerability type from text"""
        
        text_lower = text.lower()
        weakness_lower = weakness_name.lower()
        
        # Mapping keywords to vulnerability types
        type_keywords = {
            'XSS': ['xss', 'cross-site scripting', 'cross site scripting', 'reflected xss', 'stored xss', 'dom xss'],
            'SQL Injection': ['sql injection', 'sqli', 'sql', 'union select', 'blind sql'],
            'IDOR': ['idor', 'insecure direct object', 'broken access control', 'unauthorized access'],
            'SSRF': ['ssrf', 'server-side request forgery', 'server side request'],
            'Remote Code Execution': ['rce', 'remote code execution', 'code execution', 'command execution'],
            'Authentication Bypass': ['auth bypass', 'authentication bypass', 'login bypass', 'authentication'],
            'CSRF': ['csrf', 'cross-site request forgery', 'cross site request'],
            'XXE': ['xxe', 'xml external entity', 'xml injection'],
            'Business Logic': ['business logic', 'logic flaw', 'race condition', 'workflow'],
            'Information Disclosure': ['information disclosure', 'info disclosure', 'sensitive data', 'data exposure'],
            'Open Redirect': ['open redirect', 'unvalidated redirect'],
            'File Upload': ['file upload', 'unrestricted upload', 'upload vulnerability'],
            'Path Traversal': ['path traversal', 'directory traversal', 'lfi', 'local file inclusion'],
            'Deserialization': ['deserialization', 'unsafe deserialization', 'pickle'],
            'Command Injection': ['command injection', 'os command injection', 'shell injection']
        }
        
        # Check weakness name first
        for vuln_type, keywords in type_keywords.items():
            if any(keyword in weakness_lower for keyword in keywords):
                return vuln_type
        
        # Then check text
        for vuln_
