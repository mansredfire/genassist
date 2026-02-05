# src/collectors/data_sources.py

from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime

@dataclass
class VulnerabilityReport:
    """Standardized vulnerability report structure"""
    
    # Identifiers
    report_id: str
    platform: str  # hackerone, bugcrowd, cve, etc.
    
    # Target Information
    target_domain: str
    target_company: str
    target_program: str
    
    # Vulnerability Details
    vulnerability_type: str  # XSS, SQLI, IDOR, etc.
    severity: str  # critical, high, medium, low
    cvss_score: float
    
    # Technical Details
    technology_stack: List[str]
    endpoint: str
    http_method: str
    vulnerability_location: str  # frontend, backend, api, mobile
    
    # Context
    description: str
    steps_to_reproduce: List[str]
    impact: str
    remediation: str
    
    # Metadata
    reported_date: datetime
    disclosed_date: datetime
    bounty_amount: float
    researcher_reputation: int
    
    # Additional Features
    authentication_required: bool
    privileges_required: str  # none, low, high
    user_interaction: bool
    complexity: str  # low, medium, high
    
    # Tags and Categories
    tags: List[str]
    owasp_category: str
    cwe_id: int


class DataCollector:
    """Base class for data collection"""
    
    def __init__(self):
        self.reports = []
    
    def collect(self) -> List[VulnerabilityReport]:
        """Collect vulnerability reports"""
        raise NotImplementedError
    
    def normalize(self, raw_data: Dict) -> VulnerabilityReport:
        """Normalize raw data into standard format"""
        raise NotImplementedError
