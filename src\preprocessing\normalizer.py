"""Data normalization and cleaning"""

import re
from typing import List, Dict, Any
from datetime import datetime
from ..collectors.data_sources import VulnerabilityReport


class DataNormalizer:
    """Normalize and clean vulnerability report data"""
    
    def __init__(self):
        self.cleaned_count = 0
        self.removed_count = 0
    
    def normalize_reports(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Normalize a list of vulnerability reports
        
        Args:
            reports: List of raw reports
            
        Returns:
            List of cleaned and normalized reports
        """
        
        normalized = []
        
        for report in reports:
            try:
                normalized_report = self.normalize_report(report)
                if normalized_report:
                    normalized.append(normalized_report)
                    self.cleaned_count += 1
                else:
                    self.removed_count += 1
            except Exception as e:
                print(f"Error normalizing report {report.report_id}: {e}")
                self.removed_count += 1
        
        print(f"Normalized {self.cleaned_count} reports, removed {self.removed_count} invalid reports")
        
        return normalized
    
    def normalize_report(self, report: VulnerabilityReport) -> VulnerabilityReport:
        """Normalize a single report"""
        
        # Skip if missing critical fields
        if not report.title and not report.description:
            return None
        
        if not report.vulnerability_type:
            return None
        
        # Clean text fields
        if report.title:
            report.title = self.clean_text(report.title)
        
        if report.description:
            report.description = self.clean_text(report.description)
        
        # Normalize severity
        if report.severity:
            report.severity = report.severity.lower().strip()
            if report.severity not in ['critical', 'high', 'medium', 'low', 'none']:
                report.severity = 'none'
        
        # Ensure bounty is numeric
        if report.bounty_amount:
            try:
                report.bounty_amount = float(report.bounty_amount)
            except:
                report.bounty_amount = 0.0
        
        return report
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        
        if not text:
            return ""
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove URLs (optional - keep for now)
        # text = re.sub(r'http[s]?://\S+', '', text)
        
        # Trim
        text = text.strip()
        
        return text
