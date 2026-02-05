"""Enrich vulnerability reports with additional data"""

from typing import List
from ..collectors.data_sources import VulnerabilityReport


class DataEnricher:
    """Enrich vulnerability reports with derived data"""
    
    def enrich_reports(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Enrich reports with additional computed fields
        
        Args:
            reports: List of reports to enrich
            
        Returns:
            List of enriched reports
        """
        
        enriched = []
        
        for report in reports:
            try:
                enriched_report = self.enrich_report(report)
                enriched.append(enriched_report)
            except Exception as e:
                print(f"Warning: Could not enrich report {getattr(report, 'report_id', 'unknown')}: {e}")
                # Still add the report even if enrichment fails
                enriched.append(report)
        
        return enriched
    
    def enrich(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """Alias for enrich_reports - for compatibility with TrainingPipeline"""
        return self.enrich_reports(reports)
    
    def enrich_report(self, report: VulnerabilityReport) -> VulnerabilityReport:
        """Enrich a single report"""
        
        # Add risk score based on severity and bounty
        if not hasattr(report, 'risk_score') or report.risk_score is None:
            report.risk_score = self.calculate_risk_score(report)
        
        # Add exploitability score
        if not hasattr(report, 'exploitability_score') or report.exploitability_score is None:
            report.exploitability_score = self.calculate_exploitability(report)
        
        # Add impact score
        if not hasattr(report, 'impact_score') or report.impact_score is None:
            report.impact_score = self.calculate_impact(report)
        
        return report
    
    def calculate_risk_score(self, report: VulnerabilityReport) -> float:
        """Calculate overall risk score"""
        
        severity_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'none': 0.0
        }
        
        severity = getattr(report, 'severity', 'none')
        base_score = severity_scores.get(severity.lower() if severity else 'none', 0.0)
        
        # Adjust based on bounty (indicator of real-world value)
        bounty = getattr(report, 'bounty_amount', 0)
        if bounty:
            try:
                bounty_factor = min(float(bounty) / 10000, 2.0)
                base_score *= (1 + bounty_factor * 0.2)
            except (ValueError, TypeError):
                pass
        
        return min(base_score, 10.0)
    
    def calculate_exploitability(self, report: VulnerabilityReport) -> float:
        """Calculate exploitability score"""
        
        score = 5.0  # Base score
        
        # Authentication required reduces exploitability
        auth_required = getattr(report, 'authentication_required', False)
        if not auth_required:
            score += 2.0
        
        # User interaction reduces exploitability
        user_interaction = getattr(report, 'user_interaction', False)
        if not user_interaction:
            score += 1.0
        
        # Complexity affects exploitability
        complexity = getattr(report, 'complexity', 'medium')
        complexity_factors = {
            'low': 2.0,
            'medium': 0.0,
            'high': -2.0
        }
        score += complexity_factors.get(complexity if complexity else 'medium', 0.0)
        
        return max(0.0, min(score, 10.0))
    
    def calculate_impact(self, report: VulnerabilityReport) -> float:
        """Calculate impact score based on severity and CVSS"""
        
        cvss = getattr(report, 'cvss_score', 0.0)
        
        if cvss:
            try:
                return float(cvss)
            except (ValueError, TypeError):
                pass
        
        # Fallback to severity-based calculation
        severity = getattr(report, 'severity', 'none')
        severity_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'none': 0.0
        }
        
        return severity_scores.get(severity.lower() if severity else 'none', 0.0)
