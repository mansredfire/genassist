"""Remove duplicate vulnerability reports"""

from typing import List, Set
from ..collectors.data_sources import VulnerabilityReport


class Deduplicator:
    """Remove duplicate vulnerability reports"""
    
    def __init__(self):
        self.duplicates_removed = 0
    
    def remove_duplicates(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Remove duplicate reports based on report_id
        
        Args:
            reports: List of reports (may contain duplicates)
            
        Returns:
            List of unique reports
        """
        
        seen_ids: Set[str] = set()
        unique_reports = []
        
        for report in reports:
            if report.report_id not in seen_ids:
                seen_ids.add(report.report_id)
                unique_reports.append(report)
            else:
                self.duplicates_removed += 1
        
        if self.duplicates_removed > 0:
            print(f"Removed {self.duplicates_removed} duplicate reports")
        
        return unique_reports
    
    def remove_similar_duplicates(self, reports: List[VulnerabilityReport], 
                                   threshold: float = 0.9) -> List[VulnerabilityReport]:
        """
        Remove reports that are very similar (fuzzy matching)
        
        Args:
            reports: List of reports
            threshold: Similarity threshold (0-1)
            
        Returns:
            List of unique reports
        """
        
        # Simple implementation - can be enhanced with fuzzy matching
        # For now, just check title similarity
        
        unique_reports = []
        seen_titles: Set[str] = set()
        
        for report in reports:
            title_lower = report.title.lower() if report.title else ""
            
            if title_lower not in seen_titles:
                seen_titles.add(title_lower)
                unique_reports.append(report)
            else:
                self.duplicates_removed += 1
        
        return unique_reports
