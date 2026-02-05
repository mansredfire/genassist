"""JSON importer for vulnerability reports"""

import json
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

from .data_sources import VulnerabilityReport


class JSONImporter:
    """Import vulnerability reports from JSON files"""
    
    def __init__(self):
        self.reports = []
    
    def import_from_json(self, filepath: str) -> List[VulnerabilityReport]:
        """
        Import vulnerability reports from JSON file
        
        Args:
            filepath: Path to JSON file
            
        Returns:
            List of VulnerabilityReport objects
            
        Expected JSON structure:
        [
          {
            "report_id": "report_001",
            "target_domain": "example.com",
            "target_company": "Example Corp",
            "vulnerability_type": "SQL Injection",
            "severity": "high",
            "cvss_score": 7.5,
            "tech_stack": ["React", "Node.js", "MySQL"],
            "description": "SQL injection in login form",
            ...
          },
          ...
        ]
        """
        
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"JSON file not found: {filepath}")
        
        print(f"Loading JSON from: {filepath}")
        
        # Read JSON
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both single object and array
        if isinstance(data, dict):
            data = [data]
        
        if not isinstance(data, list):
            raise ValueError("JSON must be an array of reports or a single report object")
        
        reports = []
        
        for idx, item in enumerate(data):
            try:
                # Validate required fields
                required_fields = [
                    'report_id', 'target_domain', 'target_company',
                    'vulnerability_type', 'severity', 'cvss_score'
                ]
                
                missing_fields = [f for f in required_fields if f not in item]
                if missing_fields:
                    print(f"Warning: Skipping report {idx} - missing fields: {missing_fields}")
                    continue
                
                # Parse tech stack
                tech_stack = item.get('tech_stack', [])
                if isinstance(tech_stack, str):
                    tech_stack = [t.strip() for t in tech_stack.split(',')]
                
                # Create report
                report = VulnerabilityReport(
                    report_id=str(item['report_id']),
                    platform='json_import',
                    target_domain=str(item['target_domain']),
                    target_company=str(item['target_company']),
                    target_program=str(item.get('target_program', item['target_company'])),
                    vulnerability_type=str(item['vulnerability_type']),
                    severity=str(item['severity']).lower(),
                    cvss_score=float(item['cvss_score']),
                    technology_stack=tech_stack,
                    endpoint=str(item.get('endpoint', '/')),
                    http_method=str(item.get('http_method', 'GET')),
                    vulnerability_location=str(item.get('vulnerability_location', 'web')),
                    description=str(item.get('description', '')),
                    steps_to_reproduce=item.get('steps_to_reproduce', []),
                    impact=str(item.get('impact', '')),
                    remediation=str(item.get('remediation', '')),
                    reported_date=self._parse_date(item.get('reported_date')),
                    disclosed_date=self._parse_date(item.get('disclosed_date')),
                    bounty_amount=float(item.get('bounty_amount', 0.0)),
                    researcher_reputation=int(item.get('researcher_reputation', 0)),
                    authentication_required=bool(item.get('authentication_required', False)),
                    privileges_required=str(item.get('privileges_required', 'none')),
                    user_interaction=bool(item.get('user_interaction', False)),
                    complexity=str(item.get('complexity', 'medium')),
                    tags=item.get('tags', []),
                    owasp_category=str(item.get('owasp_category', '')),
                    cwe_id=int(item.get('cwe_id', 0)),
                    raw_data=item.get('raw_data', {})
                )
                
                reports.append(report)
                
            except Exception as e:
                print(f"Warning: Skipping report {idx} due to error: {e}")
                continue
        
        print(f"✓ Imported {len(reports)} reports from JSON")
        self.reports = reports
        return reports
    
    def _parse_date(self, date_str):
        """Parse date string to datetime object"""
        if not date_str:
            return None
        
        try:
            return datetime.fromisoformat(date_str)
        except:
            return None
    
    def validate_json(self, filepath: str) -> dict:
        """
        Validate JSON file without importing
        
        Returns:
            Dictionary with validation results
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            return {'valid': False, 'error': 'File not found'}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both single object and array
            if isinstance(data, dict):
                data = [data]
            
            if not isinstance(data, list):
                return {
                    'valid': False,
                    'error': 'JSON must be an array of reports or a single report object'
                }
            
            required_fields = [
                'report_id', 'target_domain', 'target_company',
                'vulnerability_type', 'severity', 'cvss_score'
            ]
            
            # Check first report for required fields
            if len(data) > 0:
                missing_fields = [f for f in required_fields if f not in data[0]]
                if missing_fields:
                    return {
                        'valid': False,
                        'error': f'Missing required fields: {missing_fields}',
                        'found_fields': list(data[0].keys())
                    }
            
            return {
                'valid': True,
                'reports': len(data),
                'required_fields_present': True
            }
            
        except json.JSONDecodeError as e:
            return {'valid': False, 'error': f'Invalid JSON: {str(e)}'}
        except Exception as e:
            return {'valid': False, 'error': str(e)}
