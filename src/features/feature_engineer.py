"""Feature engineering for vulnerability reports"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any
from sklearn.preprocessing import LabelEncoder
from ..collectors.data_sources import VulnerabilityReport


class FeatureEngineer:
    """Engineer features from vulnerability reports for ML models"""
    
    def __init__(self):
        self.feature_stats = {}
        self.label_encoders = {}
        self.feature_names = []
    
    def fit_transform(self, reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """
        Transform vulnerability reports into feature DataFrame
        
        Args:
            reports: List of VulnerabilityReport objects
            
        Returns:
            DataFrame with engineered features
        """
        
        print(f"Engineering features from {len(reports)} reports...")
        
        # Convert reports to basic features
        features = []
        
        for report in reports:
            feature_dict = self._extract_features(report)
            features.append(feature_dict)
        
        # Create DataFrame
        df = pd.DataFrame(features)
        
        # Encode categorical variables
        df = self._encode_categorical(df)
        
        # Compute and store statistics
        self._compute_feature_stats(df)
        
        print(f"✓ Engineered {len(df.columns)} features")
        
        return df
    
    def _extract_features(self, report: VulnerabilityReport) -> Dict[str, Any]:
        """Extract features from a single report"""
        
        features = {}
        
        # Basic features
        features['severity_score'] = self._severity_to_score(getattr(report, 'severity', 'none'))
        features['cvss_score'] = getattr(report, 'cvss_score', 0.0)
        features['bounty_amount'] = getattr(report, 'bounty_amount', 0.0)
        features['researcher_reputation'] = getattr(report, 'researcher_reputation', 0)
        
        # Binary features
        features['auth_required'] = 1 if getattr(report, 'authentication_required', False) else 0
        features['user_interaction'] = 1 if getattr(report, 'user_interaction', False) else 0
        
        # Complexity encoding
        complexity = getattr(report, 'complexity', 'medium')
        features['complexity_low'] = 1 if complexity == 'low' else 0
        features['complexity_medium'] = 1 if complexity == 'medium' else 0
        features['complexity_high'] = 1 if complexity == 'high' else 0
        
        # Privilege level encoding
        privileges = getattr(report, 'privileges_required', 'none')
        features['privileges_none'] = 1 if privileges == 'none' else 0
        features['privileges_user'] = 1 if privileges == 'user' else 0
        features['privileges_admin'] = 1 if privileges == 'admin' else 0
        
        # Categorical features (will be encoded later)
        features['vulnerability_type'] = getattr(report, 'vulnerability_type', 'Unknown')
        features['platform'] = getattr(report, 'platform', 'unknown')
        features['target_company'] = getattr(report, 'target_company', 'Unknown')
        features['target_domain'] = getattr(report, 'target_domain', 'unknown')
        features['target_program'] = getattr(report, 'target_program', 'unknown')
        features['vulnerability_location'] = getattr(report, 'vulnerability_location', 'Unknown')
        features['http_method'] = getattr(report, 'http_method', 'Unknown')
        features['owasp_category'
