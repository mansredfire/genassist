"""Feature engineering for vulnerability reports"""

import pandas as pd
import numpy as np
import pickle
from typing import List, Dict, Any
from pathlib import Path
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
        features['owasp_category'] = getattr(report, 'owasp_category', 'Unknown')
        features['cwe_id'] = getattr(report, 'cwe_id', 'Unknown')
        
        # Technology stack features
        tech_stack = getattr(report, 'technology_stack', [])
        if tech_stack:
            features['tech_stack'] = ','.join(tech_stack) if isinstance(tech_stack, list) else str(tech_stack)
            features['tech_stack_count'] = len(tech_stack) if isinstance(tech_stack, list) else 0
        else:
            features['tech_stack'] = 'Unknown'
            features['tech_stack_count'] = 0
        
        # Text length features
        description = getattr(report, 'description', '')
        features['description_length'] = len(description) if description else 0
        
        title = getattr(report, 'title', '')
        features['title_length'] = len(title) if title else 0
        
        # Risk and exploitability scores (if enriched)
        features['risk_score'] = getattr(report, 'risk_score', 0.0)
        features['exploitability_score'] = getattr(report, 'exploitability_score', 0.0)
        features['impact_score'] = getattr(report, 'impact_score', 0.0)
        
        return features
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to numeric score"""
        severity_map = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'none': 0.0
        }
        return severity_map.get(severity.lower() if severity else 'none', 0.0)
    
    def _encode_categorical(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical variables"""
        
        categorical_columns = [
            'vulnerability_type', 'platform', 'target_company', 
            'target_domain', 'target_program', 'vulnerability_location',
            'http_method', 'owasp_category', 'cwe_id', 'tech_stack'
        ]
        
        for col in categorical_columns:
            if col in df.columns:
                # Create label encoder
                le = LabelEncoder()
                
                # Handle missing values
                df[col] = df[col].fillna('Unknown')
                
                # Fit and transform
                df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
                
                # Store encoder for later use
                self.label_encoders[col] = le
                
                # Drop original categorical column
                df = df.drop(columns=[col])
        
        return df
    
    def _compute_feature_stats(self, df: pd.DataFrame):
        """Compute feature statistics for normalization"""
        
        # Select only numeric columns for statistics
        numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
        
        if not numeric_cols:
            print("Warning: No numeric columns found for statistics")
            self.feature_stats = {
                'mean': {},
                'std': {},
                'min': {},
                'max': {}
            }
            return
        
        # Compute statistics only on numeric columns
        numeric_df = df[numeric_cols]
        
        self.feature_stats = {
            'mean': numeric_df.mean().to_dict(),
            'std': numeric_df.std().to_dict(),
            'min': numeric_df.min().to_dict(),
            'max': numeric_df.max().to_dict()
        }
        
        # Store feature names
        self.feature_names = numeric_cols
        
        print(f"Computed statistics for {len(numeric_cols)} numeric features")
    
    def transform(self, reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """
        Transform new reports using fitted encoders
        
        Args:
            reports: List of VulnerabilityReport objects
            
        Returns:
            DataFrame with engineered features
        """
        
        # Extract features
        features = []
        for report in reports:
            feature_dict = self._extract_features(report)
            features.append(feature_dict)
        
        df = pd.DataFrame(features)
        
        # Apply existing encoders
        categorical_columns = [
            'vulnerability_type', 'platform', 'target_company', 
            'target_domain', 'target_program', 'vulnerability_location',
            'http_method', 'owasp_category', 'cwe_id', 'tech_stack'
        ]
        
        for col in categorical_columns:
            if col in df.columns and col in self.label_encoders:
                le = self.label_encoders[col]
                
                # Handle missing values
                df[col] = df[col].fillna('Unknown')
                
                # Transform using existing encoder
                # Handle unseen labels
                df[f'{col}_encoded'] = df[col].astype(str).apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                )
                
                # Drop original column
                df = df.drop(columns=[col])
        
        return df
    
    def save(self, filepath):
        """Save the feature engineer state to a pickle file"""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        state = {
            'feature_stats': self.feature_stats,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
        
        print(f"Saved FeatureEngineer to {filepath}")
    
    def load(self, filepath):
        """Load the feature engineer state from a pickle file"""
        filepath = Path(filepath)
        
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        self.feature_stats = state.get('feature_stats', {})
        self.label_encoders = state.get('label_encoders', {})
        self.feature_names = state.get('feature_names', [])
        
        print(f"Loaded FeatureEngineer from {filepath}")
        
        return self
