"""Feature engineering - Production Implementation"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any
from collections import Counter
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer

from src.collectors.data_sources import VulnerabilityReport


class FeatureEngineer:
    """
    Transforms vulnerability reports into ML-ready features
    
    Implements comprehensive feature extraction including:
    - Categorical encoding
    - Technology stack embeddings
    - Temporal features
    - Text features (TF-IDF)
    - Interaction features
    - Statistical aggregations
    """
    
    def __init__(self):
        # Encoders
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=100,
            ngram_range=(1, 2),
            stop_words='english'
        )
        
        # Vocabularies
        self.tech_vocab = set()
        self.company_vocab = set()
        self.domain_vocab = set()
        
        # Statistics
        self.feature_stats = {}
        
        # Fitted flag
        self.is_fitted = False
    
    def fit_transform(self, reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """
        Fit feature extractors and transform reports into features
        
        Args:
            reports: List of VulnerabilityReport objects
            
        Returns:
            DataFrame with engineered features
        """
        
        print(f"Engineering features from {len(reports)} reports...")
        
        # Extract basic features
        features_list = []
        descriptions = []
        
        for report in reports:
            feature_dict = self._extract_basic_features(report)
            features_list.append(feature_dict)
            descriptions.append(report.description)
        
        df = pd.DataFrame(features_list)
        
        # Build vocabularies
        self._build_vocabularies(reports)
        
        # Add technology features
        df = self._add_technology_features(df, reports)
        
        # Add text features
        df = self._add_text_features(df, descriptions)
        
        # Add temporal features
        df = self._add_temporal_features(df)
        
        # Encode categorical variables
        df = self._encode_categoricals(df)
        
        # Add interaction features
        df = self._add_interaction_features(df)
        
        # Add statistical features
        df = self._add_statistical_features(df, reports)
        
        # Handle missing values
        df = self._handle_missing_values(df)
        
        # Store feature statistics
        self._compute_feature_stats(df)
        
        self.is_fitted = True
        
        print(f"Generated {df.shape[1]} features")
        
        return df
    
    def transform(self, reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """
        Transform new reports using fitted extractors
        
        Args:
            reports: List of VulnerabilityReport objects
            
        Returns:
            DataFrame with engineered features
        """
        
        if not self.is_fitted:
            raise ValueError("FeatureEngineer must be fitted before transform")
        
        # Extract basic features
        features_list = []
        descriptions = []
        
        for report in reports:
            feature_dict = self._extract_basic_features(report)
            features_list.append(feature_dict)
            descriptions.append(report.description)
        
        df = pd.DataFrame(features_list)
        
        # Add all feature types (using fitted encoders)
        df = self._add_technology_features(df, reports)
        df = self._add_text_features(df, descriptions)
        df = self._add_temporal_features(df)
        df = self._encode_categoricals(df, fit=False)
        df = self._add_interaction_features(df)
        df = self._add_statistical_features(df, reports)
        df = self._handle_missing_values(df)
        
        return df
    
    def _extract_basic_features(self, report: VulnerabilityReport) -> Dict[str, Any]:
        """Extract basic features from a single report"""
        
        features = {
            # Target features
            'target_company': report.target_company,
            'target_domain': report.target_domain,
            'target_program': report.target_program,
            
            # Vulnerability features
            'vuln_type': report.vulnerability_type,
            'severity': report.severity,
            'cvss_score': report.cvss_score,
            'complexity': report.complexity,
            'owasp_category': report.owasp_category,
            'cwe_id': report.cwe_id,
            
            # Platform
            'platform': report.platform,
            
            # Technology features
            'tech_stack_count': len(report.technology_stack),
            'tech_stack_str': ','.join(sorted(report.technology_stack)),
            
            # Authentication features
            'auth_required': int(report.authentication_required),
            'privilege_level': report.privileges_required,
            'user_interaction': int(report.user_interaction),
            
            # Location features
            'location': report.vulnerability_location,
            'endpoint': report.endpoint,
            'http_method': report.http_method,
            'endpoint_depth': self._calculate_endpoint_depth(report.endpoint),
            
            # Temporal features
            'reported_year': report.reported_date.year if report.reported_date else 0,
            'reported_month': report.reported_date.month if report.reported_date else 0,
            'reported_day_of_week': report.reported_date.weekday() if report.reported_date else 0,
            'disclosure_delay_days': self._calculate_disclosure_delay(report),
            
            # Bounty features
            'bounty_amount': report.bounty_amount,
            'has_bounty': int(report.bounty_amount > 0),
            'bounty_tier': self._categorize_bounty(report.bounty_amount),
            
            # Researcher features
            'researcher_reputation': report.researcher_reputation,
            'reputation_tier': self._categorize_reputation(report.researcher_reputation),
            
            # Text features
            'description_length': len(report.description),
            'description_word_count': len(report.description.split()),
            'steps_count': len(report.steps_to_reproduce),
            'has_poc': int(len(report.steps_to_reproduce) > 0),
            
            # Tags
            'tag_count': len(report.tags),
        }
        
        return features
    
    def _build_vocabularies(self, reports: List[VulnerabilityReport]):
        """Build vocabularies from reports"""
        
        for report in reports:
            # Technology vocabulary
            self.tech_vocab.update(report.technology_stack)
            
            # Company vocabulary
            if report.target_company:
                self.company_vocab.add(report.target_company)
            
            # Domain vocabulary
            if report.target_domain:
                self.domain_vocab.add(report.target_domain)
    
    def _add_technology_features(self, df: pd.DataFrame, 
                                 reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """Add technology stack features"""
        
        # One-hot encode common technologies
        common_technologies = [
            'React', 'Angular', 'Vue.js', 'Node.js', 'Python', 'PHP', 
            'Java', 'Ruby', 'Go', 'GraphQL', 'REST', 'MongoDB', 
            'PostgreSQL', 'MySQL', 'Redis', 'AWS', 'Azure', 
            'Google Cloud', 'Docker', 'Kubernetes', 'Nginx', 'Apache'
        ]
        
        for tech in common_technologies:
            feature_name = f'tech_{tech.lower().replace(".", "").replace(" ", "_")}'
            df[feature_name] = [
                int(tech in report.technology_stack) 
                for report in reports
            ]
        
        # Technology category features
        df['has_frontend_framework'] = [
            int(any(fw in report.technology_stack 
                   for fw in ['React', 'Angular', 'Vue.js', 'Svelte']))
            for report in reports
        ]
        
        df['has_backend_framework'] = [
            int(any(fw in report.technology_stack 
                   for fw in ['Node.js', 'Django', 'Flask', 'Rails', 'Laravel']))
            for report in reports
        ]
        
        df['has_database'] = [
            int(any(db in report.technology_stack 
                   for db in ['MongoDB', 'PostgreSQL', 'MySQL', 'Redis', 'Cassandra']))
            for report in reports
        ]
        
        df['has_cloud_service'] = [
            int(any(cloud in report.technology_stack 
                   for cloud in ['AWS', 'Azure', 'Google Cloud', 'GCP']))
            for report in reports
        ]
        
        df['has_container_tech'] = [
            int(any(container in report.technology_stack 
                   for container in ['Docker', 'Kubernetes']))
            for report in reports
        ]
        
        # Primary language detection
        df['primary_language'] = [
            self._detect_primary_language(report.technology_stack)
            for report in reports
        ]
        
        return df
    
    def _add_text_features(self, df: pd.DataFrame, descriptions: List[str]) -> pd.DataFrame:
        """Add text-based features using TF-IDF"""
        
        if not descriptions:
            return df
        
        # Fit or transform TF-IDF
        if not self.is_fitted:
            tfidf_matrix = self.tfidf_vectorizer.fit_transform(descriptions)
        else:
            tfidf_matrix = self.tfidf_vectorizer.transform(descriptions)
        
        # Convert to DataFrame
        tfidf_features = pd.DataFrame(
            tfidf_matrix.toarray(),
            columns=[f'tfidf_{i}' for i in range(tfidf_matrix.shape[1])]
        )
        
        # Concatenate with main DataFrame
        df = pd.concat([df.reset_index(drop=True), tfidf_features], axis=1)
        
        # Add text statistics
        df['avg_word_length'] = [
            np.mean([len(word) for word in desc.split()]) if desc else 0
            for desc in descriptions
        ]
        
        df['has_technical_terms'] = [
            int(any(term in desc.lower() for term in 
                   ['injection', 'bypass', 'escalation', 'traversal', 'overflow']))
            for desc in descriptions
        ]
        
        return df
    
    def _add_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add temporal features"""
        
        # Season
        df['season'] = df['reported_month'].apply(lambda m:
            0 if m in [12, 1, 2] else      # Winter
            1 if m in [3, 4, 5] else       # Spring
            2 if m in [6, 7, 8] else       # Summer
            3 if m in [9, 10, 11] else 0   # Fall
        )
        
        # Is weekend
        df['is_weekend'] = (df['reported_day_of_week'] >= 5).astype(int)
        
        # Quarter
        df['quarter'] = df['reported_month'].apply(lambda m:
            1 if m <= 3 else
            2 if m <= 6 else
            3 if m <= 9 else 4
        )
        
        # Year features (for trend analysis)
        df['years_since_2020'] = df['reported_year'] - 2020
        
        # Disclosure delay categories
        df['disclosure_speed'] = df['disclosure_delay_days'].apply(lambda d:
            0 if d < 0 else           # Invalid
            1 if d <= 30 else         # Fast (< 1 month)
            2 if d <= 90 else         # Normal (1-3 months)
            3 if d <= 180 else        # Slow (3-6 months)
            4                         # Very slow (> 6 months)
        )
        
        return df
    
    def _encode_categoricals(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """Encode categorical variables"""
        
        categorical_columns = [
            'target_company', 'platform', 'vuln_type', 'severity',
            'complexity', 'privilege_level', 'location', 'http_method',
            'primary_language', 'owasp_category', 'bounty_tier', 
            'reputation_tier'
        ]
        
        for col in categorical_columns:
            if col not in df.columns:
                continue
            
            # Fill missing values
            df[col] = df[col].fillna('Unknown')
            
            if fit:
                # Fit and transform
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(df[col])
            else:
                # Transform only (handle unknown categories)
                if col in self.label_encoders:
                    encoder = self.label_encoders[col]
                    df[f'{col}_encoded'] = df[col].apply(lambda x:
                        encoder.transform([x])[0] if x in encoder.classes_ else -1
                    )
                else:
                    df[f'{col}_encoded'] = -1
        
        return df
    
    def _add_interaction_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create interaction features"""
        
        # Technology × Vulnerability Type interactions
        if 'tech_react' in df.columns and 'vuln_type_encoded' in df.columns:
            df['react_xss_interaction'] = (
                df['tech_react'] * (df['vuln_type'] == 'XSS').astype(int)
            )
        
        if 'has_database' in df.columns and 'vuln_type_encoded' in df.columns:
            df['db_sqli_interaction'] = (
                df['has_database'] * (df['vuln_type'] == 'SQL Injection').astype(int)
            )
        
        # Authentication × Severity
        if 'auth_required' in df.columns and 'cvss_score' in df.columns:
            df['auth_severity_interaction'] = df['auth_required'] * df['cvss_score']
        
        # Complexity × User Interaction
        if 'user_interaction' in df.columns and 'complexity_encoded' in df.columns:
            df['complexity_ui_interaction'] = (
                df['user_interaction'] * df['complexity_encoded']
            )
        
        # Platform × Bounty
        if 'platform_encoded' in df.columns and 'bounty_amount' in df.columns:
            df['platform_bounty_interaction'] = (
                df['platform_encoded'] * np.log1p(df['bounty_amount'])
            )
        
        # Technology diversity × CVSS
        if 'tech_stack_count' in df.columns and 'cvss_score' in df.columns:
            df['tech_diversity_severity'] = df['tech_stack_count'] * df['cvss_score']
        
        return df
    
    def _add_statistical_features(self, df: pd.DataFrame,
                                  reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """Add statistical aggregation features"""
        
        # Company-level statistics
        company_stats = self._compute_company_statistics(reports)
        df['company_avg_bounty'] = df['target_company'].map(
            lambda x: company_stats.get(x, {}).get('avg_bounty', 0)
        )
        df['company_total_reports'] = df['target_company'].map(
            lambda x: company_stats.get(x, {}).get('total_reports', 0)
        )
        df['company_avg_severity'] = df['target_company'].map(
            lambda x: company_stats.get(x, {}).get('avg_severity', 5.0)
        )
        
        # Vulnerability type statistics
        vuln_stats = self._compute_vuln_type_statistics(reports)
        df['vulntype_avg_bounty'] = df['vuln_type'].map(
            lambda x: vuln_stats.get(x, {}).get('avg_bounty', 0)
        )
        df['vulntype_frequency'] = df['vuln_type'].map(
            lambda x: vuln_stats.get(x, {}).get('frequency', 0)
        )
        
        return df
    
    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in features"""
        
        # Numeric columns - fill with median
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            if df[col].isnull().any():
                median_value = df[col].median()
                df[col] = df[col].fillna(median_value)
        
        # Categorical columns - already handled in encoding
        
        # Replace inf values
        df = df.replace([np.inf, -np.inf], 0)
        
        return df
    
    def _compute_feature_stats(self, df: pd.DataFrame):
        """Compute and store feature statistics"""
        
        self.feature_stats = {
            'mean': df.mean().to_dict(),
            'std': df.std().to_dict(),
            'min': df.min().to_dict(),
            'max': df.max().to_dict()
        }
    
    def _calculate_endpoint_depth(self, endpoint: str) -> int:
        """Calculate API endpoint depth"""
        if not endpoint:
            return 0
        return endpoint.count('/')
    
    def _calculate_disclosure_delay(self, report: VulnerabilityReport) -> int:
        """Calculate days between report and disclosure"""
        if not report.reported_date or not report.disclosed_date:
            return 0
        
        delta = report.disclosed_date - report.reported_date
        return max(0, delta.days)
    
    def _categorize_bounty(self, amount: float) -> str:
        """Categorize bounty amount into tiers"""
        if amount == 0:
            return 'none'
        elif amount < 500:
            return 'low'
        elif amount < 2000:
            return 'medium'
        elif amount < 10000:
            return 'high'
        else:
            return 'critical'
    
    def _categorize_reputation(self, reputation: int) -> str:
        """Categorize researcher reputation"""
        if reputation == 0:
            return 'unknown'
        elif reputation < 100:
            return 'beginner'
        elif reputation < 1000:
            return 'intermediate'
        elif reputation < 10000:
            return 'advanced'
        else:
            return 'expert'
    
    def _detect_primary_language(self, tech_stack: List[str]) -> str:
        """Detect primary programming language"""
        
        languages = ['Python', 'JavaScript', 'Node.js', 'Java', 'Ruby', 
                    'PHP', 'Go', 'C#', 'C++', 'Rust']
        
        for lang in languages:
            if lang in tech_stack:
                return lang
        
        return 'Unknown'
    
    def _compute_company_statistics(self, reports: List[VulnerabilityReport]) -> Dict:
        """Compute per-company statistics"""
        
        company_data = {}
        
        for report in reports:
            company = report.target_company
            
            if company not in company_data:
                company_data[company] = {
                    'bounties': [],
                    'severities': [],
                    'count': 0
                }
            
            company_data[company]['bounties'].append(report.bounty_amount)
            company_data[company]['severities'].append(report.cvss_score)
            company_data[company]['count'] += 1
        
        # Compute statistics
        company_stats = {}
        for company, data in company_data.items():
            company_stats[company] = {
                'avg_bounty': np.mean(data['bounties']),
                'avg_severity': np.mean(data['severities']),
                'total_reports': data['count']
            }
        
        return company_stats
    
    def _compute_vuln_type_statistics(self, reports: List[VulnerabilityReport]) -> Dict:
        """Compute per-vulnerability-type statistics"""
        
        vuln_data = {}
        
        for report in reports:
            vuln_type = report.vulnerability_type
            
            if vuln_type not in vuln_data:
                vuln_data[vuln_type] = {
                    'bounties': [],
                    'count': 0
                }
            
            vuln_data[vuln_type]['bounties'].append(report.bounty_amount)
            vuln_data[vuln_type]['count'] += 1
        
        # Compute statistics
        vuln_stats = {}
        for vuln_type, data in vuln_data.items():
            vuln_stats[vuln_type] = {
                'avg_bounty': np.mean(data['bounties']),
                'frequency': data['count']
            }
        
        return vuln_stats
    
    def get_feature_importance_names(self, feature_indices: np.ndarray) -> List[str]:
        """Get feature names for given indices"""
        
        # This would be called after training to map feature importances
        # to readable feature names
        pass
    
    def save(self, filepath: str):
        """Save feature engineer state"""
        import pickle
        
        with open(filepath, 'wb') as f:
            pickle.dump({
                'label_encoders': self.label_encoders,
                'scaler': self.scaler,
                'tfidf_vectorizer': self.tfidf_vectorizer,
                'tech_vocab': self.tech_vocab,
                'company_vocab': self.company_vocab,
                'domain_vocab': self.domain_vocab,
                'feature_stats': self.feature_stats,
                'is_fitted': self.is_fitted
            }, f)
        
        print(f"Saved FeatureEngineer to {filepath}")
    
    @classmethod
    def load(cls, filepath: str):
        """Load feature engineer state"""
        import pickle
        
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        engineer = cls()
        engineer.label_encoders = state['label_encoders']
        engineer.scaler = state['scaler']
        engineer.tfidf_vectorizer = state['tfidf_vectorizer']
        engineer.tech_vocab = state['tech_vocab']
        engineer.company_vocab = state['company_vocab']
        engineer.domain_vocab = state['domain_vocab']
        engineer.feature_stats = state['feature_stats']
        engineer.is_fitted = state['is_fitted']
        
        print(f"Loaded FeatureEngineer from {filepath}")
        
        return engineer
