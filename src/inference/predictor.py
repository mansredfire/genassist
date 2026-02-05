"""Enhanced threat prediction engine with comprehensive vulnerability coverage"""

import pickle
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import json
from datetime import datetime

from src.features.feature_engineer import FeatureEngineer
from src.models.vulnerability_classifier import VulnerabilityPredictor
from src.models.severity_predictor import SeverityPredictor
from src.models.chain_detector import ChainDetector
from src.collectors.enhanced_extractor import EnhancedVulnerabilityExtractor
from src.collectors.data_sources import VulnerabilityReport


class ThreatPredictor:
    """
    Enhanced production inference engine for vulnerability prediction
    
    New Features:
    - 40+ vulnerability type predictions
    - Modern API/GraphQL vulnerability detection
    - Cloud misconfiguration detection
    - Advanced authentication issue detection
    - Business logic flaw detection
    - Enhanced chain detection (25+ patterns)
    - Technology-specific recommendations
    """
    
    def __init__(self, models_dir: str = "data/models"):
        self.models_dir = Path(models_dir)
        self.models = {}
        self.feature_engineer = None
        self.enhanced_extractor = EnhancedVulnerabilityExtractor()
        self.metadata = {}
        
        # Load all components
        self.load_models()
    
    def load_models(self):
        """Load all trained models and feature engineer"""
        
        print(f"Loading models from {self.models_dir}...")
        
        try:
            # Load feature engineer
            feature_engineer_path = self.models_dir / 'feature_engineer.pkl'
            if feature_engineer_path.exists():
                self.feature_engineer = FeatureEngineer.load(str(feature_engineer_path))
                print("  ✓ Loaded FeatureEngineer")
            else:
                print("  ⚠ FeatureEngineer not found - will use default")
                self.feature_engineer = FeatureEngineer()
            
            # Load vulnerability predictor
            vuln_pred_path = self.models_dir / 'vulnerability_predictor.pkl'
            if vuln_pred_path.exists():
                self.models['vulnerability_predictor'] = VulnerabilityPredictor.load(
                    str(vuln_pred_path)
                )
                print("  ✓ Loaded VulnerabilityPredictor")
            else:
                print("  ⚠ VulnerabilityPredictor not found")
            
            # Load severity predictor
            severity_pred_path = self.models_dir / 'severity_predictor.pkl'
            if severity_pred_path.exists():
                self.models['severity_predictor'] = SeverityPredictor.load(
                    str(severity_pred_path)
                )
                print("  ✓ Loaded SeverityPredictor")
            else:
                print("  ⚠ SeverityPredictor not found")
            
            # Load chain detector
            chain_det_path = self.models_dir / 'chain_detector.pkl'
            if chain_det_path.exists():
                with open(chain_det_path, 'rb') as f:
                    self.models['chain_detector'] = pickle.load(f)
                print("  ✓ Loaded ChainDetector")
            else:
                # Create new chain detector with default patterns
                self.models['chain_detector'] = ChainDetector()
                print("  ⚠ ChainDetector not found - using default patterns")
            
            # Load metadata
            metadata_path = self.models_dir / 'metadata.json'
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
                print("  ✓ Loaded metadata")
            
            print("✓ All models loaded successfully")
            
        except Exception as e:
            print(f"Error loading models: {e}")
            raise
    
    def analyze_target(self, target_info: Dict) -> Dict:
        """
        Analyze a target and predict likely vulnerabilities
        
        Enhanced with:
        - Modern API vulnerability predictions
        - Cloud misconfiguration detection
        - GraphQL vulnerability detection
        - Advanced authentication predictions
        - Technology-specific recommendations
        
        Args:
            target_info: Dictionary with target information
                {
                    'domain': 'example.com',
                    'company_name': 'Example Corp',
                    'technology_stack': ['React', 'Node.js', 'PostgreSQL'],
                    'endpoints': ['/api/users', '/api/posts'],
                    'auth_required': True,
                    'has_api': True,
                    'has_graphql': False,
                    'cloud_provider': 'AWS',  # NEW
                    'description': 'Social media platform'
                }
        
        Returns:
            Comprehensive analysis with predictions and recommendations
        """
        
        print(f"\n{'='*70}")
        print(f"ANALYZING TARGET: {target_info.get('domain', 'Unknown')}")
        print(f"{'='*70}\n")
        
        # Auto-detect technologies if not provided
        if not target_info.get('technology_stack'):
            tech_info = self._detect_technologies(target_info['domain'])
            target_info['technology_stack'] = tech_info
            print(f"Auto-detected technologies: {tech_info}")
        
        # Create synthetic vulnerability report for feature extraction
        synthetic_report = self._create_synthetic_report(target_info)
        
        # Extract features
        print("Extracting features...")
        features_df = self.feature_engineer.transform([synthetic_report])
        
        # Remove target columns
        X = features_df.drop(['vuln_type', 'severity', 'cvss_score'], axis=1, errors='ignore')
        
        # Keep only numeric columns
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X = X[numeric_cols]
        
        print(f"Generated {X.shape[1]} features")
        
        # Predict vulnerabilities
        print("Predicting vulnerabilities...")
        vulnerability_predictions = self._predict_vulnerabilities(X, target_info)
        
        # Predict severities
        print("Predicting severities...")
        severity_predictions = self._predict_severities(X, vulnerability_predictions)
        
        # Detect chains
        print("Detecting vulnerability chains...")
        chain_predictions = self._detect_chains(vulnerability_predictions)
        
        # Generate test strategy
        print("Generating test strategy...")
        test_strategy = self._generate_test_strategy(
            vulnerability_predictions,
            chain_predictions,
            target_info
        )
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            vulnerability_predictions,
            severity_predictions,
            chain_predictions
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            vulnerability_predictions,
            chain_predictions,
            target_info
        )
        
        # Generate technology-specific insights
        tech_insights = self._generate_tech_insights(target_info)
        
        # Compile results
        results = {
            'target': target_info['domain'],
            'company': target_info.get('company_name', 'Unknown'),
            'technology_stack': target_info.get('technology_stack', []),
            'analysis_timestamp': datetime.now().isoformat(),
            'vulnerability_predictions': vulnerability_predictions,
            'severity_predictions': severity_predictions,
            'chain_predictions': chain_predictions,
            'test_strategy': test_strategy,
            'risk_score': risk_score,
            'risk_level': self._categorize_risk(risk_score),
            'recommendations': recommendations,
            'technology_insights': tech_insights,
            'metadata': {
                'model_version': self.metadata.get('model_versions', {}),
                'training_date': self.metadata.get('training_date', 'Unknown'),
                'enhanced_detection': True,
                'vulnerability_types_covered': 40
            }
        }
        
        print(f"\n✓ Analysis complete!")
        print(f"Risk Score: {risk_score}/10 ({results['risk_level'].upper()})")
        print(f"Top Vulnerabilities: {len([v for v in vulnerability_predictions if v['probability'] > 0.5])}")
        print(f"Chains Detected: {len(chain_predictions)}")
        
        return results
    
    def _detect_technologies(self, domain: str) -> List[str]:
        """Auto-detect technologies (placeholder - can be enhanced with real detection)"""
        
        # This is a simplified version
        # In production, you'd use tools like Wappalyzer, BuiltWith, etc.
        
        technologies = []
        
        # Could add real technology detection here
        # For now, return empty list to use user-provided tech stack
        
        return technologies
    
    def _create_synthetic_report(self, target_info: Dict) -> VulnerabilityReport:
        """Create a synthetic vulnerability report for feature extraction"""
        
        from datetime import datetime
        
        return VulnerabilityReport(
            report_id='synthetic',
            platform='analysis',
            target_domain=target_info.get('domain', ''),
            target_company=target_info.get('company_name', ''),
            target_program=target_info.get('domain', ''),
            vulnerability_type='XSS',  # Placeholder
            severity='medium',
            cvss_score=5.0,
            technology_stack=target_info.get('technology_stack', []),
            endpoint=target_info.get('endpoints', ['/'])[0] if target_info.get('endpoints') else '/',
            http_method='GET',
            vulnerability_location='web',
            description=target_info.get('description', ''),
            steps_to_reproduce=[],
            impact='',
            remediation='',
            reported_date=datetime.now(),
            disclosed_date=datetime.now(),
            bounty_amount=0.0,
            researcher_reputation=0,
            authentication_required=target_info.get('auth_required', False),
            privileges_required='none',
            user_interaction=False,
            complexity='medium',
            tags=[],
            owasp_category='',
            cwe_id=0,
            raw_data={}
        )
    
    def _predict_vulnerabilities(self, X: pd.DataFrame, 
                                target_info: Dict) -> List[Dict]:
        """Enhanced vulnerability prediction with technology-specific insights"""
        
        if 'vulnerability_predictor' not in self.models:
            print("⚠ VulnerabilityPredictor not loaded - using enhanced heuristics")
            return self._enhanced_heuristic_prediction(target_info)
        
        predictor = self.models['vulnerability_predictor']
        
        # Get top-k predictions
        top_predictions = predictor.predict_top_k(X, k=15, method='averaging')
        
        # Get model agreement
        agreement_scores = predictor.get_model_agreement(X)
        
        results = []
        
        for vuln_type, probability in top_predictions[0]:
            # Calculate priority (1-5 scale)
            priority = self._calculate_priority(probability, vuln_type)
            
            # Determine confidence level
            confidence = self._categorize_confidence(
                agreement_scores[0] if len(agreement_scores) > 0 else 0.7
            )
            
            # Add technology-specific context
            tech_relevance = self._assess_tech_relevance(
                vuln_type, 
                target_info.get('technology_stack', [])
            )
            
            results.append({
                'vulnerability_type': vuln_type,
                'probability': float(probability),
                'confidence': confidence,
                'priority': priority,
                'model_agreement': float(agreement_scores[0] if len(agreement_scores) > 0 else 0.7),
                'technology_relevance': tech_relevance
            })
        
        return results
    
    def _enhanced_heuristic_prediction(self, target_info: Dict) -> List[Dict]:
        """Enhanced heuristic-based vulnerability prediction with new types"""
        
        tech_stack = target_info.get('technology_stack', [])
        has_api = target_info.get('has_api', False)
        has_graphql = target_info.get('has_graphql', False)
        auth_required = target_info.get('auth_required', False)
        cloud_provider = target_info.get('cloud_provider', '')
        
        predictions = []
        
        # ==================== FRONTEND FRAMEWORK VULNERABILITIES ====================
        if any(fw in tech_stack for fw in ['React', 'Angular', 'Vue.js', 'Svelte']):
            predictions.extend([
                {
                    'vulnerability_type': 'XSS',
                    'probability': 0.75,
                    'confidence': 'high',
                    'priority': 4,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'CORS Misconfiguration',
                    'probability': 0.60,
                    'confidence': 'medium',
                    'priority': 3,
                    'technology_relevance': 'high'
                }
            ])
        
        # ==================== DATABASE VULNERABILITIES ====================
        if any(db in tech_stack for db in ['MySQL', 'PostgreSQL']):
            predictions.append({
                'vulnerability_type': 'SQL Injection',
                'probability': 0.65,
                'confidence': 'medium',
                'priority': 4,
                'technology_relevance': 'high'
            })
        
        if any(db in tech_stack for db in ['MongoDB', 'Cassandra', 'CouchDB']):
            predictions.append({
                'vulnerability_type': 'NoSQL Injection',
                'probability': 0.60,
                'confidence': 'medium',
                'priority': 4,
                'technology_relevance': 'high'
            })
        
        # ==================== API VULNERABILITIES ====================
        if has_api:
            predictions.extend([
                {
                    'vulnerability_type': 'IDOR',
                    'probability': 0.70,
                    'confidence': 'high',
                    'priority': 4,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'Excessive Data Exposure',
                    'probability': 0.65,
                    'confidence': 'medium',
                    'priority': 3,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'Rate Limiting Issues',
                    'probability': 0.55,
                    'confidence': 'medium',
                    'priority': 3,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'API Abuse',
                    'probability': 0.50,
                    'confidence': 'medium',
                    'priority': 3,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'SSRF',
                    'probability': 0.45,
                    'confidence': 'medium',
                    'priority': 3,
                    'technology_relevance': 'medium'
                }
            ])
        
        # ==================== GRAPHQL VULNERABILITIES ====================
        if has_graphql or 'GraphQL' in tech_stack:
            predictions.extend([
                {
                    'vulnerability_type': 'GraphQL Introspection',
                    'probability': 0.80,
                    'confidence': 'high',
                    'priority': 4,
                    'technology_relevance': 'critical'
                },
                {
                    'vulnerability_type': 'GraphQL Batching Abuse',
                    'probability': 0.65,
                    'confidence': 'medium',
                    'priority': 3,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'Excessive Data Exposure',
                    'probability': 0.70,
                    'confidence': 'high',
                    'priority': 4,
                    'technology_relevance': 'high'
                }
            ])
        
        # ==================== AUTHENTICATION VULNERABILITIES ====================
        if auth_required:
            predictions.extend([
                {
                    'vulnerability_type': 'Authentication Bypass',
                    'probability': 0.55,
                    'confidence': 'medium',
                    'priority': 4,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'Broken Authentication',
                    'probability': 0.50,
                    'confidence': 'medium',
                    'priority': 3,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'JWT Vulnerabilities',
                    'probability': 0.60,
                    'confidence': 'medium',
                    'priority': 4,
                    'technology_relevance': 'high'
                },
                {
                    'vulnerability_type': 'Session Fixation',
                    'probability': 0.45,
                    'confidence': 'low',
                    'priority': 3,
                    'technology_relevance': 'medium'
                },
                {
                    'vulnerability_type': 'CSRF',
                    'probability': 0.40,
                    'confidence': 'medium',
                    'priority': 2,
                    'technology_relevance': 'medium'
                }
            ])
        
        # ==================== CLOUD VULNERABILITIES ====================
        if cloud_provider:
            predictions.extend([
                {
                    'vulnerability_type': 'Cloud Misconfiguration',
                    'probability': 0.70,
                    'confidence': 'medium',
                    'priority': 5,
                    'technology_relevance': 'critical'
                },
                {
                    'vulnerability_type': 'SSRF',
                    'probability': 0.65,
                    'confidence': 'high',
                    'priority': 4,
                    'technology_relevance': 'high'
                }
            ])
            
            if cloud_provider.upper() == 'AWS':
                predictions.append({
                    'vulnerability_type': 'S3 Bucket Exposure',
                    'probability': 0.60,
                    'confidence': 'medium',
                    'priority': 4,
                    'technology_relevance': 'high'
                })
        
        # ==================== BUSINESS LOGIC ====================
        predictions.extend([
            {
                'vulnerability_type': 'Business Logic',
                'probability': 0.60,
                'confidence': 'medium',
                'priority': 4,
                'technology_relevance': 'medium'
            },
            {
                'vulnerability_type': 'Race Condition',
                'probability': 0.35,
                'confidence': 'low',
                'priority': 3,
                'technology_relevance': 'medium'
            }
        ])
        
        # ==================== CONFIGURATION ISSUES ====================
        predictions.extend([
            {
                'vulnerability_type': 'Information Disclosure',
                'probability': 0.50,
                'confidence': 'low',
                'priority': 2,
                'technology_relevance': 'low'
            },
            {
                'vulnerability_type': 'Exposed Admin Interface',
                'probability': 0.40,
                'confidence': 'low',
                'priority': 3,
                'technology_relevance': 'low'
            },
            {
                'vulnerability_type': 'Weak Cryptography',
                'probability': 0.35,
                'confidence': 'low',
                'priority': 3,
                'technology_relevance': 'low'
            }
        ])
        
        # ==================== COMMON WEB VULNERABILITIES ====================
        predictions.extend([
            {
                'vulnerability_type': 'Open Redirect',
                'probability': 0.30,
                'confidence': 'low',
                'priority': 2,
                'technology_relevance': 'low'
            },
            {
                'vulnerability_type': 'Clickjacking',
                'probability': 0.25,
                'confidence': 'low',
                'priority': 2,
                'technology_relevance': 'low'
            }
        ])
        
        # Sort by probability and return top 15
        predictions.sort(key=lambda x: x['probability'], reverse=True)
        
        return predictions[:15]
    
    def _assess_tech_relevance(self, vuln_type: str, tech_stack: List[str]) -> str:
        """Assess how relevant a vulnerability is to the technology stack"""
        
        # High relevance mappings
        high_relevance = {
            'GraphQL Introspection': ['GraphQL', 'Apollo'],
            'GraphQL Batching Abuse': ['GraphQL', 'Apollo'],
            'NoSQL Injection': ['MongoDB', 'Cassandra', 'CouchDB', 'Redis'],
            'SQL Injection': ['MySQL', 'PostgreSQL', 'SQL Server'],
            'JWT Vulnerabilities': ['Node.js', 'Express', 'JWT'],
            'Cloud Misconfiguration': ['AWS', 'Azure', 'GCP', 'Google Cloud'],
            'S3 Bucket Exposure': ['AWS'],
            'Deserialization': ['Java', 'Python', 'Ruby', 'PHP'],
        }
        
        if vuln_type in high_relevance:
            if any(tech in tech_stack for tech in high_relevance[vuln_type]):
                return 'critical'
        
        # Medium relevance for general API/web vulnerabilities
        api_vulns = ['IDOR', 'API Abuse', 'Excessive Data Exposure', 'Rate Limiting Issues']
        if vuln_type in api_vulns:
            return 'high'
        
        # Default
        return 'medium'
    
    def _predict_severities(self, X: pd.DataFrame, 
                           vulnerability_predictions: List[Dict]) -> Dict:
        """Predict severity for each vulnerability"""
        
        severity_predictions = {}
        
        if 'severity_predictor' not in self.models:
            # Use CVSS-based heuristics
            for vuln in vulnerability_predictions:
                vuln_type = vuln['vulnerability_type']
                severity_predictions[vuln_type] = self._heuristic_severity(vuln_type)
            return severity_predictions
        
        predictor = self.models['severity_predictor']
        
        # Get detailed predictions
        detailed_predictions = predictor.predict_with_confidence(X)
        
        for vuln in vulnerability_predictions:
            vuln_type = vuln['vulnerability_type']
            
            # Use first prediction (we only have one sample)
            if detailed_predictions:
                pred = detailed_predictions[0]
                severity_predictions[vuln_type] = {
                    'severity': pred['severity'],
                    'confidence': pred['confidence'],
                    'cvss_score': pred.get('cvss_score', 5.0),
                    'severity_distribution': pred.get('severity_distribution', {})
                }
            else:
                severity_predictions[vuln_type] = self._heuristic_severity(vuln_type)
        
        return severity_predictions
    
    def _heuristic_severity(self, vuln_type: str) -> Dict:
        """Enhanced heuristic severity assignment with new vulnerability types"""
        
        severity_map = {
            # Critical
            'Remote Code Execution': ('critical', 9.5),
            'SQL Injection': ('critical', 9.0),
            'NoSQL Injection': ('critical', 8.5),
            'Authentication Bypass': ('critical', 8.5),
            'Deserialization': ('critical', 9.0),
            'Cloud Misconfiguration': ('critical', 8.5),
            'Account Takeover': ('critical', 9.0),
            
            # High
            'SSRF': ('high', 8.0),
            'Command Injection': ('high', 8.5),
            'JWT Vulnerabilities': ('high', 7.5),
            'XSS': ('high', 7.0),
            'IDOR': ('high', 7.5),
            'File Upload': ('high', 7.5),
            'GraphQL Introspection': ('high', 7.0),
            'Privilege Escalation': ('high', 8.0),
            'S3 Bucket Exposure': ('high', 7.5),
            'Broken Authorization': ('high', 7.5),
            'Path Traversal': ('high', 7.0),
            'XXE': ('high', 7.5),
            
            # Medium
            'CSRF': ('medium', 6.0),
            'Business Logic': ('medium', 6.5),
            'Information Disclosure': ('medium', 5.0),
            'Excessive Data Exposure': ('medium', 6.0),
            'Rate Limiting Issues': ('medium', 5.5),
            'API Abuse': ('medium', 6.0),
            'GraphQL Batching Abuse': ('medium', 6.0),
            'CORS Misconfiguration': ('medium', 6.0),
            'Session Fixation': ('medium', 6.5),
            'Broken Authentication': ('medium', 6.5),
            'Weak Cryptography': ('medium', 5.5),
            'Webhook Abuse': ('medium', 6.0),
            'Cache Poisoning': ('medium', 6.5),
            'Host Header Injection': ('medium', 6.0),
            
            # Low
            'Open Redirect': ('low', 4.0),
            'Clickjacking': ('low', 4.5),
            'Exposed Admin Interface': ('low', 5.0),
            'Race Condition': ('medium', 6.0),  # Can be high depending on impact
        }
        
        severity, cvss = severity_map.get(vuln_type, ('medium', 5.0))
        
        return {
            'severity': severity,
            'confidence': 0.7,
            'cvss_score': cvss,
            'severity_distribution': {severity: 0.7}
        }
    
    def _detect_chains(self, vulnerability_predictions: List[Dict]) -> List[Dict]:
        """Detect vulnerability chains"""
        
        if 'chain_detector' not in self.models:
            return []
        
        detector = self.models['chain_detector']
        
        # Get vulnerability types with probability > 0.3
        likely_vulns = [
            v['vulnerability_type'] 
            for v in vulnerability_predictions 
            if v['probability'] > 0.3
        ]
        
        # Detect chains
        chains = detector.detect_chains(likely_vulns)
        
        # Rank chains
        ranked_chains = detector.rank_chains(chains)
        
        return ranked_chains
    
    def _generate_test_strategy(self, vulnerability_predictions: List[Dict],
                                chain_predictions: List[Dict],
                                target_info: Dict) -> Dict:
        """Enhanced test strategy generation with new vulnerability types"""
        
        strategy = {
            'priority_targets': [],
            'time_allocation': {},
            'tools_recommended': [],
            'methodology': [],
            'technology_specific_tests': []
        }
        
        # Top 7 vulnerabilities (increased from 5)
        top_vulns = vulnerability_predictions[:7]
        
        total_priority = sum(v['priority'] for v in top_vulns)
        
        for vuln in top_vulns:
            vuln_type = vuln['vulnerability_type']
            
            # Time allocation (as percentage)
            time_pct = (vuln['priority'] / total_priority) * 100 if total_priority > 0 else 0
            
            target = {
                'vulnerability': vuln_type,
                'probability': vuln['probability'],
                'priority': vuln['priority'],
                'time_allocation': f"{time_pct:.1f}%",
                'test_cases': self._get_test_cases(vuln_type, target_info),
                'tools': self._get_recommended_tools(vuln_type),
                'endpoints_to_test': self._get_endpoints_to_test(vuln_type, target_info)
            }
            
            strategy['priority_targets'].append(target)
            strategy['time_allocation'][vuln_type] = time_pct
        
        # Add chain-specific strategies
        if chain_predictions:
            strategy['chain_testing'] = []
            for chain in chain_predictions[:5]:  # Top 5 chains
                strategy['chain_testing'].append({
                    'chain_name': chain['name'],
                    'exploitability_score': chain['exploitability_score'],
                    'steps': chain['steps'],
                    'required_vulns': chain['present_vulnerabilities'],
                    'partial': chain.get('partial', False)
                })
        
        # Overall tools
        all_tools = set()
        for target in strategy['priority_targets']:
            all_tools.update(target['tools'])
        strategy['tools_recommended'] = sorted(list(all_tools))
        
        # Enhanced methodology
        strategy['methodology'] = self._generate_methodology(target_info, vulnerability_predictions)
        
        # Technology-specific tests
        strategy['technology_specific_tests'] = self._generate_tech_specific_tests(target_info)
        
        return strategy
    
    def _get_test_cases(self, vuln_type: str, target_info: Dict) -> List[str]:
        """Enhanced test cases including new vulnerability types"""
        
        test_cases = {
            # Injection attacks
            'XSS': [
                'Test all input fields with XSS payloads',
                'Check for reflected XSS in URL parameters',
                'Test stored XSS in user-generated content',
                'Verify DOM-based XSS in client-side JavaScript',
                'Test XSS in HTTP headers and cookies'
            ],
            'SQL Injection': [
                'Test all input parameters with SQL injection payloads',
                'Check for error-based SQL injection',
                'Test blind SQL injection with time delays',
                'Verify boolean-based blind SQL injection',
                'Test second-order SQL injection'
            ],
            'NoSQL Injection': [
                'Test MongoDB operator injection ($where, $ne, $gt)',
                'Check for JSON injection in NoSQL queries',
                'Test authentication bypass via NoSQL injection',
                'Verify operator injection in aggregation pipelines',
                'Test JavaScript injection in $where clauses'
            ],
            'Command Injection': [
                'Test OS command injection in file processing',
                'Check for shell injection via user input',
                'Test blind command injection with time delays',
                'Verify command injection in subprocess calls',
                'Test injection in system() and exec() functions'
            ],
            'GraphQL Injection': [
                'Test SQL injection through GraphQL queries',
                'Check for command injection in GraphQL resolvers',
                'Test injection in GraphQL mutations',
                'Verify NoSQL injection through GraphQL'
            ],
            
            # Access control
            'IDOR': [
                'Enumerate object IDs and test access control',
                'Test sequential ID manipulation',
                'Verify cross-account access restrictions',
                'Test IDOR in API endpoints',
                'Check for IDOR in file access and downloads'
            ],
            'Broken Authorization': [
                'Test vertical privilege escalation',
                'Check horizontal privilege escalation',
                'Verify function-level access control',
                'Test role manipulation',
                'Check for missing authorization checks'
            ],
            'Privilege Escalation': [
                'Test role modification in requests',
                'Check for privilege elevation via parameter tampering',
                'Verify admin function access as regular user',
                'Test privilege inheritance flaws'
            ],
            
            # Authentication
            'JWT Vulnerabilities': [
                'Test JWT none algorithm acceptance',
                'Check for JWT signature bypass',
                'Test JWT algorithm confusion (RS256 to HS256)',
                'Verify JWT weak secret brute force',
                'Test JWT header parameter injection (kid, jku)'
            ],
            'Broken Authentication': [
                'Test weak password policies',
                'Check for default credentials',
                'Test brute force protection',
                'Verify credential stuffing protection',
                'Test password reset functionality'
            ],
            'Session Fixation': [
                'Test session ID regeneration after login',
                'Check for session fixation in authentication',
                'Verify session token randomness',
                'Test session hijacking vulnerabilities'
            ],
            'Authentication Bypass': [
                'Test direct URL access to protected resources',
                'Check for authentication logic flaws',
                'Test token validation bypass',
                'Verify multi-factor authentication bypass'
            ],
            
            # API Security
            'API Abuse': [
                'Test API endpoint enumeration',
                'Check for hidden/undocumented endpoints',
                'Test API scraping and mass data extraction',
                'Verify API versioning vulnerabilities'
            ],
            'Excessive Data Exposure': [
                'Test for over-fetching in API responses',
                'Check for sensitive data in responses',
                'Verify mass assignment vulnerabilities',
                'Test for unnecessary data exposure'
            ],
            'Rate Limiting Issues': [
                'Test for missing rate limits on authentication',
                'Check for rate limit bypass techniques',
                'Verify brute force protection',
                'Test for DoS via unlimited requests'
            ],
            'GraphQL Introspection': [
                'Query __schema to enumerate GraphQL schema',
                'Test introspection query execution',
                'Check for schema exposure',
                'Verify introspection disabled in production'
            ],
            'GraphQL Batching Abuse': [
                'Test deeply nested GraphQL queries',
                'Check for query complexity limits',
                'Test batched query execution',
                'Verify resource exhaustion via complex queries'
            ],
            
            # SSRF & Cloud
            'SSRF': [
                'Test URL parameters for SSRF',
                'Check cloud metadata endpoint access (169.254.169.254)',
                'Test DNS rebinding attacks',
                'Verify localhost/127.0.0.1 access restrictions',
                'Test SSRF via file upload and XXE'
            ],
            'Cloud Misconfiguration': [
                'Test access to cloud metadata endpoints',
                'Check for exposed IAM credentials',
                'Verify cloud storage bucket permissions',
                'Test for insecure cloud API access'
            ],
            'S3 Bucket Exposure': [
                'Enumerate S3 buckets via naming patterns',
                'Test public read/write access',
                'Check for bucket ACL misconfigurations',
                'Verify S3 bucket policies'
            ],
            
            # Business Logic
            'Business Logic': [
                'Test race conditions in critical operations',
                'Check price/quantity manipulation',
                'Verify workflow bypass vulnerabilities',
                'Test discount/coupon abuse',
                'Check for parallel session handling flaws'
            ],
            'Race Condition': [
                'Test concurrent requests to critical endpoints',
                'Check for TOCTOU vulnerabilities',
                'Verify transaction atomicity',
                'Test parallel processing flaws',
                'Check for double spending vulnerabilities'
            ],
            
            # Configuration
            'CORS Misconfiguration': [
                'Test for wildcard Access-Control-Allow-Origin',
                'Check for null origin acceptance',
                'Verify credentials exposure via CORS',
                'Test CORS policy bypass'
            ],
            'Exposed Admin Interface': [
                'Enumerate admin panels and interfaces',
                'Test default admin credentials',
                'Check for publicly accessible admin endpoints',
                'Verify admin panel protection'
            ],
            'Weak Cryptography': [
                'Test for weak hashing algorithms (MD5, SHA1)',
                'Check for hardcoded encryption keys',
                'Verify TLS/SSL configuration',
                'Test for predictable random number generation'
            ],
            
            # Web Attacks
            'CSRF': [
                'Test state-changing operations without CSRF tokens',
                'Verify CSRF token validation',
                'Check for CSRF token reuse',
                'Test CSRF in API endpoints',
                'Verify SameSite cookie attributes'
            ],
            'Clickjacking': [
                'Test for missing X-Frame-Options header',
                'Check for missing Content-Security-Policy frame-ancestors',
                'Verify iframe protection',
                'Test for UI redressing vulnerabilities'
            ],
            'Open Redirect': [
                'Test unvalidated redirects in logout/login flows',
                'Check for redirect parameter manipulation',
                'Verify URL validation',
                'Test for phishing via open redirects'
            ],
            'Host Header Injection': [
                'Test Host header manipulation in password resets',
                'Check for cache poisoning via Host header',
                'Verify Host header validation',
                'Test for routing-based SSRF'
            ],
            'Cache Poisoning': [
                'Test cache key manipulation',
                'Check for header-based cache poisoning',
                'Verify cache behavior with Host header',
                'Test for XSS via cache poisoning'
            ],
            
            # Webhooks
            'Webhook Abuse': [
                'Test SSRF via webhook URLs',
                'Check for webhook validation bypass',
                'Verify webhook authentication',
                'Test for internal network access via webhooks'
            ],
        }
        
        return test_cases.get(vuln_type, ['Perform standard security testing for this vulnerability'])
    
    def _get_recommended_tools(self, vuln_type: str) -> List[str]:
        """Enhanced tool recommendations for new vulnerability types"""
        
        tools = {
            'XSS': ['Dalfox', 'XSStrike', 'Burp Suite', 'OWASP ZAP'],
            'SQL Injection': ['SQLMap', 'Burp Suite', 'NoSQLMap'],
            'NoSQL Injection': ['NoSQLMap', 'Burp Suite', 'mongoshell'],
            'Command Injection': ['Commix', 'Burp Suite'],
            'GraphQL Injection': ['GraphQL Voyager', 'Burp Suite', 'InQL'],
            
            'IDOR': ['Burp Suite', 'Custom Scripts', 'Postman', 'Autorize'],
            'Broken Authorization': ['Burp Suite', 'Autorize', 'AuthMatrix'],
            'Privilege Escalation': ['Burp Suite', 'Custom Scripts'],
            
            'JWT Vulnerabilities': ['jwt_tool', 'Burp Suite JWT Editor', 'JWTCracker'],
            'Broken Authentication': ['Burp Suite', 'Hydra', 'Medusa'],
            'Session Fixation': ['Burp Suite', 'OWASP ZAP'],
            'Authentication Bypass': ['Burp Suite', 'Custom Scripts'],
            
            'API Abuse': ['Postman', 'Burp Suite', 'Arjun', 'Kiterunner'],
            'Excessive Data Exposure': ['Burp Suite', 'Postman', 'GraphQL Voyager'],
            'Rate Limiting Issues': ['Burp Suite Intruder', 'Custom Scripts'],
            'GraphQL Introspection': ['GraphQL Voyager', 'InQL', 'GraphiQL'],
            'GraphQL Batching Abuse': ['GraphQL Voyager', 'Custom Scripts'],
            
            'SSRF': ['SSRFmap', 'Interactsh', 'Burp Collaborator', 'Gopherus'],
            'Cloud Misconfiguration': ['CloudMapper', 'ScoutSuite', 'Prowler'],
            'S3 Bucket Exposure': ['S3Scanner', 'AWSBucketDump', 'CloudBrute'],
            
            'Business Logic': ['Burp Suite', 'Custom Scripts'],
            'Race Condition': ['Burp Suite Turbo Intruder', 'Custom Scripts'],
            'Webhook Abuse': ['Burp Suite', 'Webhook.site', 'Interactsh'],
            
            'CORS Misconfiguration': ['Burp Suite', 'CORScanner'],
            'Exposed Admin Interface': ['Burp Suite', 'DirBuster', 'Gobuster'],
            'Weak Cryptography': ['Burp Suite', 'testssl.sh', 'SSLScan'],
            
            'CSRF': ['Burp Suite', 'OWASP ZAP'],
            'Clickjacking': ['Burp Suite', 'ClickjackThis'],
            'Open Redirect': ['Burp Suite', 'OWASP ZAP'],
            'Host Header Injection': ['Burp Suite', 'Host Header Attack'],
            'Cache Poisoning': ['Burp Suite', 'Web Cache Vulnerability Scanner'],
            
            'File Upload': ['Burp Suite', 'Upload Scanner', 'fuxploider'],
            'Path Traversal': ['Burp Suite', 'dotdotpwn'],
            'XXE': ['Burp Suite', 'XXEinjector'],
            'Deserialization': ['ysoserial', 'Burp Suite'],
            'Remote Code Execution': ['Metasploit', 'Custom Exploits'],
        }
        
        return tools.get(vuln_type, ['Burp Suite', 'OWASP ZAP', 'Nuclei'])
    
    def _get_endpoints_to_test(self, vuln_type: str, 
                               target_info: Dict) -> List[str]:
        """Get specific endpoints to test for vulnerability type"""
        
        endpoints = target_info.get('endpoints', ['/'])
        
        # Vulnerability-specific endpoint filtering
        endpoint_filters = {
            'IDOR': lambda e: any(x in e.lower() for x in ['api', 'user', 'profile', 'account', '/id/']),
            'SQL Injection': lambda e: any(x in e.lower() for x in ['search', 'query', 'id=', 'filter']),
            'NoSQL Injection': lambda e: any(x in e.lower() for x in ['search', 'query', 'filter', 'api']),
            'XSS': lambda e: any(x in e.lower() for x in ['comment', 'message', 'search', 'post']),
            'GraphQL Introspection': lambda e: 'graphql' in e.lower(),
            'API Abuse': lambda e: '/api/' in e.lower(),
            'JWT Vulnerabilities': lambda e: any(x in e.lower() for x in ['auth', 'login', 'token']),
        }
        
        if vuln_type in endpoint_filters:
            filtered = [e for e in endpoints if endpoint_filters[vuln_type](e)]
            return filtered[:5] if filtered else endpoints[:5]
        
        return endpoints[:5] if len(endpoints) > 5 else endpoints
    
    def _generate_methodology(self, target_info: Dict, 
                             vulnerability_predictions: List[Dict]) -> List[str]:
        """Generate enhanced testing methodology"""
        
        methodology = [
            'Start with reconnaissance and technology fingerprinting',
            'Run automated scanners (Nuclei, Burp Suite, OWASP ZAP)',
            'Focus manual testing on high-probability vulnerabilities',
        ]
        
        # Add GraphQL-specific steps if relevant
        has_graphql = target_info.get('has_graphql') or any(
            v['vulnerability_type'] in ['GraphQL Introspection', 'GraphQL Batching Abuse']
            for v in vulnerability_predictions[:5]
        )
        
        if has_graphql:
            methodology.append('Enumerate GraphQL schema via introspection queries')
            methodology.append('Test GraphQL-specific vulnerabilities (batching, depth limits)')
        
        # Add API-specific steps if relevant
        has_api = target_info.get('has_api')
        if has_api:
            methodology.append('Enumerate API endpoints and test for IDOR/broken access control')
            methodology.append('Test API for rate limiting and excessive data exposure')
        
        # Add cloud-specific steps if relevant
        cloud_provider = target_info.get('cloud_provider')
        if cloud_provider:
            methodology.append(f'Test for {cloud_provider} cloud misconfigurations and metadata access')
        
        methodology.extend([
            'Test for vulnerability chains systematically',
            'Document all findings with clear reproduction steps',
            'Verify exploitability before reporting'
        ])
        
        return methodology
    
    def _generate_tech_specific_tests(self, target_info: Dict) -> List[Dict]:
        """Generate technology-specific test recommendations"""
        
        tech_stack = target_info.get('technology_stack', [])
        tests = []
        
        # React/Frontend frameworks
        if any(fw in tech_stack for fw in ['React', 'Angular', 'Vue.js']):
            tests.append({
                'technology': 'Frontend Framework (React/Angular/Vue)',
                'tests': [
                    'Test for client-side XSS and DOM-based vulnerabilities',
                    'Check for exposed API keys in JavaScript bundles',
                    'Test for sensitive data in localStorage/sessionStorage',
                    'Verify proper CSP implementation'
                ]
            })
        
        # MongoDB/NoSQL
        if any(db in tech_stack for db in ['MongoDB', 'Cassandra', 'CouchDB']):
            tests.append({
                'technology': 'NoSQL Database',
                'tests': [
                    'Test NoSQL injection via operator manipulation',
                    'Check for exposed database endpoints',
                    'Test for authentication bypass via NoSQL injection',
                    'Verify proper input sanitization'
                ]
            })
        
        # GraphQL
        if 'GraphQL' in tech_stack or target_info.get('has_graphql'):
            tests.append({
                'technology': 'GraphQL',
                'tests': [
                    'Test if introspection is enabled in production',
                    'Check for query depth/complexity limits',
                    'Test for batching abuse and DoS',
                    'Verify proper authorization on queries/mutations'
                ]
            })
        
        # AWS/Cloud
        if target_info.get('cloud_provider') == 'AWS':
            tests.append({
                'technology': 'AWS Cloud',
                'tests': [
                    'Test for SSRF to metadata endpoint (169.254.169.254)',
                    'Check for exposed S3 buckets',
                    'Test for IAM credential exposure',
                    'Verify proper cloud security group configurations'
                ]
            })
        
        # Node.js
        if 'Node.js' in tech_stack:
            tests.append({
                'technology': 'Node.js',
                'tests': [
                    'Test for prototype pollution',
                    'Check for command injection in child_process',
                    'Test for path traversal in file operations',
                    'Verify proper dependency security (npm audit)'
                ]
            })
        
        return tests
    
    def _calculate_risk_score(self, vulnerability_predictions: List[Dict],
                              severity_predictions: Dict,
                              chain_predictions: List[Dict]) -> float:
        """Enhanced risk score calculation"""
        
        # Weighted vulnerability score
        vuln_score = 0
        for vuln in vulnerability_predictions[:15]:  # Top 15 vulnerabilities
            vuln_type = vuln['vulnerability_type']
            prob = vuln['probability']
            
            # Get severity
            sev_info = severity_predictions.get(vuln_type, {})
            cvss = sev_info.get('cvss_score', 5.0)
            
            # Weighted contribution (probability × CVSS)
            vuln_score += prob * cvss
        
        # Normalize by number of vulnerabilities
        vuln_score = vuln_score / 15 if vuln_score > 0 else 0
        
        # Chain multiplier (enhanced)
        chain_multiplier = 1.0
        if chain_predictions:
            complete_chains = [c for c in chain_predictions if not c.get('partial', False)]
            
            # Critical chains add more weight
            critical_chains = sum(1 for c in complete_chains if c['severity'] == 'critical')
            high_chains = sum(1 for c in complete_chains if c['severity'] == 'high')
            
            chain_multiplier = 1.0 + (critical_chains * 0.15) + (high_chains * 0.08)
        
        # Final score
        risk_score = min(vuln_score * chain_multiplier, 10.0)
        
        return round(risk_score, 2)
    
    def _categorize_risk(self, risk_score: float) -> str:
        """Categorize risk level"""
        
        if risk_score >= 8.0:
            return 'critical'
        elif risk_score >= 6.0:
            return 'high'
        elif risk_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, vulnerability_predictions: List[Dict],
                                  chain_predictions: List[Dict],
                                  target_info: Dict) -> List[str]:
        """Enhanced recommendations with technology-specific advice"""
        
        recommendations = []
        
        # Top vulnerability recommendations
        if vulnerability_predictions:
            top_vuln = vulnerability_predictions[0]
            recommendations.append(
                f"🎯 PRIORITY: Test for {top_vuln['vulnerability_type']} "
                f"(probability: {top_vuln['probability']:.1%}, priority: {top_vuln['priority']}/5)"
            )
        
        # Chain recommendations
        if chain_predictions:
            complete_chains = [c for c in chain_predictions if not c.get('partial', False)]
            if complete_chains:
                top_chain = complete_chains[0]
                recommendations.append(
                    f"⚠️  CRITICAL CHAIN: {top_chain['name']} detected - "
                    f"Test systematically for: {', '.join(top_chain['present_vulnerabilities'])}"
                )
        
        # Technology-specific recommendations
        tech_stack = target_info.get('technology_stack', [])
        
        if 'GraphQL' in tech_stack or target_info.get('has_graphql'):
            recommendations.append(
                "🔍 GraphQL detected - Immediately check introspection status and query complexity limits"
            )
        
        if any(db in tech_stack for db in ['MongoDB', 'Cassandra']):
            recommendations.append(
                "💾 NoSQL database detected - Prioritize NoSQL injection testing with operator manipulation"
            )
        
        if target_info.get('cloud_provider'):
            cloud = target_info['cloud_provider']
            recommendations.append(
                f"☁️  {cloud} cloud environment - Test for SSRF to metadata endpoints and exposed storage"
            )
        
        if any(fw in tech_stack for fw in ['React', 'Angular', 'Vue.js']):
            recommendations.append(
                "⚛️  Frontend framework detected - Check for client-side vulnerabilities and exposed secrets"
            )
        
        # Generic best practices
        recommendations.extend([
            "📋 Start with automated scanning, then manual testing on high-priority targets",
            "📝 Document all findings with clear PoC and reproduction steps",
            "✅ Verify exploitability and business impact before reporting"
        ])
        
        return recommendations
    
    def _generate_tech_insights(self, target_info: Dict) -> Dict:
        """Generate technology-specific security insights"""
        
        tech_stack = target_info.get('technology_stack', [])
        insights = {
            'attack_surface': [],
            'common_vulnerabilities': [],
            'security_considerations': []
        }
        
        # Analyze attack surface based on tech stack
        if any(fw in tech_stack for fw in ['React', 'Angular', 'Vue.js']):
            insights['attack_surface'].append('Client-side JavaScript application')
            insights['common_vulnerabilities'].extend(['XSS', 'CORS Misconfiguration'])
        
        if target_info.get('has_api'):
            insights['attack_surface'].append('REST/GraphQL API endpoints')
            insights['common_vulnerabilities'].extend(['IDOR', 'Excessive Data Exposure'])
        
        if target_info.get('cloud_provider'):
            insights['attack_surface'].append('Cloud infrastructure')
            insights['common_vulnerabilities'].extend(['Cloud Misconfiguration', 'SSRF'])
        
        # Security considerations
        if 'Node.js' in tech_stack:
            insights['security_considerations'].append(
                'Node.js: Check for prototype pollution and command injection'
            )
        
        if any(db in tech_stack for db in ['MongoDB', 'Cassandra']):
            insights['security_considerations'].append(
                'NoSQL: Test operator injection and authentication bypass'
            )
        
        return insights
    
    def _calculate_priority(self, probability: float, vuln_type: str) -> int:
        """Enhanced priority calculation"""
        
        # Base priority from probability
        if probability >= 0.8:
            base_priority = 5
        elif probability >= 0.6:
            base_priority = 4
        elif probability >= 0.4:
            base_priority = 3
        elif probability >= 0.2:
            base_priority = 2
        else:
            base_priority = 1
        
        # Adjust for high-impact vulnerabilities
        critical_vulns = [
            'Remote Code Execution', 'SQL Injection', 'NoSQL Injection',
            'Authentication Bypass', 'Cloud Misconfiguration', 'Deserialization',
            'Account Takeover', 'Privilege Escalation'
        ]
        
        if vuln_type in critical_vulns and base_priority < 5:
            base_priority += 1
        
        return min(base_priority, 5)
    
    def _categorize_confidence(self, agreement_score: float) -> str:
        """Categorize confidence level"""
        
        if agreement_score >= 0.9:
            return 'very_high'
        elif agreement_score >= 0.7:
            return 'high'
        elif agreement_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def batch_analyze(self, targets: List[Dict]) -> List[Dict]:
        """Analyze multiple targets"""
        
        results = []
        
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Analyzing {target.get('domain', 'Unknown')}")
            try:
                result = self.analyze_target(target)
                results.append(result)
            except Exception as e:
                print(f"Error analyzing {target.get('domain')}: {e}")
                results.append({
                    'target': target.get('domain'),
                    'error': str(e)
                })
        
        return results
