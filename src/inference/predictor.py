"""Threat prediction engine - Production Implementation"""

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
from src.collectors.tech_detector import TechnologyDetector
from src.collectors.data_sources import VulnerabilityReport


class ThreatPredictor:
    """
    Production inference engine for vulnerability prediction
    
    Features:
    - Loads trained models
    - Predicts vulnerabilities with confidence scores
    - Detects attack chains
    - Generates test strategies
    - Produces actionable recommendations
    """
    
    def __init__(self, models_dir: str = "data/models"):
        self.models_dir = Path(models_dir)
        self.models = {}
        self.feature_engineer = None
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
        
        Args:
            target_info: Dictionary with target information
                {
                    'domain': 'example.com',
                    'company_name': 'Example Corp',
                    'technology_stack': ['React', 'Node.js', 'PostgreSQL'],
                    'endpoints': ['/api/users', '/api/posts'],
                    'auth_required': True,
                    'has_api': True,
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
            tech_detector = TechnologyDetector()
            tech_info = tech_detector.detect(target_info['domain'])
            target_info['technology_stack'] = tech_info['technologies']
            print(f"Auto-detected technologies: {tech_info['technologies']}")
        
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
            'metadata': {
                'model_version': self.metadata.get('model_versions', {}),
                'training_date': self.metadata.get('training_date', 'Unknown')
            }
        }
        
        print(f"\n✓ Analysis complete!")
        print(f"Risk Score: {risk_score}/10 ({results['risk_level'].upper()})")
        print(f"Top Vulnerabilities: {len([v for v in vulnerability_predictions if v['probability'] > 0.5])}")
        print(f"Chains Detected: {len(chain_predictions)}")
        
        return results
    
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
        """Predict vulnerability types with probabilities"""
        
        if 'vulnerability_predictor' not in self.models:
            print("⚠ VulnerabilityPredictor not loaded - using heuristics")
            return self._heuristic_vulnerability_prediction(target_info)
        
        predictor = self.models['vulnerability_predictor']
        
        # Get top-k predictions
        top_predictions = predictor.predict_top_k(X, k=10, method='averaging')
        
        # Get model agreement
        agreement_scores = predictor.get_model_agreement(X)
        
        results = []
        
        for vuln_type, probability in top_predictions[0]:
            # Calculate priority (1-5 scale)
            priority = self._calculate_priority(probability, vuln_type)
            
            # Determine confidence level
            confidence = self._categorize_confidence(agreement_scores[0] if len(agreement_scores) > 0 else 0.7)
            
            results.append({
                'vulnerability_type': vuln_type,
                'probability': float(probability),
                'confidence': confidence,
                'priority': priority,
                'model_agreement': float(agreement_scores[0] if len(agreement_scores) > 0 else 0.7)
            })
        
        return results
    
    def _heuristic_vulnerability_prediction(self, target_info: Dict) -> List[Dict]:
        """Fallback heuristic-based vulnerability prediction"""
        
        tech_stack = target_info.get('technology_stack', [])
        has_api = target_info.get('has_api', False)
        auth_required = target_info.get('auth_required', False)
        
        predictions = []
        
        # Technology-based heuristics
        if any(fw in tech_stack for fw in ['React', 'Angular', 'Vue.js']):
            predictions.append({
                'vulnerability_type': 'XSS',
                'probability': 0.75,
                'confidence': 'medium',
                'priority': 4
            })
        
        if any(db in tech_stack for db in ['MySQL', 'PostgreSQL', 'MongoDB']):
            predictions.append({
                'vulnerability_type': 'SQL Injection',
                'probability': 0.65,
                'confidence': 'medium',
                'priority': 4
            })
        
        if has_api:
            predictions.extend([
                {
                    'vulnerability_type': 'IDOR',
                    'probability': 0.70,
                    'confidence': 'high',
                    'priority': 4
                },
                {
                    'vulnerability_type': 'SSRF',
                    'probability': 0.45,
                    'confidence': 'medium',
                    'priority': 3
                }
            ])
        
        if auth_required:
            predictions.extend([
                {
                    'vulnerability_type': 'Authentication Bypass',
                    'probability': 0.55,
                    'confidence': 'medium',
                    'priority': 3
                },
                {
                    'vulnerability_type': 'CSRF',
                    'probability': 0.40,
                    'confidence': 'medium',
                    'priority': 2
                }
            ])
        
        # Always add common vulnerabilities
        predictions.extend([
            {
                'vulnerability_type': 'Business Logic',
                'probability': 0.60,
                'confidence': 'medium',
                'priority': 4
            },
            {
                'vulnerability_type': 'Information Disclosure',
                'probability': 0.50,
                'confidence': 'low',
                'priority': 2
            }
        ])
        
        # Sort by probability
        predictions.sort(key=lambda x: x['probability'], reverse=True)
        
        return predictions[:10]
    
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
        """Heuristic severity assignment"""
        
        severity_map = {
            'Remote Code Execution': ('critical', 9.5),
            'SQL Injection': ('critical', 9.0),
            'Authentication Bypass': ('critical', 8.5),
            'SSRF': ('high', 8.0),
            'XSS': ('high', 7.0),
            'IDOR': ('high', 7.5),
            'File Upload': ('high', 7.5),
            'Deserialization': ('critical', 9.0),
            'CSRF': ('medium', 6.0),
            'Business Logic': ('medium', 6.5),
            'Information Disclosure': ('medium', 5.0),
            'Open Redirect': ('low', 4.0)
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
        """Generate comprehensive testing strategy"""
        
        strategy = {
            'priority_targets': [],
            'time_allocation': {},
            'tools_recommended': [],
            'methodology': []
        }
        
        # Top 5 vulnerabilities
        top_vulns = vulnerability_predictions[:5]
        
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
            for chain in chain_predictions[:3]:
                strategy['chain_testing'].append({
                    'chain_name': chain['name'],
                    'steps': chain['steps'],
                    'required_vulns': chain['vulns']
                })
        
        # Overall tools
        all_tools = set()
        for target in strategy['priority_targets']:
            all_tools.update(target['tools'])
        strategy['tools_recommended'] = sorted(list(all_tools))
        
        # Methodology
        strategy['methodology'] = [
            'Start with automated scanning using recommended tools',
            'Focus manual testing on high-priority vulnerabilities',
            'Test for vulnerability chains systematically',
            'Document all findings with PoC',
            'Verify exploitability before reporting'
        ]
        
        return strategy
    
    def _get_test_cases(self, vuln_type: str, target_info: Dict) -> List[str]:
        """Get specific test cases for vulnerability type"""
        
        test_cases = {
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
            'IDOR': [
                'Enumerate object IDs and test access control',
                'Test sequential ID manipulation',
                'Verify cross-account access restrictions',
                'Test IDOR in API endpoints',
                'Check for IDOR in file access'
            ],
            'SSRF': [
                'Test URL parameters for SSRF',
                'Attempt to access internal network resources',
                'Check for cloud metadata endpoint access (169.254.169.254)',
                'Test DNS rebinding attacks',
                'Verify localhost/127.0.0.1 access restrictions'
            ],
            'Authentication Bypass': [
                'Test password reset functionality',
                'Verify session management',
                'Check for direct object reference in auth',
                'Test authentication logic flaws',
                'Verify JWT token validation'
            ],
            'CSRF': [
                'Test state-changing operations without CSRF tokens',
                'Verify token validation',
                'Check for token reuse vulnerabilities',
                'Test CSRF in API endpoints',
                'Verify SameSite cookie attributes'
            ],
            'Business Logic': [
                'Test race conditions in critical operations',
                'Verify price/quantity manipulation',
                'Check for workflow bypass',
                'Test parallel session handling',
                'Verify discount/coupon logic'
            ]
        }
        
        return test_cases.get(vuln_type, ['Perform standard security testing'])
    
    def _get_recommended_tools(self, vuln_type: str) -> List[str]:
        """Get recommended tools for vulnerability type"""
        
        tools = {
            'XSS': ['Dalfox', 'XSStrike', 'Burp Suite', 'OWASP ZAP'],
            'SQL Injection': ['SQLMap', 'Burp Suite', 'NoSQLMap'],
            'IDOR': ['Burp Suite', 'Custom Scripts', 'Postman'],
            'SSRF': ['SSRFmap', 'Interactsh', 'Burp Collaborator'],
            'Authentication Bypass': ['Burp Suite', 'Custom Scripts'],
            'CSRF': ['Burp Suite', 'OWASP ZAP'],
            'Business Logic': ['Burp Suite', 'Custom Scripts'],
            'SSRF': ['SSRFmap', 'Burp Suite'],
            'File Upload': ['Burp Suite', 'Upload Scanner'],
            'Remote Code Execution': ['Metasploit', 'Custom Exploits']
        }
        
        return tools.get(vuln_type, ['Burp Suite', 'OWASP ZAP', 'Nuclei'])
    
    def _get_endpoints_to_test(self, vuln_type: str, 
                               target_info: Dict) -> List[str]:
        """Get specific endpoints to test"""
        
        endpoints = target_info.get('endpoints', ['/'])
        
        # Vulnerability-specific endpoint suggestions
        if vuln_type == 'IDOR':
            return [e for e in endpoints if 'api' in e or 'user' in e or 'profile' in e]
        elif vuln_type == 'SQL Injection':
            return [e for e in endpoints if 'search' in e or 'query' in e or 'id=' in e]
        elif vuln_type == 'XSS':
            return [e for e in endpoints if 'comment' in e or 'message' in e or 'search' in e]
        
        return endpoints[:5] if len(endpoints) > 5 else endpoints
    
    def _calculate_risk_score(self, vulnerability_predictions: List[Dict],
                              severity_predictions: Dict,
                              chain_predictions: List[Dict]) -> float:
        """Calculate overall risk score (0-10)"""
        
        # Weighted vulnerability score
        vuln_score = 0
        for vuln in vulnerability_predictions[:10]:
            vuln_type = vuln['vulnerability_type']
            prob = vuln['probability']
            
            # Get severity
            sev_info = severity_predictions.get(vuln_type, {})
            cvss = sev_info.get('cvss_score', 5.0)
            
            # Weighted contribution
            vuln_score += prob * cvss
        
        # Normalize by number of vulnerabilities
        vuln_score = vuln_score / 10 if vuln_score > 0 else 0
        
        # Chain multiplier
        chain_multiplier = 1.0
        if chain_predictions:
            # Add 10% for each critical chain
            critical_chains = sum(1 for c in chain_predictions if c['severity'] == 'critical')
            chain_multiplier = 1.0 + (critical_chains * 0.1)
        
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
        """Generate actionable recommendations"""
        
        recommendations = []
        
        # Top vulnerability
        if vulnerability_predictions:
            top_vuln = vulnerability_predictions[0]
            recommendations.append(
                f"Prioritize testing for {top_vuln['vulnerability_type']} "
                f"(probability: {top_vuln['probability']:.1%})"
            )
        
        # Chains
        if chain_predictions:
            top_chain = chain_predictions[0]
            recommendations.append(
                f"Critical chain detected: {top_chain['name']} - "
                f"Test for {', '.join(top_chain['vulns'])}"
            )
        
        # Technology-specific
        tech_stack = target_info.get('technology_stack', [])
        if 'React' in tech_stack or 'Angular' in tech_stack:
            recommendations.append(
                "Frontend framework detected - focus on client-side vulnerabilities (XSS, DOM-based attacks)"
            )
        
        if any(db in tech_stack for db in ['MySQL', 'PostgreSQL']):
            recommendations.append(
                "SQL database detected - thoroughly test for SQL injection"
            )
        
        # Generic best practices
        recommendations.extend([
            "Start with automated scanning, then proceed to manual testing",
            "Document all findings with clear reproduction steps",
            "Verify exploitability before submitting reports"
        ])
        
        return recommendations
    
    def _calculate_priority(self, probability: float, vuln_type: str) -> int:
        """Calculate priority (1-5 scale)"""
        
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
        
        # Adjust for vulnerability type severity
        high_impact_vulns = ['Remote Code Execution', 'SQL Injection', 
                            'Authentication Bypass', 'SSRF']
        
        if vuln_type in high_impact_vulns and base_priority < 5:
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
