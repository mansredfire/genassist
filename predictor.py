# src/inference/predictor.py

import pickle
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
from pathlib import Path
import json

class ThreatPredictor:
    """
    Production inference engine for vulnerability prediction
    """
    
    def __init__(self, models_dir: str = "data/models"):
        self.models_dir = Path(models_dir)
        self.models = {}
        self.feature_engineer = None
        self.feature_names = []
        self.load_models()
    
    def load_models(self):
        """Load all trained models"""
        
        # Load vulnerability predictor
        with open(self.models_dir / 'vulnerability_predictor.pkl', 'rb') as f:
            self.models['vulnerability_predictor'] = pickle.load(f)
        
        # Load severity predictor
        with open(self.models_dir / 'severity_predictor.pkl', 'rb') as f:
            self.models['severity_predictor'] = pickle.load(f)
        
        # Load chain detector
        with open(self.models_dir / 'chain_detector.pkl', 'rb') as f:
            self.models['chain_detector'] = pickle.load(f)
        
        # Load feature engineer
        with open(self.models_dir / 'feature_engineer.pkl', 'rb') as f:
            self.feature_engineer = pickle.load(f)
        
        # Load feature names
        with open(self.models_dir / 'feature_names.json', 'r') as f:
            self.feature_names = json.load(f)
    
    def analyze_target(self, target_info: Dict) -> Dict:
        """
        Analyze a target and predict likely vulnerabilities
        
        Args:
            target_info: Dictionary containing:
                - domain: str
                - technology_stack: List[str]
                - company_name: str
                - endpoints: List[str]
                - authentication_type: str
                - additional_info: Dict
        
        Returns:
            Dictionary with predictions and recommendations
        """
        
        # Convert target info to features
        features = self._prepare_features(target_info)
        
        # Predict vulnerability types
        vuln_predictions = self._predict_vulnerabilities(features)
        
        # Predict severity for each vulnerability type
        severity_predictions = self._predict_severities(features, vuln_predictions)
        
        # Detect potential chains
        chains = self._detect_chains(vuln_predictions)
        
        # Generate test strategy
        test_strategy = self._generate_test_strategy(
            vuln_predictions, 
            severity_predictions, 
            chains
        )
        
        # Compile results
        results = {
            'target': target_info['domain'],
            'analysis_timestamp': pd.Timestamp.now().isoformat(),
            'vulnerability_predictions': vuln_predictions,
            'severity_predictions': severity_predictions,
            'chain_predictions': chains,
            'test_strategy': test_strategy,
            'risk_score': self._calculate_risk_score(vuln_predictions, severity_predictions),
            'recommendations': self._generate_recommendations(vuln_predictions, chains)
        }
        
        return results
    
    def _prepare_features(self, target_info: Dict) -> pd.DataFrame:
        """Convert target info to feature vector"""
        
        # Create a mock vulnerability report for feature extraction
        mock_report = VulnerabilityReport(
            report_id='prediction',
            platform='prediction',
            target_domain=target_info['domain'],
            target_company=target_info.get('company_name', ''),
            target_program='',
            vulnerability_type='',  # To be predicted
            severity='',  # To be predicted
            cvss_score=0.0,
            technology_stack=target_info.get('technology_stack', []),
            endpoint=target_info.get('endpoints', [''])[0] if target_info.get('endpoints') else '',
            http_method='GET',
            vulnerability_location=target_info.get('location', 'web'),
            description='',
            steps_to_reproduce=[],
            impact='',
            remediation='',
            reported_date=pd.Timestamp.now(),
            disclosed_date=pd.Timestamp.now(),
            bounty_amount=0.0,
            researcher_reputation=0,
            authentication_required=target_info.get('auth_required', False),
            privileges_required=target_info.get('privilege_level', 'none'),
            user_interaction=False,
            complexity='medium',
            tags=[],
            owasp_category='',
            cwe_id=0
        )
        
        # Extract features
        features = self.feature_engineer._extract_features(mock_report)
        features_df = pd.DataFrame([features])
        
        # Ensure all expected features are present
        for feature in self.feature_names:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        return features_df[self.feature_names]
    
    def _predict_vulnerabilities(self, features: pd.DataFrame) -> List[Dict]:
        """Predict vulnerability types and probabilities"""
        
        vuln_predictor = self.models['vulnerability_predictor']
        
        # Get ensemble predictions
        _, probabilities = vuln_predictor.ensemble_predict(features, method='averaging')
        
        # Get class labels
        classes = vuln_predictor.models['random_forest'].classes_
        
        # Create predictions list with probabilities
        predictions = []
        for idx, vuln_type in enumerate(classes):
            prob = probabilities[0][idx]
            if prob > 0.1:  # Only include if probability > 10%
                predictions.append({
                    'vulnerability_type': vuln_type,
                    'probability': float(prob),
                    'confidence': self._calculate_confidence(prob),
                    'priority': self._calculate_priority(prob)
                })
        
        # Sort by probability
        predictions.sort(key=lambda x: x['probability'], reverse=True)
        
        return predictions
    
    def _predict_severities(self, features: pd.DataFrame, 
                           vuln_predictions: List[Dict]) -> Dict:
        """Predict severity for each vulnerability type"""
        
        severity_predictor = self.models.get('severity_predictor')
        
        if not severity_predictor:
            return {}
        
        severities = {}
        
        for vuln in vuln_predictions:
            # Modify features to reflect this specific vulnerability
            vuln_features = features.copy()
            # Predict severity
            _, severity_probs = severity_predictor.predict(vuln_features)
            
            severity_classes = ['low', 'medium', 'high', 'critical']
            severity_idx = np.argmax(severity_probs[0])
            
            severities[vuln['vulnerability_type']] = {
                'severity': severity_classes[severity_idx],
                'confidence': float(severity_probs[0][severity_idx])
            }
        
        return severities
    
    def _detect_chains(self, vuln_predictions: List[Dict]) -> List[Dict]:
        """Detect potential vulnerability chains"""
        
        chain_detector = self.models['chain_detector']
        
        # Get high-probability vulnerabilities
        likely_vulns = [v['vulnerability_type'] for v in vuln_predictions 
                       if v['probability'] > 0.3]
        
        # Detect chains
        chains = chain_detector.detect_chains(likely_vulns)
        
        # Calculate chain scores
        for chain in chains:
            chain['exploitability_score'] = chain_detector.calculate_chain_score(chain)
        
        return chains
    
    def _generate_test_strategy(self, vuln_predictions: List[Dict],
                                severity_predictions: Dict,
                                chains: List[Dict]) -> Dict:
        """Generate testing strategy based on predictions"""
        
        strategy = {
            'priority_targets': [],
            'test_cases': [],
            'recommended_tools': [],
            'time_allocation': {}
        }
        
        # Priority targets (top 5 vulnerabilities)
        for vuln in vuln_predictions[:5]:
            vuln_type = vuln['vulnerability_type']
            severity_info = severity_predictions.get(vuln_type, {})
            
            priority_target = {
                'vulnerability': vuln_type,
                'probability': vuln['probability'],
                'severity': severity_info.get('severity', 'unknown'),
                'priority_score': vuln['probability'] * self._severity_multiplier(
                    severity_info.get('severity', 'medium')
                ),
                'test_cases': self._get_test_cases(vuln_type),
                'tools': self._get_recommended_tools(vuln_type)
            }
            
            strategy['priority_targets'].append(priority_target)
        
        # Add chain-specific tests
        for chain in chains:
            chain_tests = {
                'chain_name': chain['name'],
                'vulnerabilities': chain['vulns'],
                'test_sequence': self._generate_chain_test_sequence(chain),
                'tools': self._get_chain_tools(chain)
            }
            strategy['test_cases'].append(chain_tests)
        
        # Time allocation recommendation
        total_time = 100  # percentage
        for idx, target in enumerate(strategy['priority_targets']):
            # Allocate more time to higher priority vulnerabilities
            time_percent = (total_time / (idx + 1)) / sum(1/(i+1) for i in range(len(strategy['priority_targets'])))
            strategy['time_allocation'][target['vulnerability']] = f"{time_percent:.1f}%"
        
        return strategy
    
    def _calculate_confidence(self, probability: float) -> str:
        """Calculate confidence level"""
        if probability > 0.8:
            return 'very_high'
        elif probability > 0.6:
            return 'high'
        elif probability > 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_priority(self, probability: float) -> int:
        """Calculate priority (1-5, 5 being highest)"""
        if probability > 0.8:
            return 5
        elif probability > 0.6:
            return 4
        elif probability > 0.4:
            return 3
        elif probability > 0.2:
            return 2
        else:
            return 1
    
    def _severity_multiplier(self, severity: str) -> float:
        """Get severity multiplier"""
        multipliers = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.0,
            'low': 0.5
        }
        return multipliers.get(severity, 1.0)
    
    def _calculate_risk_score(self, vuln_predictions: List[Dict],
                              severity_predictions: Dict) -> float:
        """Calculate overall risk score (0-10)"""
        
        total_score = 0.0
        
        for vuln in vuln_predictions[:10]:  # Top 10 vulnerabilities
            vuln_type = vuln['vulnerability_type']
            probability = vuln['probability']
            
            severity_info = severity_predictions.get(vuln_type, {})
            severity = severity_info.get('severity', 'medium')
            
            # Score = Probability × Severity Weight
            severity_weights = {
                'critical': 10.0,
                'high': 7.5,
                'medium': 5.0,
                'low': 2.5
            }
            
            score = probability * severity_weights.get(severity, 5.0)
            total_score += score
        
        # Normalize to 0-10 scale
        normalized_score = min(total_score / len(vuln_predictions[:10]), 10.0)
        
        return round(normalized_score, 2)
    
    def _generate_recommendations(self, vuln_predictions: List[Dict],
                                  chains: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        # Top vulnerability recommendation
        if vuln_predictions:
            top_vuln = vuln_predictions[0]
            recommendations.append(
                f"Focus testing efforts on {top_vuln['vulnerability_type']} "
                f"(probability: {top_vuln['probability']:.2%})"
            )
        
        # Chain recommendations
        if chains:
            recommendations.append(
                f"Found {len(chains)} potential vulnerability chains. "
                f"Test for chain exploitability."
            )
        
        # Tool recommendations
        top_3_vulns = vuln_predictions[:3]
        tools = set()
        for vuln in top_3_vulns:
            tools.update(self._get_recommended_tools(vuln['vulnerability_type']))
        
        recommendations.append(
            f"Recommended tools: {', '.join(sorted(tools))}"
        )
        
        return recommendations
    
    def _get_test_cases(self, vuln_type: str) -> List[str]:
        """Get test cases for vulnerability type"""
        
        test_cases = {
            'XSS': [
                'Test reflected XSS in all input parameters',
                'Test stored XSS in user-generated content',
                'Test DOM-based XSS in JavaScript code',
                'Bypass XSS filters with encoding',
                'Test in HTTP headers and cookies'
            ],
            'SQLI': [
                'Test SQL injection in all parameters',
                'Test time-based blind SQLi',
                'Test boolean-based blind SQLi',
                'Test UNION-based SQLi',
                'Test second-order SQLi'
            ],
            'IDOR': [
                'Test object reference manipulation',
                'Test sequential ID enumeration',
                'Test UUID/GUID manipulation',
                'Test cross-account access',
                'Test privilege escalation via IDOR'
            ],
            'SSRF': [
                'Test internal network access',
                'Test cloud metadata endpoint access',
                'Test protocol smuggling',
                'Test DNS rebinding',
                'Test SSRF via file upload'
            ],
            'AUTH_BYPASS': [
                'Test authentication bypass techniques',
                'Test password reset vulnerabilities',
                'Test session fixation',
                'Test JWT/token manipulation',
                'Test OAuth/SSO vulnerabilities'
            ],
            'CSRF': [
                'Test missing CSRF tokens',
                'Test CSRF token validation',
                'Test SameSite cookie attribute',
                'Test JSON-based CSRF',
                'Test state-changing GET requests'
            ],
            'BUSINESS_LOGIC': [
                'Test workflow bypass',
                'Test race conditions',
                'Test price manipulation',
                'Test negative values',
                'Test integer overflow/underflow'
            ]
        }
        
        return test_cases.get(vuln_type, [
            'Test standard vulnerability patterns',
            'Review application logic',
            'Test edge cases'
        ])
    
    def _get_recommended_tools(self, vuln_type: str) -> List[str]:
        """Get recommended tools for vulnerability type"""
        
        tools = {
            'XSS': ['Dalfox', 'XSStrike', 'Nuclei', 'Burp Suite'],
            'SQLI': ['SQLMap', 'Nuclei', 'Burp Suite'],
            'IDOR': ['Burp Suite', 'Custom Scripts', 'Nuclei'],
            'SSRF': ['SSRFmap', 'Interactsh', 'Burp Suite'],
            'AUTH_BYPASS': ['Burp Suite', 'Nuclei', 'Custom Scripts'],
            'CSRF': ['Burp Suite', 'OWASP ZAP'],
            'BUSINESS_LOGIC': ['Manual Testing', 'Custom Scripts'],
            'INFO_DISCLOSURE': ['Nuclei', 'Arjun', 'Burp Suite'],
            'RCE': ['Nuclei', 'Metasploit', 'Custom Exploits']
        }
        
        return tools.get(vuln_type, ['Nuclei', 'Burp Suite'])
    
    def _generate_chain_test_sequence(self, chain: Dict) -> List[str]:
        """Generate test sequence for vulnerability chain"""
        
        sequence = []
        for idx, vuln in enumerate(chain['vulns'], 1):
            sequence.append(f"Step {idx}: Test for {vuln}")
            sequence.append(f"  → Verify {vuln} can be exploited")
            if idx < len(chain['vulns']):
                sequence.append(f"  → Use {vuln} result for next step")
        
        sequence.append(f"Final Step: Confirm full chain exploitation")
        
        return sequence
    
    def _get_chain_tools(self, chain: Dict) -> List[str]:
        """Get tools for testing vulnerability chain"""
        
        all_tools = set()
        for vuln in chain['vulns']:
            all_tools.update(self._get_recommended_tools(vuln))
        
        return list(all_tools)


class NucleiTemplateGenerator:
    """
    Generates Nuclei templates based on predictions
    """
    
    def __init__(self):
        self.template_base_path = Path('nuclei-templates/custom')
        self.template_base_path.mkdir(parents=True, exist_ok=True)
    
    def generate_template(self, vuln_type: str, target_info: Dict) -> str:
        """Generate Nuclei template for specific vulnerability"""
        
        template = {
            'id': f"{vuln_type.lower()}-{target_info['domain'].replace('.', '-')}",
            'info': {
                'name': f'{vuln_type} Detection for {target_info["domain"]}',
                'author': 'BugPredict AI',
                'severity': 'info',
                'description': f'Auto-generated template to test for {vuln_type}',
                'tags': [vuln_type.lower(), 'auto-generated']
            },
            'requests': self._generate_requests(vuln_type, target_info)
        }
        
        # Convert to YAML
        import yaml
        template_yaml = yaml.dump(template, sort_keys=False)
        
        # Save template
        template_file = self.template_base_path / f"{template['id']}.yaml"
        with open(template_file, 'w') as f:
            f.write(template_yaml)
        
        return str(template_file)
    
    def _generate_requests(self, vuln_type: str, target_info: Dict) -> List[Dict]:
        """Generate HTTP requests for template"""
        
        if vuln_type == 'XSS':
            return [{
                'method': 'GET',
                'path': ['{{BaseURL}}{{path}}'],
                'payloads': {
                    'path': target_info.get('endpoints', ['/']),
                    'xss': [
                        '"><script>alert(1)</script>',
                        '"><img src=x onerror=alert(1)>',
                        'javascript:alert(1)'
                    ]
                },
                'matchers': [{
                    'type': 'word',
                    'words': ['<script>alert(1)</script>', 'onerror=alert(1)']
                }]
            }]
        
        elif vuln_type == 'SQLI':
            return [{
                'method': 'GET',
                'path': ['{{BaseURL}}{{path}}'],
                'payloads': {
                    'path': target_info.get('endpoints', ['/']),
                    'sqli': ["'", "' OR '1'='1", "1' UNION SELECT NULL--"]
                },
                'matchers': [{
                    'type': 'word',
                    'words': ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL']
                }]
            }]
        
        # Add more vulnerability types...
        
        return []
