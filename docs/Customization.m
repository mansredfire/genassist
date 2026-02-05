## 📄 File: `docs/CUSTOMIZATION.md` (Complete Customization Guide)

```markdown
# 🎨 BugPredict AI - Customization Guide

> Advanced guide for customizing and extending BugPredict AI

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Adding Custom Vulnerability Types](#adding-custom-vulnerability-types)
3. [Custom Feature Engineering](#custom-feature-engineering)
4. [Custom Data Sources](#custom-data-sources)
5. [Custom Models](#custom-models)
6. [Custom Chain Patterns](#custom-chain-patterns)
7. [Custom Test Strategies](#custom-test-strategies)
8. [Custom Preprocessing](#custom-preprocessing)
9. [Custom Scoring Logic](#custom-scoring-logic)
10. [Plugin System](#plugin-system)
11. [Configuration Overrides](#configuration-overrides)
12. [Examples](#examples)

---

## Overview

BugPredict AI is designed to be highly extensible. This guide covers how to customize every major component of the system.

### Customization Philosophy

- **Non-invasive**: Extend without modifying core code
- **Backward-compatible**: Don't break existing functionality
- **Well-documented**: Comment your customizations
- **Tested**: Write tests for custom components

---

## Adding Custom Vulnerability Types

### Step 1: Define Custom Type

Create `custom/vulnerability_types.py`:

```python
"""Custom vulnerability types"""

# Add to existing types
CUSTOM_VULNERABILITY_TYPES = [
    'API Key Exposure',
    'Misconfigured SAML',
    'Insecure Direct Database Access',
    'Hardcoded Secrets',
    'Debug Endpoints Exposed',
    'Improper Certificate Validation',
    'Memory Leak',
    'Insecure Cookie Handling',
    'Missing Security Headers',
    'Subdomain Takeover'
]
```

### Step 2: Add Detection Keywords

Update `src/collectors/enhanced_extractor.py`:

```python
class EnhancedVulnerabilityExtractor:
    def _build_keyword_mapping(self):
        # Get base mapping
        mapping = super()._build_keyword_mapping()
        
        # Add custom types
        custom_types = {
            'API Key Exposure': [
                'api key exposed', 'api key in response', 'leaked api key',
                'hardcoded api key', 'api key in code', 'api credentials leak'
            ],
            
            'Misconfigured SAML': [
                'saml misconfiguration', 'saml signature bypass',
                'saml xml signature wrapping', 'saml assertion manipulation'
            ],
            
            'Insecure Direct Database Access': [
                'direct database access', 'exposed database port',
                'database connection string', 'mongodb without auth',
                'redis without password'
            ],
            
            'Hardcoded Secrets': [
                'hardcoded secret', 'hardcoded password', 'hardcoded token',
                'credentials in code', 'secret in source', 'embedded credentials'
            ],
            
            'Debug Endpoints Exposed': [
                'debug endpoint', 'debug mode enabled', '/debug accessible',
                'development endpoint', 'actuator exposed'
            ],
            
            'Improper Certificate Validation': [
                'certificate validation bypass', 'invalid certificate accepted',
                'ssl verification disabled', 'trust all certificates'
            ],
            
            'Memory Leak': [
                'memory leak', 'resource exhaustion', 'memory not freed',
                'unbounded memory growth'
            ],
            
            'Insecure Cookie Handling': [
                'cookie without httponly', 'cookie without secure flag',
                'session cookie misconfiguration', 'insecure cookie'
            ],
            
            'Missing Security Headers': [
                'missing security headers', 'no csp header',
                'missing x-frame-options', 'no hsts header',
                'missing content-security-policy'
            ],
            
            'Subdomain Takeover': [
                'subdomain takeover', 'dangling dns', 'unclaimed subdomain',
                'cname pointing to unclaimed resource'
            ]
        }
        
        # Merge with base mapping
        mapping.update(custom_types)
        
        return mapping
```

### Step 3: Add CWE Mappings (Optional)

```python
def _build_cwe_mapping(self):
    mapping = super()._build_cwe_mapping()
    
    # Add custom CWE mappings
    custom_cwes = {
        798: 'Hardcoded Secrets',
        295: 'Improper Certificate Validation',
        401: 'Missing Authentication',
        614: 'Insecure Cookie Handling',
        1004: 'Missing Security Headers',
    }
    
    mapping.update(custom_cwes)
    return mapping
```

### Step 4: Add Severity Heuristics

Update `src/inference/predictor.py`:

```python
def _heuristic_severity(self, vuln_type: str) -> Dict:
    base_severities = super()._heuristic_severity(vuln_type)
    
    custom_severities = {
        'API Key Exposure': ('high', 8.0),
        'Misconfigured SAML': ('critical', 9.0),
        'Insecure Direct Database Access': ('critical', 9.5),
        'Hardcoded Secrets': ('high', 7.5),
        'Debug Endpoints Exposed': ('medium', 6.0),
        'Improper Certificate Validation': ('high', 7.0),
        'Memory Leak': ('medium', 5.5),
        'Insecure Cookie Handling': ('medium', 6.0),
        'Missing Security Headers': ('low', 4.5),
        'Subdomain Takeover': ('high', 7.5),
    }
    
    if vuln_type in custom_severities:
        severity, cvss = custom_severities[vuln_type]
        return {
            'severity': severity,
            'confidence': 0.7,
            'cvss_score': cvss,
            'severity_distribution': {severity: 0.7}
        }
    
    return base_severities
```

### Step 5: Retrain Models

```bash
# Collect data with new types detected
python scripts/collect_data.py --source all --limit 10000

# Retrain models
python scripts/train_model.py
```

---

## Custom Feature Engineering

### Creating Custom Features

Create `custom/features.py`:

```python
"""Custom feature engineering extensions"""

from typing import List, Dict
import re

class CustomFeatureExtractor:
    """Extract custom features from vulnerability reports"""
    
    def extract_url_features(self, report) -> Dict:
        """Extract features from URLs"""
        
        features = {}
        endpoint = report.endpoint
        
        # URL depth
        features['url_depth'] = endpoint.count('/')
        
        # Has parameters
        features['has_params'] = '?' in endpoint
        
        # Parameter count
        if '?' in endpoint:
            params = endpoint.split('?')[1].split('&')
            features['param_count'] = len(params)
        else:
            features['param_count'] = 0
        
        # Has ID in path
        features['has_id_in_path'] = bool(re.search(r'/\d+/', endpoint))
        
        # Has UUID in path
        features['has_uuid_in_path'] = bool(
            re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
                     endpoint, re.I)
        )
        
        return features
    
    def extract_description_features(self, report) -> Dict:
        """Extract advanced text features"""
        
        features = {}
        desc = report.description.lower()
        
        # Sentiment indicators
        features['mentions_bypass'] = 'bypass' in desc
        features['mentions_exploit'] = 'exploit' in desc
        features['mentions_malicious'] = 'malicious' in desc
        
        # Complexity indicators
        features['mentions_complex'] = any(word in desc for word in [
            'complex', 'sophisticated', 'advanced', 'multiple steps'
        ])
        
        # Impact indicators
        features['mentions_data_breach'] = any(word in desc for word in [
            'data breach', 'leak', 'exposure', 'steal', 'exfiltrate'
        ])
        
        features['mentions_takeover'] = any(word in desc for word in [
            'takeover', 'hijack', 'compromise'
        ])
        
        # Code indicators
        features['has_code_snippet'] = any(marker in desc for marker in [
            '```', 'curl ', 'http://', 'https://'
        ])
        
        features['has_payload'] = any(marker in desc for marker in [
            '<script>', 'alert(', 'eval(', 'union select', 'OR 1=1'
        ])
        
        return features
    
    def extract_timing_features(self, report) -> Dict:
        """Extract timing-based features"""
        
        features = {}
        
        if report.reported_date and report.disclosed_date:
            delta = (report.disclosed_date - report.reported_date).days
            
            # Disclosure patterns
            features['quick_disclosure'] = delta < 30
            features['delayed_disclosure'] = delta > 180
            features['disclosure_days'] = delta
            
            # Disclosure day of week
            features['disclosed_on_weekend'] = report.disclosed_date.weekday() >= 5
            
            # Disclosure month (seasonality)
            features['disclosed_month'] = report.disclosed_date.month
        
        return features
    
    def extract_researcher_features(self, report) -> Dict:
        """Extract researcher-specific features"""
        
        features = {}
        
        # Reputation tiers
        rep = report.researcher_reputation
        features['is_top_researcher'] = rep >= 1000
        features['is_established_researcher'] = 500 <= rep < 1000
        features['is_new_researcher'] = rep < 100
        
        # Reputation buckets
        if rep >= 2000:
            features['reputation_bucket'] = 5
        elif rep >= 1000:
            features['reputation_bucket'] = 4
        elif rep >= 500:
            features['reputation_bucket'] = 3
        elif rep >= 100:
            features['reputation_bucket'] = 2
        else:
            features['reputation_bucket'] = 1
        
        return features
```

### Integrating Custom Features

Update `src/features/feature_engineer.py`:

```python
from custom.features import CustomFeatureExtractor

class FeatureEngineer:
    def __init__(self):
        super().__init__()
        self.custom_extractor = CustomFeatureExtractor()
    
    def fit_transform(self, reports):
        # Get base features
        features_df = super().fit_transform(reports)
        
        # Extract custom features
        custom_features = []
        
        for report in reports:
            custom = {}
            
            # URL features
            custom.update(self.custom_extractor.extract_url_features(report))
            
            # Description features
            custom.update(self.custom_extractor.extract_description_features(report))
            
            # Timing features
            custom.update(self.custom_extractor.extract_timing_features(report))
            
            # Researcher features
            custom.update(self.custom_extractor.extract_researcher_features(report))
            
            custom_features.append(custom)
        
        # Convert to DataFrame
        custom_df = pd.DataFrame(custom_features)
        
        # Concatenate with base features
        features_df = pd.concat([features_df, custom_df], axis=1)
        
        return features_df
```

---

## Custom Data Sources

### Creating a Custom Collector

Create `custom/collectors/custom_source.py`:

```python
"""Custom data source collector"""

from src.collectors.data_sources import DataCollector, VulnerabilityReport
from typing import List, Dict
import requests
from datetime import datetime

class CustomSourceCollector(DataCollector):
    """
    Collect vulnerability data from a custom source
    
    Example: Internal bug tracking system, custom API, etc.
    """
    
    def __init__(self, api_url: str, api_key: str = None):
        super().__init__()
        self.api_url = api_url
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
    
    def collect(self, limit: int = 1000, use_cache: bool = True) -> List[VulnerabilityReport]:
        """Collect reports from custom source"""
        
        # Check cache
        if use_cache:
            cached = self.load_cache('custom_source_reports.pkl')
            if cached:
                return cached[:limit]
        
        print(f"Collecting from custom source: {self.api_url}")
        
        reports = []
        page = 1
        
        while len(reports) < limit:
            # Fetch page
            response = self.session.get(
                f"{self.api_url}/vulnerabilities",
                params={
                    'page': page,
                    'per_page': 100
                }
            )
            
            if response.status_code != 200:
                print(f"Error: {response.status_code}")
                break
            
            data = response.json()
            
            if not data.get('vulnerabilities'):
                break
            
            # Normalize each vulnerability
            for vuln in data['vulnerabilities']:
                report = self.normalize(vuln)
                if report:
                    reports.append(report)
            
            page += 1
            
            print(f"  Collected {len(reports)} reports...")
        
        # Cache results
        if use_cache:
            self.save_cache(reports, 'custom_source_reports.pkl')
        
        print(f"✓ Collected {len(reports)} reports from custom source")
        
        return reports[:limit]
    
    def normalize(self, raw_data: Dict) -> VulnerabilityReport:
        """Normalize custom format to VulnerabilityReport"""
        
        try:
            # Map your custom format to standard format
            report = VulnerabilityReport(
                report_id=f"CUSTOM-{raw_data['id']}",
                platform='custom_source',
                target_domain=raw_data.get('target', 'unknown'),
                target_company=raw_data.get('company', 'Unknown'),
                target_program=raw_data.get('program', 'Custom'),
                
                # Map vulnerability type
                vulnerability_type=self.extract_vulnerability_type(
                    raw_data.get('description', ''),
                    raw_data.get('type', '')
                ),
                
                # Map severity
                severity=raw_data.get('severity', 'medium').lower(),
                cvss_score=raw_data.get('cvss_score', 5.0),
                
                # Technical details
                technology_stack=self.extract_technologies(
                    raw_data.get('description', '')
                ),
                endpoint=raw_data.get('endpoint', '/'),
                http_method=raw_data.get('method', 'GET'),
                
                # Content
                description=raw_data.get('description', ''),
                steps_to_reproduce=raw_data.get('steps', []),
                impact=raw_data.get('impact', ''),
                remediation=raw_data.get('remediation', ''),
                
                # Dates
                reported_date=self._parse_date(raw_data.get('reported_at')),
                disclosed_date=self._parse_date(raw_data.get('disclosed_at')),
                
                # Optional fields
                bounty_amount=raw_data.get('bounty', 0.0),
                researcher_reputation=raw_data.get('reporter_reputation', 0),
                authentication_required=raw_data.get('requires_auth', False),
                tags=raw_data.get('tags', []),
                cwe_id=raw_data.get('cwe_id', 0),
                
                raw_data=raw_data
            )
            
            return report
            
        except Exception as e:
            print(f"Error normalizing report: {e}")
            return None
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime"""
        if not date_str:
            return None
        
        try:
            return datetime.fromisoformat(date_str)
        except:
            return None
```

### Using Custom Collector

```python
from custom.collectors.custom_source import CustomSourceCollector

# Initialize
collector = CustomSourceCollector(
    api_url='https://api.example.com',
    api_key='your_api_key'
)

# Collect
reports = collector.collect(limit=1000)

# Use in training
from src.training.pipeline import TrainingPipeline

pipeline = TrainingPipeline()
pipeline.raw_reports = reports
pipeline.run_full_pipeline()
```

---

## Custom Models

### Adding a Custom Model to Ensemble

Create `custom/models.py`:

```python
"""Custom ML models"""

from sklearn.base import BaseEstimator, ClassifierMixin
import numpy as np

class CustomVulnerabilityClassifier(BaseEstimator, ClassifierMixin):
    """
    Custom classifier for vulnerability prediction
    
    Example: Neural network, custom algorithm, etc.
    """
    
    def __init__(self, hidden_layers=3, neurons_per_layer=128):
        self.hidden_layers = hidden_layers
        self.neurons_per_layer = neurons_per_layer
        self.model = None
        self.classes_ = None
    
    def fit(self, X, y):
        """Train the model"""
        
        from sklearn.neural_network import MLPClassifier
        
        self.classes_ = np.unique(y)
        
        # Build neural network
        hidden_layer_sizes = tuple([self.neurons_per_layer] * self.hidden_layers)
        
        self.model = MLPClassifier(
            hidden_layer_sizes=hidden_layer_sizes,
            activation='relu',
            solver='adam',
            alpha=0.0001,
            batch_size='auto',
            learning_rate='adaptive',
            max_iter=500,
            random_state=42
        )
        
        self.model.fit(X, y)
        
        return self
    
    def predict(self, X):
        """Make predictions"""
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        return self.model.predict_proba(X)
```

### Integrate Custom Model

Update `src/models/vulnerability_classifier.py`:

```python
from custom.models import CustomVulnerabilityClassifier

class VulnerabilityPredictor:
    def build_models(self):
        # Existing models
        self.models = {
            'random_forest': RandomForestClassifier(...),
            'xgboost': XGBClassifier(...),
            'lightgbm': LGBMClassifier(...),
            'catboost': CatBoostClassifier(...),
            'gradient_boosting': GradientBoostingClassifier(...),
            
            # Add custom model
            'custom_neural_network': CustomVulnerabilityClassifier(
                hidden_layers=3,
                neurons_per_layer=128
            )
        }
```

---

## Custom Chain Patterns

### Adding Custom Attack Chains

Create `custom/chain_patterns.py`:

```python
"""Custom attack chain patterns"""

CUSTOM_CHAIN_PATTERNS = [
    {
        'name': 'API Key Leak to Data Breach',
        'vulns': ['API Key Exposure', 'Excessive Data Exposure', 'Rate Limiting Issues'],
        'severity': 'critical',
        'description': 'Leaked API key → Unrestricted API access → Mass data extraction',
        'prerequisites': ['API Key Exposure'],
        'steps': [
            'Discover exposed API key in response/code',
            'Use API key to access protected endpoints',
            'Exploit excessive data exposure to extract sensitive data',
            'Abuse lack of rate limiting for mass extraction'
        ],
        'impact': 'Complete data breach via API abuse',
        'likelihood': 0.85,
        'attack_complexity': 'low'
    },
    
    {
        'name': 'Subdomain Takeover to Phishing',
        'vulns': ['Subdomain Takeover', 'Missing Security Headers', 'Open Redirect'],
        'severity': 'high',
        'description': 'Takeover subdomain → Host phishing page → Redirect victims',
        'prerequisites': ['Subdomain Takeover'],
        'steps': [
            'Identify dangling DNS record for subdomain',
            'Claim the dangling resource (S3, Heroku, etc.)',
            'Host convincing phishing page',
            'Use open redirect to send victims to phishing page'
        ],
        'impact': 'Credential theft via trusted subdomain',
        'likelihood': 0.75,
        'attack_complexity': 'medium'
    },
    
    {
        'name': 'Debug Endpoint to Server Compromise',
        'vulns': ['Debug Endpoints Exposed', 'Information Disclosure', 'Remote Code Execution'],
        'severity': 'critical',
        'description': 'Debug endpoint → Leak internals → Exploit RCE',
        'prerequisites': ['Debug Endpoints Exposed'],
        'steps': [
            'Discover exposed debug/actuator endpoints',
            'Extract sensitive information (env vars, configs)',
            'Use information to identify RCE vulnerability',
            'Exploit RCE for server compromise'
        ],
        'impact': 'Full server compromise',
        'likelihood': 0.70,
        'attack_complexity': 'medium'
    },
    
    {
        'name': 'Certificate Bypass to MITM',
        'vulns': ['Improper Certificate Validation', 'Information Disclosure', 'Session Fixation'],
        'severity': 'high',
        'description': 'Bypass cert validation → MITM → Steal session tokens',
        'prerequisites': ['Improper Certificate Validation'],
        'steps': [
            'Identify app with disabled certificate validation',
            'Perform man-in-the-middle attack',
            'Intercept and steal session tokens',
            'Use tokens for session hijacking'
        ],
        'impact': 'Account takeover via session theft',
        'likelihood': 0.65,
        'attack_complexity': 'high'
    },
    
    {
        'name': 'Hardcoded Secret to Infrastructure Access',
        'vulns': ['Hardcoded Secrets', 'Cloud Misconfiguration', 'S3 Bucket Exposure'],
        'severity': 'critical',
        'description': 'Hardcoded AWS creds → Cloud access → Data exfiltration',
        'prerequisites': ['Hardcoded Secrets'],
        'steps': [
            'Find hardcoded AWS credentials in code/config',
            'Use credentials to access AWS account',
            'Enumerate and access misconfigured S3 buckets',
            'Exfiltrate sensitive data from buckets'
        ],
        'impact': 'Complete cloud infrastructure compromise',
        'likelihood': 0.80,
        'attack_complexity': 'low'
    }
]
```

### Integrate Custom Chains

Update `src/models/chain_detector.py`:

```python
from custom.chain_patterns import CUSTOM_CHAIN_PATTERNS

class ChainDetector:
    def _build_chain_patterns(self):
        # Get base patterns
        base_patterns = super()._build_chain_patterns()
        
        # Add custom patterns
        all_patterns = base_patterns + CUSTOM_CHAIN_PATTERNS
        
        return all_patterns
```

---

## Custom Test Strategies

### Custom Test Case Generator

Create `custom/test_strategies.py`:

```python
"""Custom test strategy generation"""

class CustomTestStrategyGenerator:
    """Generate custom test strategies for new vulnerability types"""
    
    def get_test_cases(self, vuln_type: str) -> list:
        """Get test cases for custom vulnerability types"""
        
        custom_test_cases = {
            'API Key Exposure': [
                'Check all API responses for exposed keys',
                'Search JavaScript files for hardcoded keys',
                'Test .git directory for committed keys',
                'Check environment variable endpoints',
                'Test backup/config files for key leakage'
            ],
            
            'Misconfigured SAML': [
                'Test SAML signature validation bypass',
                'Attempt XML signature wrapping attack',
                'Check for SAML assertion replay',
                'Test certificate validation',
                'Verify recipient URL validation'
            ],
            
            'Insecure Direct Database Access': [
                'Scan for exposed database ports (27017, 6379, 5432)',
                'Test database authentication bypass',
                'Check for default credentials',
                'Test direct database queries without app layer',
                'Verify network segmentation'
            ],
            
            'Hardcoded Secrets': [
                'Search source code for hardcoded credentials',
                'Check configuration files for secrets',
                'Test environment variable leakage',
                'Review container images for secrets',
                'Check version control history for secrets'
            ],
            
            'Debug Endpoints Exposed': [
                'Enumerate /debug, /actuator, /admin endpoints',
                'Test development endpoints in production',
                'Check for exposed metrics endpoints',
                'Test health check information disclosure',
                'Verify debug mode is disabled'
            ],
            
            'Subdomain Takeover': [
                'Enumerate subdomains via DNS',
                'Check for dangling CNAME records',
                'Test claiming unclaimed resources',
                'Verify DNS record ownership',
                'Check for expired service subscriptions'
            ],
            
            'Missing Security Headers': [
                'Test for missing Content-Security-Policy',
                'Check for missing X-Frame-Options',
                'Verify HSTS header presence',
                'Test for missing X-Content-Type-Options',
                'Check Referrer-Policy configuration'
            ],
            
            'Improper Certificate Validation': [
                'Test with self-signed certificate',
                'Check with expired certificate',
                'Test with wrong hostname certificate',
                'Verify certificate chain validation',
                'Test certificate pinning bypass'
            ],
            
            'Insecure Cookie Handling': [
                'Check for missing HttpOnly flag',
                'Verify Secure flag on cookies',
                'Test SameSite attribute',
                'Check cookie domain scope',
                'Verify cookie encryption'
            ],
            
            'Memory Leak': [
                'Perform repeated operations to exhaust memory',
                'Monitor memory usage over time',
                'Test with large payloads',
                'Check for resource cleanup',
                'Verify connection pooling'
            ]
        }
        
        return custom_test_cases.get(
            vuln_type,
            ['Perform standard security testing for this vulnerability']
        )
    
    def get_recommended_tools(self, vuln_type: str) -> list:
        """Get tools for custom vulnerability types"""
        
        custom_tools = {
            'API Key Exposure': ['truffleHog', 'GitLeaks', 'detect-secrets', 'Burp Suite'],
            'Misconfigured SAML': ['SAML Raider', 'Burp Suite', 'SAMLReQuest'],
            'Insecure Direct Database Access': ['nmap', 'masscan', 'mongodb-cli', 'redis-cli'],
            'Hardcoded Secrets': ['truffleHog', 'GitLeaks', 'detect-secrets', 'gitleaks'],
            'Debug Endpoints Exposed': ['ffuf', 'dirsearch', 'Burp Suite', 'gobuster'],
            'Subdomain Takeover': ['SubOver', 'subjack', 'can-i-take-over-xyz', 'dnsrecon'],
            'Missing Security Headers': ['securityheaders.com', 'Mozilla Observatory', 'Burp Suite'],
            'Improper Certificate Validation': ['testssl.sh', 'SSLyze', 'nmap'],
            'Insecure Cookie Handling': ['Burp Suite', 'OWASP ZAP', 'Cookie Manager'],
            'Memory Leak': ['Valgrind', 'Apache JMeter', 'custom scripts']
        }
        
        return custom_tools.get(
            vuln_type,
            ['Burp Suite', 'OWASP ZAP', 'Nuclei']
        )
```

### Integrate Custom Test Strategies

Update `src/inference/predictor.py`:

```python
from custom.test_strategies import CustomTestStrategyGenerator

class ThreatPredictor:
    def __init__(self):
        super().__init__()
        self.custom_test_gen = CustomTestStrategyGenerator()
    
    def _get_test_cases(self, vuln_type, target_info):
        # Try custom test cases first
        custom_cases = self.custom_test_gen.get_test_cases(vuln_type)
        
        if custom_cases != ['Perform standard security testing for this vulnerability']:
            return custom_cases
        
        # Fall back to default
        return super()._get_test_cases(vuln_type, target_info)
    
    def _get_recommended_tools(self, vuln_type):
        # Try custom tools first
        custom_tools = self.custom_test_gen.get_recommended_tools(vuln_type)
        
        if len(custom_tools) > 2:  # Custom tools found
            return custom_tools
        
        # Fall back to default
        return super()._get_recommended_tools(vuln_type)
```

---

## Custom Preprocessing

### Custom Data Normalizer

Create `custom/preprocessing.py`:

```python
"""Custom preprocessing steps"""

class CustomNormalizer:
    """Custom normalization logic"""
    
    def normalize_domain(self, domain: str) -> str:
        """Normalize domain names"""
        
        # Remove protocol
        domain = domain.replace('https://', '').replace('http://', '')
        
        # Remove www
        domain = domain.replace('www.', '')
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        # Convert to lowercase
        domain = domain.lower()
        
        return domain
    
    def normalize_technology_names(self, tech_stack: list) -> list:
        """Standardize technology names"""
        
        normalization_map = {
            'react.js': 'React',
            'reactjs': 'React',
            'react native': 'React Native',
            'angular.js': 'Angular',
            'angularjs': 'Angular',
            'vue': 'Vue.js',
            'vuejs': 'Vue.js',
            'node': 'Node.js',
            'nodejs': 'Node.js',
            'express': 'Express',
            'expressjs': 'Express',
            'postgres': 'PostgreSQL',
            'psql': 'PostgreSQL',
            'mongo': 'MongoDB',
            'mongodb': 'MongoDB',
            # Add more mappings
        }
        
        normalized = []
        for tech in tech_stack:
            tech_lower = tech.lower()
            normalized_tech = normalization_map.get(tech_lower, tech)
            if normalized_tech not in normalized:
                normalized.append(normalized_tech)
        
        return normalized
    
    def clean_description(self, description: str) -> str:
        """Clean and normalize description text"""
        
        import re
        
        # Remove excessive whitespace
        description = re.sub(r'\s+', ' ', description)
        
        # Remove markdown code blocks
        description = re.sub(r'```[\s\S]*?```', '[code]', description)
        
        # Remove URLs (keep for analysis but replace in text)
        description = re.sub(r'https?://[^\s]+', '[URL]', description)
        
        # Remove email addresses
        description = re.sub(r'\S+@\S+', '[email]', description)
        
        # Normalize common abbreviations
        replacements = {
            "xss": "cross-site scripting",
            "sqli": "sql injection",
            "csrf": "cross-site request forgery",
            "rce": "remote code execution",
            "idor": "insecure direct object reference",
            "ssrf": "server-side request forgery"
        }
        
        for abbr, full in replacements.items():
            description = re.sub(
                r'\b' + abbr + r'\b',
                full,
                description,
                flags=re.IGNORECASE
            )
        
        return description.strip()
```

### Integrate Custom Preprocessing

```python
from custom.preprocessing import CustomNormalizer

class DataNormalizer:
    def __init__(self):
        super().__init__()
        self.custom_normalizer = CustomNormalizer()
    
    def normalize(self, reports):
        normalized = []
        
        for report in reports:
            # Apply custom normalization
            report.target_domain = self.custom_normalizer.normalize_domain(
                report.target_domain
            )
            
            report.technology_stack = self.custom_normalizer.normalize_technology_names(
                report.technology_stack
            )
            
            report.description = self.custom_normalizer.clean_description(
                report.description
            )
            
            normalized.append(report)
        
        return normalized
```

---

## Custom Scoring Logic

### Custom Risk Scoring

Create `custom/scoring.py`:

```python
"""Custom scoring logic"""

class CustomRiskScorer:
    """Custom risk scoring algorithm"""
    
    def calculate_risk_score(self, predictions, severities, chains, target_info):
        """
        Custom risk scoring that considers:
        - Vulnerability predictions
        - Severity assessments
        - Attack chains
        - Target-specific factors
        """
        
        # Base score from vulnerabilities
        vuln_score = self._calculate_vulnerability_score(predictions, severities)
        
        # Chain multiplier
        chain_multiplier = self._calculate_chain_multiplier(chains)
        
        # Target-specific factors
        target_multiplier = self._calculate_target_multiplier(target_info)
        
        # Combined score
        risk_score = vuln_score * chain_multiplier * target_multiplier
        
        # Normalize to 0-10 scale
        risk_score = min(risk_score, 10.0)
        
        return round(risk_score, 2)
    
    def _calculate_vulnerability_score(self, predictions, severities):
        """Calculate score from vulnerabilities"""
        
        score = 0
        weights = {
            'critical': 1.0,
            'high': 0.7,
            'medium': 0.4,
            'low': 0.2
        }
        
        for vuln in predictions[:10]:
            vuln_type = vuln['vulnerability_type']
            prob = vuln['probability']
            
            severity_info = severities.get(vuln_type, {})
            severity = severity_info.get('severity', 'medium')
            
            weight = weights.get(severity, 0.4)
            score += prob * weight * 10
        
        return score / 10  # Normalize
    
    def _calculate_chain_multiplier(self, chains):
        """Calculate multiplier from attack chains"""
        
        if not chains:
            return 1.0
        
        critical_chains = sum(1 for c in chains if c['severity'] == 'critical')
        high_chains = sum(1 for c in chains if c['severity'] == 'high')
        
        multiplier = 1.0 + (critical_chains * 0.20) + (high_chains * 0.10)
        
        return min(multiplier, 1.5)  # Cap at 1.5x
    
    def _calculate_target_multiplier(self, target_info):
        """Calculate multiplier based on target characteristics"""
        
        multiplier = 1.0
        
        # High-value targets
        if any(keyword in target_info.get('company_name', '').lower() 
               for keyword in ['bank', 'finance', 'healthcare', 'government']):
            multiplier += 0.15
        
        # Complex tech stack = more attack surface
        tech_count = len(target_info.get('technology_stack', []))
        if tech_count >= 5:
            multiplier += 0.10
        
        # Public APIs increase risk
        if target_info.get('has_api'):
            multiplier += 0.05
        
        # Cloud infrastructure
        if target_info.get('cloud_provider'):
            multiplier += 0.05
        
        return min(multiplier, 1.35)  # Cap at 1.35x
```

### Integrate Custom Scoring

```python
from custom.scoring import CustomRiskScorer

class ThreatPredictor:
    def __init__(self):
        super().__init__()
        self.custom_scorer = CustomRiskScorer()
    
    def _calculate_risk_score(self, predictions, severities, chains):
        # Use custom scoring
        return self.custom_scorer.calculate_risk_score(
            predictions,
            severities,
            chains,
            self.current_target_info
        )
```

---

## Plugin System

### Creating a Plugin Architecture

Create `custom/plugins.py`:

```python
"""Plugin system for BugPredict AI"""

from abc import ABC, abstractmethod
from typing import Dict, List
import importlib
import os

class BugPredictPlugin(ABC):
    """Base class for plugins"""
    
    @abstractmethod
    def get_name(self) -> str:
        """Return plugin name"""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Return plugin version"""
        pass
    
    @abstractmethod
    def on_analysis_start(self, target_info: Dict):
        """Called before analysis starts"""
        pass
    
    @abstractmethod
    def on_analysis_complete(self, results: Dict) -> Dict:
        """Called after analysis completes, can modify results"""
        pass

class PluginManager:
    """Manage plugins"""
    
    def __init__(self, plugins_dir='custom/plugins'):
        self.plugins_dir = plugins_dir
        self.plugins = []
        self.load_plugins()
    
    def load_plugins(self):
        """Load all plugins from plugins directory"""
        
        if not os.path.exists(self.plugins_dir):
            return
        
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('_plugin.py'):
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(f'custom.plugins.{module_name}')
                    
                    # Find plugin class
                    for item in dir(module):
                        obj = getattr(module, item)
                        if (isinstance(obj, type) and 
                            issubclass(obj, BugPredictPlugin) and 
                            obj != BugPredictPlugin):
                            
                            plugin = obj()
                            self.plugins.append(plugin)
                            print(f"Loaded plugin: {plugin.get_name()} v{plugin.get_version()}")
                
                except Exception as e:
                    print(f"Error loading plugin {module_name}: {e}")
    
    def trigger_analysis_start(self, target_info):
        """Trigger all plugins on analysis start"""
        for plugin in self.plugins:
            try:
                plugin.on_analysis_start(target_info)
            except Exception as e:
                print(f"Plugin {plugin.get_name()} error: {e}")
    
    def trigger_analysis_complete(self, results):
        """Trigger all plugins on analysis complete"""
        for plugin in self.plugins:
            try:
                results = plugin.on_analysis_complete(results)
            except Exception as e:
                print(f"Plugin {plugin.get_name()} error: {e}")
        
        return results
```

### Example Plugin

Create `custom/plugins/slack_notification_plugin.py`:

```python
"""Slack notification plugin"""

from custom.plugins import BugPredictPlugin
import requests

class SlackNotificationPlugin(BugPredictPlugin):
    """Send Slack notifications for high-risk findings"""
    
    def __init__(self):
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL')
    
    def get_name(self):
        return "Slack Notification"
    
    def get_version(self):
        return "1.0.0"
    
    def on_analysis_start(self, target_info):
        # Nothing to do on start
        pass
    
    def on_analysis_complete(self, results):
        # Send notification if high risk
        if results['risk_score'] >= 7.0:
            self._send_notification(results)
        
        return results
    
    def _send_notification(self, results):
        if not self.webhook_url:
            return
        
        message = {
            "text": f"⚠️ High Risk Target Detected",
            "attachments": [{
                "color": "danger",
                "fields": [
                    {
                        "title": "Target",
                        "value": results['target'],
                        "short": True
                    },
                    {
                        "title": "Risk Score",
                        "value": f"{results['risk_score']}/10",
                        "short": True
                    },
                    {
                        "title": "Top Vulnerability",
                        "value": results['vulnerability_predictions'][0]['vulnerability_type'],
                        "short": False
                    }
                ]
            }]
        }
        
        try:
            requests.post(self.webhook_url, json=message)
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")
```

### Use Plugin System

```python
from custom.plugins import PluginManager

class ThreatPredictor:
    def __init__(self):
        super().__init__()
        self.plugin_manager = PluginManager()
    
    def analyze_target(self, target_info):
        # Trigger plugins
        self.plugin_manager.trigger_analysis_start(target_info)
        
        # Perform analysis
        results = super().analyze_target(target_info)
        
        # Trigger plugins with results
        results = self.plugin_manager.trigger_analysis_complete(results)
        
        return results
```

---

## Configuration Overrides

### Custom Configuration System

Create `custom/config.py`:

```python
"""Custom configuration overrides"""

import yaml
import os

class CustomConfig:
    """Manage custom configuration"""
    
    def __init__(self, config_file='custom/custom_config.yaml'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """Load custom configuration"""
        
        if not os.path.exists(self.config_file):
            return {}
        
        with open(self.config_file, 'r') as f:
            return yaml.safe_load(f)
    
    def get(self, key, default=None):
        """Get configuration value"""
        
        # Support nested keys with dot notation
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def override(self, base_config):
        """Override base configuration with custom values"""
        
        def deep_merge(base, override):
            """Recursively merge configurations"""
            result = base.copy()
            
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            
            return result
        
        return deep_merge(base_config, self.config)
```

### Example Custom Config

Create `custom/custom_config.yaml`:

```yaml
# Custom BugPredict AI Configuration

# Override default vulnerability types
vulnerability_types:
  custom:
    - API Key Exposure
    - Misconfigured SAML
    - Subdomain Takeover
    - Hardcoded Secrets

# Custom severity mappings
severity_overrides:
  API Key Exposure: 
    severity: high
    cvss: 8.0
  Hardcoded Secrets:
    severity: high
    cvss: 7.5

# Custom feature engineering
features:
  enable_custom_url_features: true
  enable_custom_text_features: true
  custom_tech_stack:
    - GraphQL
    - Hasura
    - Supabase
    - Vercel

# Custom model settings
models:
  enable_custom_neural_network: true
  neural_network:
    hidden_layers: 3
    neurons_per_layer: 128

# Custom chain patterns
chains:
  enable_custom_patterns: true
  min_exploitability_score: 5.0

# Custom risk scoring
risk_scoring:
  use_custom_scorer: true
  high_value_targets:
    - bank
    - finance
    - healthcare
    - government
  
# Plugin settings
plugins:
  enabled: true
  slack_notifications:
    enabled: true
    min_risk_score: 7.0
  
  email_notifications:
    enabled: false
    recipients:
      - security@example.com

# Custom test strategies
test_strategies:
  include_custom_test_cases: true
  custom_tools:
    - truffleHog
    - GitLeaks
    - SubOver
```

### Use Custom Config

```python
from custom.config import CustomConfig

# Load custom config
custom_config = CustomConfig()

# Override base configuration
if custom_config.get('features.enable_custom_url_features'):
    # Enable custom URL features
    pass

if custom_config.get('models.enable_custom_neural_network'):
    # Add custom neural network to ensemble
    pass

if custom_config.get('plugins.enabled'):
    # Enable plugin system
    plugin_manager = PluginManager()
```

---

## Examples

### Complete Custom Extension Example

Here's a complete example tying everything together:

```python
#!/usr/bin/env python3
"""
Complete custom extension example
Demonstrates all customization capabilities
"""

from src.inference.predictor import ThreatPredictor
from custom.plugins import PluginManager
from custom.config import CustomConfig
from custom.features import CustomFeatureExtractor
from custom.test_strategies import CustomTestStrategyGenerator
from custom.scoring import CustomRiskScorer

class CustomThreatPredictor(ThreatPredictor):
    """Extended ThreatPredictor with custom capabilities"""
    
    def __init__(self, models_dir='data/models'):
        super().__init__(models_dir)
        
        # Load custom configuration
        self.custom_config = CustomConfig()
        
        # Initialize custom components
        if self.custom_config.get('features.enable_custom_features'):
            self.custom_features = CustomFeatureExtractor()
        
        if self.custom_config.get('test_strategies.include_custom_test_cases'):
            self.custom_test_gen = CustomTestStrategyGenerator()
        
        if self.custom_config.get('risk_scoring.use_custom_scorer'):
            self.custom_scorer = CustomRiskScorer()
        
        # Initialize plugins
        if self.custom_config.get('plugins.enabled'):
            self.plugin_manager = PluginManager()
        else:
            self.plugin_manager = None
    
    def analyze_target(self, target_info):
        """Enhanced analysis with custom capabilities"""
        
        # Trigger plugins
        if self.plugin_manager:
            self.plugin_manager.trigger_analysis_start(target_info)
        
        # Perform standard analysis
        results = super().analyze_target(target_info)
        
        # Apply custom enhancements
        if hasattr(self, 'custom_scorer'):
            results['risk_score'] = self.custom_scorer.calculate_risk_score(
                results['vulnerability_predictions'],
                results['severity_predictions'],
                results['chain_predictions'],
                target_info
            )
        
        # Trigger plugins with results
        if self.plugin_manager:
            results = self.plugin_manager.trigger_analysis_complete(results)
        
        return results

# Usage
if __name__ == '__main__':
    predictor = CustomThreatPredictor()
    
    target = {
        'domain': 'api.example.com',
        'company_name': 'Example Bank',  # High-value target
        'technology_stack': ['React', 'GraphQL', 'Node.js', 'MongoDB'],
        'has_api': True,
        'has_graphql': True,
        'cloud_provider': 'AWS'
    }
    
    results = predictor.analyze_target(target)
    
    print(f"Risk Score: {results['risk_score']}/10")
    print(f"Custom Features Enabled: {hasattr(predictor, 'custom_features')}")
    print(f"Plugins Enabled: {predictor.plugin_manager is not None}")
```

---

## Testing Custom Components

### Unit Tests for Custom Components

Create `tests/test_custom.py`:

```python
"""Tests for custom components"""

import pytest
from custom.features import CustomFeatureExtractor
from custom.test_strategies import CustomTestStrategyGenerator
from custom.scoring import CustomRiskScorer
from src.collectors.data_sources import VulnerabilityReport

def test_custom_feature_extraction():
    """Test custom feature extraction"""
    
    extractor = CustomFeatureExtractor()
    
    # Create test report
    report = VulnerabilityReport(
        report_id='TEST-001',
        platform='test',
        target_domain='example.com',
        target_company='Test Corp',
        target_program='Test',
        vulnerability_type='XSS',
        severity='high',
        cvss_score=7.5,
        endpoint='/api/users?id=123',
        description='Test XSS vulnerability'
    )
    
    # Extract features
    features = extractor.extract_url_features(report)
    
    assert 'url_depth' in features
    assert 'has_params' in features
    assert features['has_params'] == True
    assert features['param_count'] > 0

def test_custom_test_strategies():
    """Test custom test strategy generation"""
    
    generator = CustomTestStrategyGenerator()
    
    # Test custom vulnerability type
    test_cases = generator.get_test_cases('API Key Exposure')
    
    assert len(test_cases) > 0
    assert any('api' in case.lower() for case in test_cases)
    
    # Test tools
    tools = generator.get_recommended_tools('API Key Exposure')
    
    assert len(tools) > 0
    assert 'truffleHog' in tools

def test_custom_risk_scoring():
    """Test custom risk scoring"""
    
    scorer = CustomRiskScorer()
    
    predictions = [
        {'vulnerability_type': 'SQL Injection', 'probability': 0.8},
        {'vulnerability_type': 'XSS', 'probability': 0.7}
    ]
    
    severities = {
        'SQL Injection': {'severity': 'critical', 'cvss_score': 9.0},
        'XSS': {'severity': 'high', 'cvss_score': 7.5}
    }
    
    chains = [
        {'severity': 'critical', 'name': 'Test Chain'}
    ]
    
    target_info = {
        'company_name': 'Test Bank',
        'technology_stack': ['React', 'Node.js', 'PostgreSQL'],
        'has_api': True
    }
    
    score = scorer.calculate_risk_score(predictions, severities, chains, target_info)
    
    assert 0 <= score <= 10
    assert score > 5  # Should be high due to critical vulns and bank target

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
```

---

## Best Practices for Customization

### 1. Code Organization

```
custom/
├── __init__.py
├── config.py                 # Configuration management
├── vulnerability_types.py    # Custom vulnerability definitions
├── features.py              # Custom feature extraction
├── models.py                # Custom ML models
├── chain_patterns.py        # Custom attack chains
├── test_strategies.py       # Custom test generation
├── preprocessing.py         # Custom preprocessing
├── scoring.py               # Custom risk scoring
├── plugins.py               # Plugin system
├── collectors/              # Custom data sources
│   ├── __init__.py
│   └── custom_source.py
└── plugins/                 # Individual plugins
    ├── __init__.py
    ├── slack_notification_plugin.py
    └── email_notification_plugin.py
```

### 2. Documentation

Always document your customizations:

```python
"""
Custom vulnerability type: API Key Exposure

Detection Keywords:
- api key exposed
- api key in response
- leaked api key

Severity: HIGH (7.5-8.0 CVSS)

Test Cases:
1. Check API responses for exposed keys
2. Search JavaScript files
3. Test .git directory
4. Check environment endpoints
5. Test backup files

Tools:
- truffleHog
- GitLeaks
- detect-secrets

Added: 2024-01-15
Author: Security Team
"""
```

### 3. Version Control

Keep custom components in separate branch:

```bash
# Create custom branch
git checkout -b custom-extensions

# Commit custom components
git add custom/
git commit -m "Add custom vulnerability types and features"

# Merge with care
git checkout main
git merge custom-extensions
```

### 4. Testing

Always test customizations:

```bash
# Run custom tests
pytest tests/test_custom.py -v

# Run full test suite
pytest tests/ -v

# Test with custom config
python scripts/analyze_target.py \
  --domain test.com \
  --config custom/custom_config.yaml
```

---

## Support

For customization help:
- Review example customizations in `custom/` directory
- Check documentation: [docs/](../docs/)
- GitHub Discussions: https://github.com/yourusername/bugpredict-ai/discussions
- Open an issue: https://github.com/yourusername/bugpredict-ai/issues

---

**Happy Customizing! 🎨**

*Remember: Test thoroughly before deploying custom components to production!*
```

---

✅ **CUSTOMIZATION.md Complete!**
That's **4 out of 5 major guides** done! Ready for the final one: **FAQ.md**? 📖
