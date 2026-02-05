Perfect! Let's create all the guides except CONTRIBUTING.md. I'll do them one at a time.

## 📄 File: `docs/API.md` (Complete API Reference & Integration Guide)

```markdown
# 🔌 BugPredict AI - API Reference & Integration Guide

> Complete API documentation and integration examples for BugPredict AI

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Python API](#python-api)
3. [Core Classes](#core-classes)
4. [Integration Examples](#integration-examples)
5. [REST API Server](#rest-api-server)
6. [Burp Suite Extension](#burp-suite-extension)
7. [CI/CD Integration](#cicd-integration)
8. [Custom Integrations](#custom-integrations)
9. [API Best Practices](#api-best-practices)

---

## Overview

BugPredict AI provides multiple integration methods:

- **Python API**: Import and use classes directly
- **Command-Line Interface**: Scripts for automation
- **REST API Server**: HTTP API (optional)
- **Extensions**: Burp Suite, browser extensions

---

## Python API

### Installation

```bash
pip install bugpredict-ai
# Or for development
pip install -e .
```

### Basic Usage

```python
from src.inference.predictor import ThreatPredictor

# Initialize predictor
predictor = ThreatPredictor(models_dir='data/models')

# Analyze a target
target_info = {
    'domain': 'example.com',
    'company_name': 'Example Corp',
    'technology_stack': ['React', 'Node.js', 'PostgreSQL'],
    'endpoints': ['/api/users', '/api/posts'],
    'auth_required': True,
    'has_api': True,
    'has_graphql': False,
    'cloud_provider': 'AWS'
}

# Get predictions
results = predictor.analyze_target(target_info)

# Access predictions
print(f"Risk Score: {results['risk_score']}/10")
print(f"Risk Level: {results['risk_level']}")

for vuln in results['vulnerability_predictions'][:5]:
    print(f"- {vuln['vulnerability_type']}: {vuln['probability']:.1%}")
```

---

## Core Classes

### 1. ThreatPredictor

**Purpose:** Main inference engine for vulnerability prediction

**Location:** `src/inference/predictor.py`

#### Constructor

```python
ThreatPredictor(models_dir: str = "data/models")
```

**Parameters:**
- `models_dir` (str): Directory containing trained models

**Example:**
```python
from src.inference.predictor import ThreatPredictor

predictor = ThreatPredictor(models_dir='data/models')
```

#### Methods

##### `analyze_target(target_info: Dict) -> Dict`

Analyze a target and predict vulnerabilities.

**Parameters:**
- `target_info` (Dict): Target information dictionary

**Target Info Structure:**
```python
{
    'domain': str,              # Required - Target domain
    'company_name': str,        # Optional - Company name
    'technology_stack': list,   # Optional - Technologies used
    'endpoints': list,          # Optional - API endpoints
    'auth_required': bool,      # Optional - Requires auth
    'has_api': bool,           # Optional - Has API
    'has_graphql': bool,       # Optional - Has GraphQL
    'cloud_provider': str,     # Optional - AWS/Azure/GCP
    'description': str         # Optional - Target description
}
```

**Returns:**
```python
{
    'target': str,
    'company': str,
    'technology_stack': list,
    'analysis_timestamp': str,
    'vulnerability_predictions': list,  # Top vulnerabilities
    'severity_predictions': dict,       # Severity info per vuln
    'chain_predictions': list,          # Attack chains
    'test_strategy': dict,              # Testing recommendations
    'risk_score': float,                # 0-10 score
    'risk_level': str,                  # critical/high/medium/low
    'recommendations': list,            # Actionable recommendations
    'technology_insights': dict,        # Tech-specific insights
    'metadata': dict                    # Model metadata
}
```

**Example:**
```python
target = {
    'domain': 'api.example.com',
    'technology_stack': ['React', 'GraphQL', 'MongoDB'],
    'has_graphql': True
}

results = predictor.analyze_target(target)

# Access results
print(f"Risk: {results['risk_score']}/10")

# Top vulnerabilities
for vuln in results['vulnerability_predictions'][:3]:
    print(f"{vuln['vulnerability_type']}: {vuln['probability']:.0%}")

# Detected chains
for chain in results['chain_predictions']:
    print(f"Chain: {chain['name']} (score: {chain['exploitability_score']})")
```

##### `batch_analyze(targets: List[Dict]) -> List[Dict]`

Analyze multiple targets.

**Parameters:**
- `targets` (List[Dict]): List of target info dictionaries

**Returns:**
- List of analysis results

**Example:**
```python
targets = [
    {'domain': 'example.com', 'technology_stack': ['React']},
    {'domain': 'test.io', 'technology_stack': ['Angular']},
    {'domain': 'demo.app', 'technology_stack': ['Vue.js']}
]

results = predictor.batch_analyze(targets)

for result in results:
    print(f"{result['target']}: {result['risk_score']}/10")
```

---

### 2. VulnerabilityPredictor

**Purpose:** Ensemble classifier for vulnerability type prediction

**Location:** `src/models/vulnerability_classifier.py`

#### Constructor

```python
VulnerabilityPredictor(model_type: str = 'ensemble', random_state: int = 42)
```

**Parameters:**
- `model_type` (str): Model type ('ensemble' or specific model name)
- `random_state` (int): Random seed for reproducibility

#### Methods

##### `predict(X: pd.DataFrame, model_name: Optional[str] = None) -> np.ndarray`

Predict vulnerability types.

**Parameters:**
- `X` (DataFrame): Feature matrix
- `model_name` (str, optional): Specific model to use

**Returns:**
- Array of predicted vulnerability types

**Example:**
```python
from src.models.vulnerability_classifier import VulnerabilityPredictor
import pandas as pd

# Load model
predictor = VulnerabilityPredictor.load('data/models/vulnerability_predictor.pkl')

# Prepare features
features = pd.DataFrame(...)  # Your features

# Predict
predictions = predictor.predict(features)
print(predictions)
```

##### `predict_top_k(X: pd.DataFrame, k: int = 5) -> List[List[Tuple]]`

Get top-k vulnerability predictions with probabilities.

**Parameters:**
- `X` (DataFrame): Feature matrix
- `k` (int): Number of top predictions

**Returns:**
- List of lists containing (vulnerability_type, probability) tuples

**Example:**
```python
top_predictions = predictor.predict_top_k(features, k=10)

for sample_predictions in top_predictions:
    print("Top 10 vulnerabilities:")
    for vuln_type, prob in sample_predictions:
        print(f"  {vuln_type}: {prob:.1%}")
```

##### `get_feature_importance(top_n: int = 20) -> pd.DataFrame`

Get top N most important features.

**Example:**
```python
importance = predictor.get_feature_importance(top_n=20)
print(importance)
```

---

### 3. SeverityPredictor

**Purpose:** Predict vulnerability severity and CVSS scores

**Location:** `src/models/severity_predictor.py`

#### Methods

##### `predict(X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]`

Predict severity and confidence.

**Returns:**
- Tuple of (severity_predictions, probabilities)

##### `predict_cvss(X: pd.DataFrame) -> np.ndarray`

Predict CVSS scores.

**Returns:**
- Array of predicted CVSS scores (0-10 scale)

**Example:**
```python
from src.models.severity_predictor import SeverityPredictor

predictor = SeverityPredictor.load('data/models/severity_predictor.pkl')

# Predict severity
severities, probabilities = predictor.predict(features)

# Predict CVSS scores
cvss_scores = predictor.predict_cvss(features)

print(f"Severity: {severities[0]}")
print(f"CVSS: {cvss_scores[0]:.1f}")
```

---

### 4. ChainDetector

**Purpose:** Detect vulnerability chains and attack paths

**Location:** `src/models/chain_detector.py`

#### Methods

##### `detect_chains(vulnerabilities: List[str]) -> List[Dict]`

Detect attack chains from vulnerability list.

**Parameters:**
- `vulnerabilities` (List[str]): List of vulnerability types

**Returns:**
- List of detected chain dictionaries

**Example:**
```python
from src.models.chain_detector import ChainDetector

detector = ChainDetector()

vulns = ['GraphQL Introspection', 'Excessive Data Exposure', 'IDOR']
chains = detector.detect_chains(vulns)

for chain in chains:
    print(f"Chain: {chain['name']}")
    print(f"Severity: {chain['severity']}")
    print(f"Score: {chain['exploitability_score']}/10")
    print(f"Steps: {chain['steps']}")
```

##### `find_attack_paths(vulnerabilities: List[str], max_length: int = 5) -> List[List[str]]`

Find all possible attack paths.

**Parameters:**
- `vulnerabilities` (List[str]): Vulnerability types
- `max_length` (int): Maximum path length

**Returns:**
- List of attack paths

**Example:**
```python
paths = detector.find_attack_paths(vulns, max_length=4)

for i, path in enumerate(paths[:5], 1):
    print(f"Path {i}: {' → '.join(path)}")
```

---

### 5. FeatureEngineer

**Purpose:** Extract features from vulnerability reports

**Location:** `src/features/feature_engineer.py`

#### Methods

##### `fit_transform(reports: List[VulnerabilityReport]) -> pd.DataFrame`

Fit feature extractors and transform reports.

**Parameters:**
- `reports` (List): List of VulnerabilityReport objects

**Returns:**
- DataFrame with engineered features

##### `transform(reports: List[VulnerabilityReport]) -> pd.DataFrame`

Transform new reports using fitted extractors.

**Example:**
```python
from src.features.feature_engineer import FeatureEngineer
from src.collectors.data_sources import VulnerabilityReport

engineer = FeatureEngineer()

# Fit and transform training data
train_features = engineer.fit_transform(train_reports)

# Transform new data
test_features = engineer.transform(test_reports)

# Save for later use
engineer.save('data/models/feature_engineer.pkl')

# Load
engineer = FeatureEngineer.load('data/models/feature_engineer.pkl')
```

---

### 6. Data Collectors

#### HackerOneCollector

**Location:** `src/collectors/hackerone_scraper.py`

```python
from src.collectors.hackerone_scraper import HackerOneCollector

collector = HackerOneCollector(api_token='your_token')
reports = collector.collect(limit=1000, use_cache=True)

print(f"Collected {len(reports)} reports")
```

#### BugcrowdCollector

**Location:** `src/collectors/bugcrowd_scraper.py`

```python
from src.collectors.bugcrowd_scraper import BugcrowdCollector

collector = BugcrowdCollector(api_token='your_token')
reports = collector.collect(limit=500, use_cache=True)
```

#### CVECollector

**Location:** `src/collectors/cve_collector.py`

```python
from src.collectors.cve_collector import CVECollector
from datetime import datetime, timedelta

collector = CVECollector(api_key='your_key')

end_date = datetime.now()
start_date = end_date - timedelta(days=180)

reports = collector.collect(
    start_date=start_date,
    end_date=end_date,
    keywords=['web', 'application'],
    limit=1000
)
```

---

## Integration Examples

### Example 1: Simple Vulnerability Scanner

```python
#!/usr/bin/env python3
"""Simple vulnerability scanner using BugPredict AI"""

from src.inference.predictor import ThreatPredictor
import sys

def scan_target(domain, tech_stack):
    """Scan a target for vulnerabilities"""
    
    # Initialize predictor
    predictor = ThreatPredictor()
    
    # Prepare target info
    target = {
        'domain': domain,
        'technology_stack': tech_stack,
        'has_api': True,
        'auth_required': True
    }
    
    # Analyze
    results = predictor.analyze_target(target)
    
    # Display results
    print(f"\n{'='*70}")
    print(f"SCAN RESULTS: {domain}")
    print(f"{'='*70}")
    print(f"Risk Score: {results['risk_score']}/10 ({results['risk_level'].upper()})")
    print(f"\nTop 5 Vulnerabilities:")
    
    for vuln in results['vulnerability_predictions'][:5]:
        print(f"  [{vuln['priority']}/5] {vuln['vulnerability_type']}: {vuln['probability']:.0%}")
    
    print(f"\nDetected Chains: {len(results['chain_predictions'])}")
    
    for chain in results['chain_predictions'][:3]:
        print(f"  - {chain['name']} (score: {chain['exploitability_score']}/10)")
    
    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <domain> [tech1 tech2 ...]")
        sys.exit(1)
    
    domain = sys.argv[1]
    tech_stack = sys.argv[2:] if len(sys.argv) > 2 else []
    
    scan_target(domain, tech_stack)
```

**Usage:**
```bash
python scanner.py example.com React Node.js PostgreSQL
```

---

### Example 2: Bug Bounty Target Prioritizer

```python
#!/usr/bin/env python3
"""Prioritize bug bounty targets by predicted risk"""

from src.inference.predictor import ThreatPredictor
import pandas as pd
import json

def prioritize_targets(targets_file, output_file):
    """Prioritize targets by risk score"""
    
    # Load targets
    with open(targets_file, 'r') as f:
        targets = json.load(f)
    
    # Initialize predictor
    predictor = ThreatPredictor()
    
    # Analyze all targets
    results = predictor.batch_analyze(targets)
    
    # Sort by risk score
    sorted_results = sorted(
        results, 
        key=lambda x: x.get('risk_score', 0), 
        reverse=True
    )
    
    # Create prioritized list
    prioritized = []
    for i, result in enumerate(sorted_results, 1):
        prioritized.append({
            'rank': i,
            'domain': result['target'],
            'risk_score': result['risk_score'],
            'risk_level': result['risk_level'],
            'top_vulnerability': result['vulnerability_predictions'][0]['vulnerability_type'],
            'top_vuln_probability': result['vulnerability_predictions'][0]['probability'],
            'chains_detected': len(result['chain_predictions'])
        })
    
    # Save to CSV
    df = pd.DataFrame(prioritized)
    df.to_csv(output_file, index=False)
    
    print(f"Prioritized {len(targets)} targets")
    print(f"Results saved to {output_file}")
    
    # Display top 5
    print("\nTop 5 Targets:")
    for target in prioritized[:5]:
        print(f"  {target['rank']}. {target['domain']} - Risk: {target['risk_score']}/10")

if __name__ == '__main__':
    prioritize_targets('targets.json', 'prioritized_targets.csv')
```

---

### Example 3: Continuous Monitoring

```python
#!/usr/bin/env python3
"""Monitor targets and alert on high-risk findings"""

from src.inference.predictor import ThreatPredictor
import time
import smtplib
from email.message import EmailMessage

def send_alert(target, risk_score, vulnerabilities):
    """Send email alert for high-risk findings"""
    
    msg = EmailMessage()
    msg['Subject'] = f'⚠️ High Risk Target: {target}'
    msg['From'] = 'bugpredict@example.com'
    msg['To'] = 'security@example.com'
    
    body = f"""
High-risk target detected!

Target: {target}
Risk Score: {risk_score}/10

Top Vulnerabilities:
"""
    
    for vuln in vulnerabilities[:5]:
        body += f"  - {vuln['vulnerability_type']}: {vuln['probability']:.0%}\n"
    
    msg.set_content(body)
    
    # Send email
    with smtplib.SMTP('localhost') as s:
        s.send_message(msg)

def monitor_targets(targets, interval=3600):
    """Monitor targets periodically"""
    
    predictor = ThreatPredictor()
    
    while True:
        print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Scanning targets...")
        
        results = predictor.batch_analyze(targets)
        
        for result in results:
            if result['risk_score'] >= 7.0:
                print(f"⚠️  HIGH RISK: {result['target']} - {result['risk_score']}/10")
                send_alert(
                    result['target'],
                    result['risk_score'],
                    result['vulnerability_predictions']
                )
            else:
                print(f"✓ {result['target']} - {result['risk_score']}/10")
        
        print(f"Sleeping for {interval}s...")
        time.sleep(interval)

if __name__ == '__main__':
    targets = [
        {'domain': 'app1.example.com', 'technology_stack': ['React', 'Node.js']},
        {'domain': 'app2.example.com', 'technology_stack': ['Angular', 'Java']},
    ]
    
    monitor_targets(targets, interval=3600)  # Check hourly
```

---

### Example 4: Custom Report Generator

```python
#!/usr/bin/env python3
"""Generate custom PDF reports"""

from src.inference.predictor import ThreatPredictor
from fpdf import FPDF
import datetime

class VulnerabilityReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'BugPredict AI - Vulnerability Analysis Report', 0, 1, 'C')
        self.ln(5)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_report(target_domain, tech_stack, output_file):
    """Generate PDF report for target"""
    
    # Analyze target
    predictor = ThreatPredictor()
    results = predictor.analyze_target({
        'domain': target_domain,
        'technology_stack': tech_stack,
        'has_api': True
    })
    
    # Create PDF
    pdf = VulnerabilityReport()
    pdf.add_page()
    
    # Executive Summary
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Executive Summary', 0, 1)
    pdf.set_font('Arial', '', 11)
    pdf.multi_cell(0, 5, f"""
Target: {results['target']}
Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d')}
Risk Score: {results['risk_score']}/10 ({results['risk_level'].upper()})
Technologies: {', '.join(results['technology_stack'])}
    """)
    
    # Top Vulnerabilities
    pdf.ln(5)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Top Predicted Vulnerabilities', 0, 1)
    pdf.set_font('Arial', '', 10)
    
    for i, vuln in enumerate(results['vulnerability_predictions'][:10], 1):
        pdf.cell(0, 6, f"{i}. {vuln['vulnerability_type']}: {vuln['probability']:.0%} (Priority: {vuln['priority']}/5)", 0, 1)
    
    # Attack Chains
    if results['chain_predictions']:
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Detected Attack Chains', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        for chain in results['chain_predictions'][:5]:
            pdf.multi_cell(0, 5, f"""
Chain: {chain['name']}
Severity: {chain['severity'].upper()}
Exploitability: {chain['exploitability_score']}/10
Description: {chain['description']}
            """)
            pdf.ln(3)
    
    # Recommendations
    pdf.add_page()
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Recommendations', 0, 1)
    pdf.set_font('Arial', '', 10)
    
    for i, rec in enumerate(results['recommendations'], 1):
        pdf.multi_cell(0, 5, f"{i}. {rec}")
    
    # Save
    pdf.output(output_file)
    print(f"Report saved to {output_file}")

if __name__ == '__main__':
    generate_report(
        'example.com',
        ['React', 'Node.js', 'MongoDB'],
        'vulnerability_report.pdf'
    )
```

---

## REST API Server

### Flask API Server

Create `api_server.py`:

```python
#!/usr/bin/env python3
"""REST API server for BugPredict AI"""

from flask import Flask, request, jsonify
from src.inference.predictor import ThreatPredictor
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Initialize predictor (loaded once at startup)
predictor = ThreatPredictor()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/api/v1/analyze', methods=['POST'])
def analyze():
    """Analyze a target"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'domain' not in data:
            return jsonify({'error': 'domain is required'}), 400
        
        # Analyze target
        results = predictor.analyze_target(data)
        
        return jsonify(results), 200
        
    except Exception as e:
        logging.error(f"Analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/batch', methods=['POST'])
def batch_analyze():
    """Analyze multiple targets"""
    try:
        data = request.get_json()
        
        if 'targets' not in data:
            return jsonify({'error': 'targets array is required'}), 400
        
        results = predictor.batch_analyze(data['targets'])
        
        return jsonify({'results': results}), 200
        
    except Exception as e:
        logging.error(f"Batch analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/models/info', methods=['GET'])
def model_info():
    """Get model information"""
    return jsonify(predictor.metadata), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

### Run the Server

**Bash:**
```bash
# Install Flask
pip install flask

# Run server
python api_server.py

# Server running on http://localhost:5000
```

**PowerShell:**
```powershell
# Install Flask
pip install flask

# Run server
python api_server.py
```

### API Usage Examples

**cURL:**
```bash
# Health check
curl http://localhost:5000/health

# Analyze single target
curl -X POST http://localhost:5000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "technology_stack": ["React", "Node.js"],
    "has_api": true
  }'

# Batch analysis
curl -X POST http://localhost:5000/api/v1/batch \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      {"domain": "site1.com"},
      {"domain": "site2.com"}
    ]
  }'

# Model info
curl http://localhost:5000/api/v1/models/info
```

**Python (requests):**
```python
import requests

# Analyze target
response = requests.post('http://localhost:5000/api/v1/analyze', json={
    'domain': 'example.com',
    'technology_stack': ['React', 'GraphQL'],
    'has_graphql': True
})

results = response.json()
print(f"Risk Score: {results['risk_score']}/10")
```

**JavaScript (fetch):**
```javascript
fetch('http://localhost:5000/api/v1/analyze', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    domain: 'example.com',
    technology_stack: ['React', 'Node.js']
  })
})
.then(res => res.json())
.then(data => console.log(data));
```

---

## Burp Suite Extension

### BugPredict AI Burp Extension

Create `burp_extension.py`:

```python
from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from java.util import ArrayList
import json
import sys
import os

# Add BugPredict AI to path
sys.path.insert(0, '/path/to/bugpredict-ai')
from src.inference.predictor import ThreatPredictor

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BugPredict AI")
        
        # Initialize predictor
        self.predictor = ThreatPredictor()
        
        # Register context menu
        callbacks.registerContextMenuFactory(self)
        
        print("BugPredict AI extension loaded")
    
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        
        # Add "Analyze with BugPredict AI" menu item
        menu_item = JMenuItem("Analyze with BugPredict AI")
        menu_item.addActionListener(lambda x: self.analyze_target(invocation))
        menu_items.add(menu_item)
        
        return menu_items
    
    def analyze_target(self, invocation):
        # Get selected messages
        messages = invocation.getSelectedMessages()
        
        if not messages:
            return
        
        # Extract host from first message
        http_service = messages[0].getHttpService()
        host = http_service.getHost()
        
        # Analyze
        target_info = {
            'domain': host,
            'has_api': True,
            'technology_stack': []  # Could detect from headers
        }
        
        results = self.predictor.analyze_target(target_info)
        
        # Display results
        print("\n" + "="*70)
        print(f"BugPredict AI Analysis: {host}")
        print("="*70)
        print(f"Risk Score: {results['risk_score']}/10")
        print("\nTop Vulnerabilities:")
        
        for vuln in results['vulnerability_predictions'][:5]:
            print(f"  - {vuln['vulnerability_type']}: {vuln['probability']:.0%}")
        
        print("\n" + "="*70)
```

**Installation:**
1. Save as `burp_extension.py`
2. Open Burp Suite → Extender → Extensions
3. Click "Add"
4. Select "Python" and choose `burp_extension.py`
5. Right-click on any request → "Analyze with BugPredict AI"

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security-scan.yml`:

```yaml
name: BugPredict AI Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install BugPredict AI
      run: |
        pip install bugpredict-ai
        # Or clone and install
        # git clone https://github.com/yourusername/bugpredict-ai.git
        # cd bugpredict-ai && pip install -r requirements.txt
    
    - name: Download models
      run: |
        # Download pre-trained models
        wget https://example.com/models.tar.gz
        tar -xzf models.tar.gz
    
    - name: Run security scan
      run: |
        python - <<EOF
        from src.inference.predictor import ThreatPredictor
        
        predictor = ThreatPredictor()
        results = predictor.analyze_target({
            'domain': '${{ github.repository }}',
            'technology_stack': ['React', 'Node.js'],
            'has_api': True
        })
        
        print(f"Risk Score: {results['risk_score']}/10")
        
        # Fail if high risk
        if results['risk_score'] >= 7.0:
            print("⚠️ High risk detected!")
            exit(1)
        EOF
    
    - name: Upload results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: results.json
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
security_scan:
  stage: test
  image: python:3.10
  script:
    - pip install bugpredict-ai
    - python scan.py
  artifacts:
    reports:
      junit: report.xml
    paths:
      - security_report.json
  only:
    - main
    - merge_requests
```

---

## Custom Integrations

### Slack Bot

```python
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from src.inference.predictor import ThreatPredictor

client = WebClient(token="xoxb-your-token")
predictor = ThreatPredictor()

def handle_scan_command(domain):
    """Handle /scan command from Slack"""
    
    results = predictor.analyze_target({'domain': domain})
    
    message = f"""
*Security Scan Results: {domain}*
Risk Score: {results['risk_score']}/10 ({results['risk_level']})

*Top Vulnerabilities:*
"""
    
    for vuln in results['vulnerability_predictions'][:5]:
        emoji = "🔴" if vuln['probability'] > 0.7 else "🟡" if vuln['probability'] > 0.5 else "🟢"
        message += f"{emoji} {vuln['vulnerability_type']}: {vuln['probability']:.0%}\n"
    
    try:
        client.chat_postMessage(channel="#security", text=message)
    except SlackApiError as e:
        print(f"Error: {e}")
```

### Discord Bot

```python
import discord
from src.inference.predictor import ThreatPredictor

client = discord.Client()
predictor = ThreatPredictor()

@client.event
async def on_message(message):
    if message.content.startswith('!scan'):
        domain = message.content.split()[1]
        
        results = predictor.analyze_target({'domain': domain})
        
        embed = discord.Embed(
            title=f"Security Scan: {domain}",
            color=0xff0000 if results['risk_score'] >= 7 else 0xffa500
        )
        
        embed.add_field(
            name="Risk Score",
            value=f"{results['risk_score']}/10",
            inline=False
        )
        
        vulns_text = "\n".join([
            f"• {v['vulnerability_type']}: {v['probability']:.0%}"
            for v in results['vulnerability_predictions'][:5]
        ])
        
        embed.add_field(
            name="Top Vulnerabilities",
            value=vulns_text,
            inline=False
        )
        
        await message.channel.send(embed=embed)

client.run('your-token')
```

---

## API Best Practices

### 1. Error Handling

```python
from src.inference.predictor import ThreatPredictor

predictor = ThreatPredictor()

try:
    results = predictor.analyze_target(target_info)
except FileNotFoundError as e:
    print(f"Models not found: {e}")
    print("Run: python scripts/train_model.py")
except ValueError as e:
    print(f"Invalid target info: {e}")
except Exception as e:
    print(f"Analysis failed: {e}")
```

### 2. Performance Optimization

```python
# Cache predictor instance (don't reload models every time)
class Scanner:
    def __init__(self):
        self.predictor = ThreatPredictor()  # Load once
    
    def scan(self, domain):
        return self.predictor.analyze_target({'domain': domain})

# Use batch analysis for multiple targets
scanner = Scanner()
results = scanner.predictor.batch_analyze(targets)  # More efficient
```

### 3. Memory Management

```python
import gc

# For long-running processes
def analyze_many_targets(targets):
    predictor = ThreatPredictor()
    
    for target in targets:
        results = predictor.analyze_target(target)
        
        # Process results...
        
        # Free memory periodically
        if len(results) % 100 == 0:
            gc.collect()
```

### 4. Logging

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bugpredict.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

predictor = ThreatPredictor()
logger.info("Predictor initialized")

results = predictor.analyze_target(target_info)
logger.info(f"Analyzed {target_info['domain']}: risk={results['risk_score']}")
```

---

## Support

For API issues:
- GitHub Issues: https://github.com/yourusername/bugpredict-ai/issues
- Documentation: https://bugpredict-ai.readthedocs.io
- Examples: https://github.com/yourusername/bugpredict-ai/tree/main/examples

---

**Happy Integrating! 🔌**
```

---

✅ **API.md Complete!**

Ready for the next one: **DEPLOYMENT.md**? 🚀
