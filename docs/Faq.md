# ❓ BugPredict AI - Frequently Asked Questions

> Common questions and answers about BugPredict AI

---

## 📋 Table of Contents

1. [General Questions](#general-questions)
2. [Installation & Setup](#installation--setup)
3. [Data Collection](#data-collection)
4. [Training](#training)
5. [Models & Predictions](#models--predictions)
6. [Performance & Optimization](#performance--optimization)
7. [Deployment](#deployment)
8. [Troubleshooting](#troubleshooting)
9. [Security & Privacy](#security--privacy)
10. [Integration](#integration)
11. [Contributing](#contributing)
12. [Commercial Use](#commercial-use)

---

## General Questions

### What is BugPredict AI?

BugPredict AI is an AI-powered vulnerability prediction system that uses machine learning to:
- Predict 40+ vulnerability types
- Detect 25+ attack chains
- Generate actionable test strategies
- Provide risk scoring and recommendations

It's designed for bug bounty hunters, penetration testers, and security researchers.

---

### How accurate is BugPredict AI?

Accuracy depends on training data quality and quantity:

| Training Data | Expected Accuracy | F1 Score |
|--------------|-------------------|----------|
| 1,000 reports | 65-75% | 0.65-0.75 |
| 5,000 reports | 75-85% | 0.75-0.85 |
| 10,000+ reports | 85-90% | 0.85-0.90 |

**Ensemble models** typically achieve 5-10% higher accuracy than single models.

---

### What makes BugPredict AI different from other tools?

**Unique Features:**
1. **ML-Powered Predictions**: Uses ensemble of 5 models
2. **Attack Chain Detection**: Identifies multi-step exploits
3. **Test Strategy Generation**: Provides actionable recommendations
4. **Technology-Aware**: Predictions based on tech stack
5. **Extensible**: Easy to add custom vulnerability types
6. **Production-Ready**: Complete deployment documentation

---

### Is BugPredict AI free?

Yes! BugPredict AI is **open source** under the MIT License. You can:
- ✅ Use for personal projects
- ✅ Use for commercial projects
- ✅ Modify and distribute
- ✅ Use in bug bounty hunting

**No attribution required** (but appreciated!)

---

### What programming language is BugPredict AI written in?

**Primary Language**: Python 3.10+

**Key Libraries**:
- scikit-learn, XGBoost, LightGBM, CatBoost (ML)
- pandas, numpy (data processing)
- Flask (API server)
- networkx (chain detection)

---

## Installation & Setup

### What are the system requirements?

**Minimum:**
- Python 3.10+
- 8GB RAM
- 4 CPU cores
- 10GB disk space

**Recommended:**
- Python 3.10+
- 16GB+ RAM
- 8+ CPU cores
- 20GB+ SSD
- GPU (optional, speeds up training)

---

### How do I install BugPredict AI?

**Quick Install:**

**Bash:**
```bash
git clone https://github.com/yourusername/bugpredict-ai.git
cd bugpredict-ai
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**PowerShell:**
```powershell
git clone https://github.com/yourusername/bugpredict-ai.git
cd bugpredict-ai
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

See [README.md](../README.md) for detailed instructions.

---

### Do I need GPU for BugPredict AI?

**No, GPU is optional.**

- **Training**: GPU speeds up XGBoost/LightGBM training (~2-3x faster)
- **Inference**: CPU is sufficient (GPU provides minimal benefit)

Most users run BugPredict AI on CPU successfully.

---

### Can I run BugPredict AI on Windows?

**Yes!** BugPredict AI works on:
- ✅ Windows 10/11
- ✅ macOS
- ✅ Linux (Ubuntu, Debian, CentOS, etc.)
- ✅ Docker containers

PowerShell scripts are provided for Windows users.

---

### Installation fails with "ModuleNotFoundError"

**Solution:**
```bash
# Ensure you're in virtual environment
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\Activate.ps1  # Windows

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python -c "import sklearn, xgboost, lightgbm; print('OK')"
```

---

## Data Collection

### Do I need API keys?

**Optional but recommended:**

| Source | Required? | Benefit |
|--------|-----------|---------|
| HackerOne | Optional | More data, faster collection |
| Bugcrowd | Optional | More data, faster collection |
| NVD/CVE | Optional | 10x faster (5→50 req/30s) |

**Without API keys**, BugPredict AI uses:
- Web scraping (slower)
- Public data sources
- Cached data

---

### How do I get API keys?

**HackerOne:**
1. Login to HackerOne
2. Go to Settings → API Tokens
3. Create new token
4. Copy token

**NVD:**
1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Request API key (free)
3. Receive key via email

**Bugcrowd:**
- Contact Bugcrowd support for API access

---

### How much data do I need for training?

**Minimum:** 1,000 reports (quick testing)
**Recommended:** 5,000-10,000 reports (production)
**Optimal:** 20,000+ reports (best accuracy)

**Data Mix:**
- HackerOne: ~50%
- CVE/NVD: ~30%
- Bugcrowd: ~20%

---

### How long does data collection take?

| Amount | Time (with API keys) | Time (without) |
|--------|---------------------|----------------|
| 1,000 reports | ~5-10 minutes | ~30-60 minutes |
| 5,000 reports | ~20-30 minutes | ~2-3 hours |
| 10,000 reports | ~40-60 minutes | ~4-6 hours |

**Caching** speeds up subsequent collections.

---

### Can I use my own vulnerability data?

**Yes!** Create a custom collector:
```python
from src.collectors.data_sources import DataCollector, VulnerabilityReport

class MyCollector(DataCollector):
    def collect(self, limit):
        # Your data collection logic
        pass
    
    def normalize(self, raw_data):
        # Convert to VulnerabilityReport
        return VulnerabilityReport(...)
```

See [CUSTOMIZATION.md](CUSTOMIZATION.md) for details.

---

### Data collection fails with rate limit errors

**Solution:**

1. **Use API keys** (dramatically increases limits)
2. **Enable caching** (avoids repeat requests)
3. **Reduce collection speed**:
```yaml
# config/training_config.yaml
data_collection:
  rate_limit_delay: 2  # seconds between requests
```

---

## Training

### How long does training take?

| Data Size | Hardware | Time |
|-----------|----------|------|
| 1,000 reports | 4 CPU, 8GB RAM | ~5 minutes |
| 5,000 reports | 8 CPU, 16GB RAM | ~20 minutes |
| 10,000 reports | 8 CPU, 16GB RAM | ~45 minutes |
| 20,000 reports | 16 CPU, 32GB RAM | ~2 hours |

**GPU** reduces training time by ~30-50%.

---

### Do I need to retrain models?

**Retrain when:**
- ✅ Adding new vulnerability types
- ✅ Collecting significantly more data
- ✅ Model accuracy drops below 75%
- ✅ New attack patterns emerge
- ✅ Monthly (recommended for production)

**Don't retrain** for every small data addition.

---

### Training runs out of memory

**Solutions:**

1. **Reduce data size**:
```yaml
data_collection:
  hackerone_limit: 2000  # Reduce from 5000
  cve_limit: 1000        # Reduce from 3000
```

2. **Use quick training mode**:
```bash
python scripts/train_model.py --quick
```

3. **Increase system RAM** or use cloud instance

4. **Disable cross-validation**:
```yaml
training:
  perform_cv: false
```

---

### Can I train on a subset of vulnerability types?

**Yes!** Filter before training:
```python
from src.training.pipeline import TrainingPipeline

pipeline = TrainingPipeline()
reports = pipeline.collect_data()

# Filter for specific types
target_types = ['XSS', 'SQL Injection', 'IDOR']
filtered = [r for r in reports if r.vulnerability_type in target_types]

pipeline.raw_reports = filtered
pipeline.run_full_pipeline()
```

---

### Training accuracy is low (<70%)

**Troubleshooting:**

1. **Check data quality**:
   - Are vulnerability types correctly labeled?
   - Is there enough data per type?
   - Are there duplicates?

2. **Increase training data**:
```bash
   python scripts/collect_data.py --source all --limit 15000
```

3. **Check class imbalance**:
```python
   from collections import Counter
   types = [r.vulnerability_type for r in reports]
   print(Counter(types))
```

4. **Tune hyperparameters** (see [TRAINING.md](TRAINING.md))

---

### Can I use pre-trained models?

**Yes!** Pre-trained models coming soon:

- Download from releases page
- Place in `data/models/`
- Start predicting immediately

**Note**: Pre-trained models are trained on public data only.

---

## Models & Predictions

### What vulnerability types can BugPredict AI detect?

**40+ types including:**

- Access Control (IDOR, Broken Authorization, Privilege Escalation)
- Authentication (JWT, Broken Auth, Session Issues)
- Injection (SQL, NoSQL, Command, XSS)
- API Security (API Abuse, Rate Limits, GraphQL)
- Cloud (AWS Misconfig, S3 Exposure, SSRF)
- Business Logic, CSRF, File Upload, and more

See [README.md](../README.md) for complete list.

---

### How does the ensemble model work?

BugPredict AI uses **5 different models**:
1. Random Forest
2. XGBoost
3. LightGBM
4. CatBoost
5. Gradient Boosting

**Prediction Process:**
1. Each model makes predictions
2. Probabilities are averaged (or voted)
3. Final prediction is consensus

**Benefits:**
- More robust than single model
- Higher accuracy
- Confidence scoring via model agreement

---

### What is "model agreement" score?

**Model agreement** shows how much models agree:

- **0.9-1.0**: Very confident (all models agree)
- **0.7-0.9**: Confident (most models agree)
- **0.5-0.7**: Moderate confidence
- **<0.5**: Low confidence (models disagree)

Use this to gauge prediction reliability.

---

### Can I use only specific models?

**Yes!**
```python
from src.inference.predictor import ThreatPredictor

predictor = ThreatPredictor()

# Use only XGBoost
results = predictor.analyze_target(target_info, model='xgboost')

# Or specific ensemble method
results = predictor.analyze_target(target_info, method='weighted')
```

---

### How are attack chains detected?

**Two methods:**

1. **Pattern Matching**: 25+ pre-defined chains
   - Example: SQL Injection → Info Disclosure → File Upload → RCE

2. **Graph-Based Discovery**: Automatic path finding
   - Builds vulnerability graph
   - Finds all possible paths
   - Ranks by exploitability

---

### Predictions seem inaccurate for my target

**Common causes:**

1. **Tech stack mismatch**: Specify accurate technologies
```python
   target_info = {
       'technology_stack': ['React', 'GraphQL', 'MongoDB']  # Be specific
   }
```

2. **Insufficient training data**: Collect more data for your domain

3. **Model needs retraining**: Retrain with recent data
```bash
   python scripts/train_model.py
```

4. **Use ensemble predictions**: Single models may be less accurate

---

## Performance & Optimization

### How fast is prediction?

**Typical latency:**
- Single prediction: 500ms - 2s
- Batch (10 targets): 3-5s
- Depends on: CPU, feature count, ensemble size

**Optimization tips:**
1. Use CPU with multiple cores
2. Enable caching (Redis)
3. Reduce ensemble size if needed

---

### Can I speed up predictions?

**Yes! Several options:**

1. **Enable caching**:
```python
   import redis
   redis_client = redis.Redis(host='localhost')
   # Cache results for 1 hour
```

2. **Use fewer models**:
```python
   # Use only top 3 models
   predictor.models = {
       'xgboost': predictor.models['xgboost'],
       'lightgbm': predictor.models['lightgbm'],
       'catboost': predictor.models['catboost']
   }
```

3. **Reduce feature count**:
```yaml
   feature_engineering:
     tfidf_max_features: 50  # Reduce from 100
```

---

### Memory usage is too high

**Solutions:**

1. **Reduce loaded models**:
```python
   # Load only when needed
   predictor.load_model_on_demand('xgboost')
```

2. **Use model compression**:
```bash
   # Compress pickle files
   gzip data/models/*.pkl
```

3. **Batch processing**: Process multiple targets together

4. **Increase system RAM** or use swap

---

### Can BugPredict AI handle thousands of targets?

**Yes!** Use batch processing:
```python
targets = [...]  # 1000 targets

# Process in batches
batch_size = 100
for i in range(0, len(targets), batch_size):
    batch = targets[i:i+batch_size]
    results = predictor.batch_analyze(batch)
```

**For large-scale**:
- Deploy on Kubernetes with auto-scaling
- Use Redis caching
- Implement request queuing

---

## Deployment

### How do I deploy BugPredict AI to production?

**Multiple options:**

1. **Docker** (recommended for beginners):
```bash
   docker-compose up -d
```

2. **Kubernetes** (recommended for scale):
```bash
   kubectl apply -f k8s/
```

3. **Cloud services**:
   - AWS ECS/EKS
   - Google Cloud Run
   - Azure Container Instances

See [DEPLOYMENT.md](DEPLOYMENT.md) for complete guides.

---

### What cloud provider do you recommend?

**All work well, but:**

- **AWS**: Most features, complex
- **GCP**: Easy deployment, Cloud Run excellent
- **Azure**: Good Windows integration
- **DigitalOcean**: Simple, cost-effective

**Recommendation**: Start with **Google Cloud Run** (easiest) or **Docker** (most portable).

---

### How do I scale BugPredict AI?

**Horizontal Scaling:**
```yaml
# docker-compose.yml
services:
  api:
    deploy:
      replicas: 5  # 5 instances
```

**Kubernetes Auto-scaling:**
```yaml
# k8s/hpa.yaml
spec:
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

**Load Balancing**: Nginx, AWS ALB, or GCP Load Balancer

---

### How do I secure the API?

1. **Enable authentication**:
```python
   # JWT tokens, API keys, OAuth
```

2. **Rate limiting**:
```python
   from flask_limiter import Limiter
   limiter.limit("100 per hour")
```

3. **HTTPS only**:
```nginx
   # Force HTTPS redirect
   return 301 https://$server_name$request_uri;
```

4. **Input validation**:
```python
   from marshmallow import Schema
   # Validate all inputs
```

See [DEPLOYMENT.md](DEPLOYMENT.md#security-hardening) for details.

---

### Can I deploy without Docker?

**Yes!** Run directly:
```bash
# Install dependencies
pip install -r requirements.txt
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 api_server:app
```

**Or use systemd** (Linux):
```ini
[Unit]
Description=BugPredict AI

[Service]
ExecStart=/path/to/venv/bin/gunicorn -w 4 api_server:app
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## Troubleshooting

### "Models not found" error

**Solution:**
```bash
# Train models first
python scripts/train_model.py --quick

# Verify models exist
ls data/models/
# Should see: vulnerability_predictor.pkl, severity_predictor.pkl, etc.
```

---

### Predictions always return "Other"

**Causes:**

1. **Models not trained properly**:
```bash
   # Check training metrics
   cat data/results/training_summary.txt
```

2. **Enhanced extractor not used**:
```python
   # Ensure using EnhancedVulnerabilityExtractor
   from src.collectors.enhanced_extractor import EnhancedVulnerabilityExtractor
```

3. **Insufficient training data**:
```bash
   # Collect more data
   python scripts/collect_data.py --source all --limit 10000
```

---

### API returns 500 error

**Debug steps:**

1. **Check logs**:
```bash
   docker logs bugpredict-api
   # or
   tail -f logs/bugpredict.log
```

2. **Test locally**:
```python
   from src.inference.predictor import ThreatPredictor
   predictor = ThreatPredictor()
   # Should not raise errors
```

3. **Verify models loaded**:
```bash
   curl http://localhost:5000/health
```

4. **Check memory**:
```bash
   free -h  # Linux
```

---

### ImportError or ModuleNotFoundError

**Solution:**
```bash
# Add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"  # Linux/Mac
$env:PYTHONPATH="$env:PYTHONPATH;$(Get-Location)"  # PowerShell

# Or install as package
pip install -e .
```

---

### Jupyter notebook kernel crashes

**Causes:**
- Out of memory
- Large datasets

**Solutions:**

1. **Increase memory limit**:
```bash
   # Start Jupyter with more memory
   jupyter notebook --NotebookApp.max_buffer_size=1073741824
```

2. **Use smaller datasets**:
```python
   # Sample data
   reports = reports[:1000]
```

3. **Clear output**:
```python
   from IPython.display import clear_output
   clear_output()
```

---

## Security & Privacy

### Does BugPredict AI send data externally?

**No!** BugPredict AI:
- ✅ Runs completely locally
- ✅ Doesn't send data to external servers
- ✅ Doesn't require internet (after installation)

**Only external calls:**
- Data collection APIs (HackerOne, NVD) - optional
- These can be disabled for air-gapped environments

---

### Is my training data safe?

**Yes!** Your data stays on your system:
- Stored locally in `data/` directory
- Models stored as pickle files
- No cloud uploads
- No telemetry

**Best practices:**
- Encrypt `data/` directory
- Use access controls
- Regular backups

---

### Can I use BugPredict AI on sensitive targets?

**Yes, but:**
1. **Don't include sensitive data** in analysis
2. **Use generic descriptions** if needed
3. **Deploy in secure environment**
4. **Control access** to API/models
5. **Review output** before sharing

**Recommendation**: Use on public bug bounty targets only.

---

### Does BugPredict AI comply with GDPR/privacy laws?

BugPredict AI itself **doesn't collect personal data**.

**Your responsibility:**
- Ensure training data complies with privacy laws
- Don't train on data containing PII
- Follow responsible disclosure
- Respect target privacy

---

## Integration

### Can I integrate with Burp Suite?

**Yes!** See [API.md](API.md#burp-suite-extension) for Burp extension.

**Quick setup:**
1. Load extension in Burp
2. Right-click request → "Analyze with BugPredict AI"
3. View predictions in Burp output

---

### Can I use BugPredict AI in CI/CD?

**Yes!** Example GitHub Actions:
```yaml
- name: Security Scan
  run: |
    python scripts/analyze_target.py \
      --domain ${{ github.repository }} \
      --output results.json
    
    # Fail if high risk
    python - <<EOF
    import json
    with open('results.json') as f:
        data = json.load(f)
    if data['risk_score'] >= 7.0:
        exit(1)
    EOF
```

See [API.md](API.md#cicd-integration) for more examples.

---

### Can I integrate with Slack/Discord?

**Yes!** Create a plugin:
```python
# custom/plugins/slack_plugin.py
class SlackPlugin(BugPredictPlugin):
    def on_analysis_complete(self, results):
        if results['risk_score'] >= 7:
            send_slack_notification(results)
        return results
```

See [CUSTOMIZATION.md](CUSTOMIZATION.md#plugin-system).

---

### Does BugPredict AI have a REST API?

**Yes!** Flask API server included:
```bash
# Start API server
python api_server.py

# Use API
curl -X POST http://localhost:5000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

See [API.md](API.md) for complete documentation.

---

### Can I use BugPredict AI in other languages?

**Via REST API**, yes!

**JavaScript:**
```javascript
fetch('http://localhost:5000/api/v1/analyze', {
  method: 'POST',
  body: JSON.stringify({domain: 'example.com'})
})
```

**Go:**
```go
resp, err := http.Post(
    "http://localhost:5000/api/v1/analyze",
    "application/json",
    body
)
```

---

## Contributing

### How can I contribute?

**Ways to contribute:**
1. 🐛 Report bugs via GitHub Issues
2. 💡 Suggest features via Discussions
3. 📝 Improve documentation
4. 🔧 Submit pull requests
5. ⭐ Star the repository
6. 📢 Share with others

---

### I found a bug, what should I do?

1. **Check existing issues**: https://github.com/yourusername/bugpredict-ai/issues
2. **Create new issue** with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - System info (OS, Python version)
   - Error logs

---

### Can I add new vulnerability types?

**Yes!** See [CUSTOMIZATION.md](CUSTOMIZATION.md#adding-custom-vulnerability-types)

**Process:**
1. Add detection keywords
2. Add to enhanced extractor
3. Add test cases
4. Retrain models
5. Submit PR (optional)

---

### How do I submit a pull request?

1. Fork repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes
4. Add tests
5. Run tests: `pytest tests/ -v`
6. Commit: `git commit -m "Add amazing feature"`
7. Push: `git push origin feature/amazing-feature`
8. Open Pull Request on GitHub

---

## Commercial Use

### Can I use BugPredict AI commercially?

**Yes!** MIT License allows:
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use

**No attribution required** (but appreciated!)

---

### Can I sell services using BugPredict AI?

**Yes!** You can:
- Offer vulnerability assessment services
- Build commercial tools on top
- Integrate into paid products
- Provide hosted API service

**No restrictions** under MIT License.

---

### Do I need to open-source my modifications?

**No!** MIT License doesn't require:
- Publishing your code
- Sharing modifications
- Open-sourcing derivatives

You **can** keep modifications private.

---

### Can I rebrand BugPredict AI?

**Yes!** MIT License allows:
- Rebranding
- White-labeling
- Custom versions
- Proprietary distributions

**Just include** MIT License notice in your distribution.

---

## Still Have Questions?

### Where can I get help?

**Resources:**
- 📖 Documentation: [docs/](../docs/)
- 💬 GitHub Discussions: https://github.com/yourusername/bugpredict-ai/discussions
- 🐛 Issues: https://github.com/yourusername/bugpredict-ai/issues
- 📧 Email: support@bugpredict-ai.example.com

---

### How often is BugPredict AI updated?

**Regular updates include:**
- New vulnerability types
- Model improvements
- Bug fixes
- Documentation updates
- New features

**Check releases**: https://github.com/yourusername/bugpredict-ai/releases

---

### What's the roadmap?

**Planned features:**
- Web UI dashboard
- Real-time scanning
- Browser extension
- More integrations (Jira, Linear, etc.)
- Cloud-native deployment
- Advanced ML models
- Mobile app

See [GitHub Issues](https://github.com/yourusername/bugpredict-ai/issues) with "enhancement" label.

---

### How can I stay updated?

1. ⭐ **Star** the repository
2. 👀 **Watch** for releases
3. 📧 **Subscribe** to newsletter (coming soon)
4. 🐦 **Follow** on Twitter (coming soon)
5. 💬 **Join** Discord (coming soon)

---

**Didn't find your question? Ask on [GitHub Discussions](https://github.com/yourusername/bugpredict-ai/discussions)!**

*Documentation last updated: 2024-02-05*
