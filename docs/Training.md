## 📄 File: `docs/TRAINING.md` (Complete Training Guide)

```markdown
# 🎓 BugPredict AI - Complete Training Guide

> Comprehensive guide to training ML models for vulnerability prediction

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start Training](#quick-start-training)
4. [Data Collection](#data-collection)
5. [Training Configuration](#training-configuration)
6. [Training Pipeline](#training-pipeline)
7. [Model Architecture](#model-architecture)
8. [Monitoring Training](#monitoring-training)
9. [Evaluation & Metrics](#evaluation--metrics)
10. [Advanced Training](#advanced-training)
11. [Troubleshooting](#troubleshooting)
12. [Best Practices](#best-practices)

---

## Overview

BugPredict AI uses an ensemble of machine learning models to predict vulnerabilities. The training pipeline includes:

- **Data Collection**: HackerOne, Bugcrowd, NVD/CVE
- **Preprocessing**: Normalization, deduplication, enrichment
- **Feature Engineering**: 100+ features extracted
- **Model Training**: 5 ensemble models per classifier
- **Evaluation**: Cross-validation and test set evaluation

### Models Trained

1. **VulnerabilityPredictor**: Multi-class classifier (40+ vulnerability types)
   - Random Forest
   - XGBoost
   - LightGBM
   - CatBoost
   - Gradient Boosting

2. **SeverityPredictor**: Severity classification + CVSS regression
   - XGBoost Classifier (severity)
   - XGBoost Regressor (CVSS score)

3. **ChainDetector**: Attack chain detection
   - 25+ pre-defined patterns
   - Graph-based discovery

---

## Prerequisites

### Hardware Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8GB
- Storage: 10GB free

**Recommended:**
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 20GB+ SSD
- GPU: Optional (speeds up XGBoost/LightGBM)

### Software Requirements

- Python 3.10+
- pip
- Virtual environment (recommended)

### API Keys (Optional but Recommended)

- **HackerOne API Token**: For collecting HackerOne reports
- **Bugcrowd API Token**: For collecting Bugcrowd reports
- **NVD API Key**: For faster CVE collection (5→50 requests/30s)

**Get API Keys:**
- HackerOne: https://docs.hackerone.com/programs/api-tokens.html
- Bugcrowd: Contact Bugcrowd support
- NVD: https://nvd.nist.gov/developers/request-an-api-key

---

## Quick Start Training

### 1. Express Training (5 minutes)

For quick testing with minimal data:

**Bash:**
```bash
# Activate environment
source venv/bin/activate

# Quick training with reduced data
python scripts/train_model.py --quick

# Expected output:
# ✓ Collected 500 HackerOne reports
# ✓ Collected 200 CVEs
# ✓ Training completed in ~5 minutes
# ✓ Models saved to data/models/
```

**PowerShell:**
```powershell
# Activate environment
.\venv\Scripts\Activate.ps1

# Quick training with reduced data
python scripts/train_model.py --quick
```

### 2. Standard Training (30-60 minutes)

For production-quality models:

**Bash:**
```bash
# Full training pipeline
python scripts/train_model.py

# With API keys (faster collection)
export HACKERONE_TOKEN="your_token"
export NVD_API_KEY="your_key"
python scripts/train_model.py
```

**PowerShell:**
```powershell
# Full training pipeline
python scripts/train_model.py

# With API keys
$env:HACKERONE_TOKEN="your_token"
$env:NVD_API_KEY="your_key"
python scripts/train_model.py
```

---

## Data Collection

### Step 1: Collect Vulnerability Data

The training pipeline automatically collects data, but you can also collect manually:

**Collect from All Sources:**

**Bash:**
```bash
python scripts/collect_data.py \
  --source all \
  --limit 10000 \
  --output data/raw
```

**PowerShell:**
```powershell
python scripts/collect_data.py `
  --source all `
  --limit 10000 `
  --output data/raw
```

**Collect from Specific Sources:**

**Bash:**
```bash
# HackerOne only
python scripts/collect_data.py \
  --source hackerone \
  --limit 5000 \
  --hackerone-token $HACKERONE_TOKEN

# Bugcrowd only
python scripts/collect_data.py \
  --source bugcrowd \
  --limit 2000 \
  --bugcrowd-token $BUGCROWD_TOKEN

# CVE/NVD only (last 365 days)
python scripts/collect_data.py \
  --source cve \
  --days-back 365 \
  --limit 3000 \
  --nvd-api-key $NVD_API_KEY
```

**PowerShell:**
```powershell
# HackerOne only
python scripts/collect_data.py `
  --source hackerone `
  --limit 5000 `
  --hackerone-token $env:HACKERONE_TOKEN

# Bugcrowd only
python scripts/collect_data.py `
  --source bugcrowd `
  --limit 2000 `
  --bugcrowd-token $env:BUGCROWD_TOKEN

# CVE/NVD only (last 365 days)
python scripts/collect_data.py `
  --source cve `
  --days-back 365 `
  --limit 3000 `
  --nvd-api-key $env:NVD_API_KEY
```

### Data Collection Output

```
Collecting from HackerOne...
  → HackerOne: 5000 reports
  ✓ Saved to data/cache/hackerone_reports.pkl

Collecting from Bugcrowd...
  → Bugcrowd: 2000 reports
  ✓ Saved to data/cache/bugcrowd_reports.pkl

Collecting from NVD...
Date range: 2023-01-01 to 2024-02-04
  → NVD: 3000 reports
  ✓ Saved to data/cache/cve_reports.pkl

Total collected: 10000 reports
```

### Recommended Data Sizes

| Training Goal | HackerOne | Bugcrowd | CVE | Total | Training Time |
|---------------|-----------|----------|-----|-------|---------------|
| Quick Test | 500 | 200 | 300 | 1,000 | ~5 min |
| Development | 2,000 | 1,000 | 1,000 | 4,000 | ~15 min |
| Production | 5,000 | 2,000 | 3,000 | 10,000 | ~45 min |
| High Quality | 10,000 | 5,000 | 5,000 | 20,000 | ~2 hours |

---

## Training Configuration

### Configuration File: `config/training_config.yaml`

```yaml
# Data Collection Settings
data_collection:
  # HackerOne
  collect_hackerone: true
  hackerone_limit: 5000
  hackerone_token: null  # Or set via env var
  
  # Bugcrowd
  collect_bugcrowd: true
  bugcrowd_limit: 2000
  bugcrowd_token: null  # Or set via env var
  
  # NVD/CVE
  collect_cve: true
  cve_start_date: '2020-01-01'
  cve_limit: 3000
  nvd_api_key: null  # Or set via env var

# Preprocessing Settings
preprocessing:
  remove_duplicates: true
  normalize_text: true
  min_report_quality: 0.5
  
  # Text normalization
  lowercase: true
  remove_special_chars: false
  max_description_length: 5000

# Feature Engineering Settings
feature_engineering:
  # Text features
  tfidf_max_features: 100
  tfidf_ngram_range: [1, 2]
  
  # Technology features
  extract_tech_stack: true
  common_technologies: 22
  
  # Temporal features
  include_time_features: true
  
  # Statistical features
  compute_company_stats: true
  compute_vuln_stats: true

# Training Settings
training:
  # Data split
  test_size: 0.2
  validation_size: 0.1
  random_state: 42
  
  # Cross-validation
  perform_cv: true
  cv_folds: 5
  
  # Model selection
  train_vulnerability_predictor: true
  train_severity_predictor: true
  train_chain_detector: true

# Model Hyperparameters
models:
  random_forest:
    n_estimators: 200
    max_depth: 15
    min_samples_split: 5
    
  xgboost:
    n_estimators: 200
    max_depth: 10
    learning_rate: 0.1
    
  lightgbm:
    n_estimators: 200
    max_depth: 10
    learning_rate: 0.1
    
  catboost:
    iterations: 200
    depth: 10
    learning_rate: 0.1

# Output Settings
output:
  models_dir: 'data/models'
  results_dir: 'data/results'
  save_feature_importance: true
  save_training_history: true
  save_predictions: true
```

### Using Custom Configuration

**Bash:**
```bash
# Edit configuration
nano config/training_config.yaml

# Train with custom config
python scripts/train_model.py \
  --config config/training_config.yaml
```

**PowerShell:**
```powershell
# Edit configuration
notepad config/training_config.yaml

# Train with custom config
python scripts/train_model.py `
  --config config/training_config.yaml
```

---

## Training Pipeline

### Full Pipeline Stages

```
[STAGE 1] Data Collection
    ↓
[STAGE 2] Data Preprocessing
    ├── Normalization
    ├── Deduplication
    └── Enrichment
    ↓
[STAGE 3] Feature Engineering
    ├── Basic features (40+)
    ├── Technology features (20+)
    ├── Text features (TF-IDF)
    ├── Temporal features (10+)
    ├── Interaction features
    └── Statistical features
    ↓
[STAGE 4] Train/Test Split
    ├── Stratified split
    └── Validation split
    ↓
[STAGE 5] Model Training
    ├── VulnerabilityPredictor
    │   ├── Random Forest
    │   ├── XGBoost
    │   ├── LightGBM
    │   ├── CatBoost
    │   └── Gradient Boosting
    ├── SeverityPredictor
    │   ├── Severity Classifier
    │   └── CVSS Regressor
    └── ChainDetector
        └── Pattern Matching
    ↓
[STAGE 6] Model Evaluation
    ├── Test set evaluation
    ├── Cross-validation
    ├── Confusion matrices
    └── Feature importance
    ↓
[STAGE 7] Model Persistence
    ├── Save models
    ├── Save feature engineer
    ├── Save metrics
    └── Generate reports
```

### Pipeline Execution

**Bash:**
```bash
python scripts/train_model.py
```

**PowerShell:**
```powershell
python scripts/train_model.py
```

**Expected Output:**
```
================================================================================================
BUGPREDICT AI TRAINING PIPELINE
================================================================================================

[STEP 1/7] Data Collection
--------------------------------------------------------------------------------
Collecting from HackerOne...
  → HackerOne: 5000 reports
Collecting from Bugcrowd...
  → Bugcrowd: 2000 reports
Collecting from NVD...
  → NVD: 3000 reports
✓ Collected 10000 vulnerability reports

[STEP 2/7] Data Preprocessing
--------------------------------------------------------------------------------
Normalizing data...
  → Normalized: 10000 reports
Removing duplicates...
  → Deduplicated: 9547 reports
Enriching data...
  → Enriched: 9547 reports
✓ Preprocessed 9547 reports

[STEP 3/7] Feature Engineering
--------------------------------------------------------------------------------
Engineering features from 9547 reports...

Building vocabularies...
Adding technology features...
Adding text features...
Adding temporal features...
Encoding categorical variables...
Adding interaction features...
Adding statistical features...

✓ Generated 156 features

[STEP 4/7] Data Splitting
--------------------------------------------------------------------------------
Features shape: (9547, 156)
Target classes: 42

Train set: 6873 samples
Validation set: 764 samples
Test set: 1910 samples

[STEP 5/7] Model Training
--------------------------------------------------------------------------------

================================================================================================
TRAINING VULNERABILITY CLASSIFIER
================================================================================================

Building ensemble models...
Built 5 models

Training random_forest...
Train Accuracy: 0.9823 | F1: 0.9814
Val Accuracy:   0.8456 | F1: 0.8392
Test Accuracy:  0.8312 | F1: 0.8267
Performing 5-fold cross-validation...
CV F1 Score: 0.8401 (+/- 0.0234)
✓ random_forest training complete

Training xgboost...
Train Accuracy: 0.9654 | F1: 0.9628
Val Accuracy:   0.8723 | F1: 0.8687
Test Accuracy:  0.8598 | F1: 0.8556
Performing 5-fold cross-validation...
CV F1 Score: 0.8645 (+/- 0.0189)
✓ xgboost training complete

Training lightgbm...
Train Accuracy: 0.9589 | F1: 0.9567
Val Accuracy:   0.8689 | F1: 0.8654
Test Accuracy:  0.8567 | F1: 0.8523
Performing 5-fold cross-validation...
CV F1 Score: 0.8612 (+/- 0.0201)
✓ lightgbm training complete

Training catboost...
Train Accuracy: 0.9612 | F1: 0.9593
Val Accuracy:   0.8712 | F1: 0.8678
Test Accuracy:  0.8589 | F1: 0.8547
Performing 5-fold cross-validation...
CV F1 Score: 0.8634 (+/- 0.0195)
✓ catboost training complete

Training gradient_boosting...
Train Accuracy: 0.9234 | F1: 0.9198
Val Accuracy:   0.8512 | F1: 0.8467
Test Accuracy:  0.8423 | F1: 0.8378
Performing 5-fold cross-validation...
CV F1 Score: 0.8489 (+/- 0.0223)
✓ gradient_boosting training complete

================================================================================================
ENSEMBLE SUMMARY
================================================================================================
random_forest        - Test F1: 0.8267
xgboost             - Test F1: 0.8556
lightgbm            - Test F1: 0.8523
catboost            - Test F1: 0.8547
gradient_boosting   - Test F1: 0.8378

================================================================================================
TRAINING SEVERITY PREDICTOR
================================================================================================

Building xgboost severity predictor...
✓ Built xgboost models

Training Severity Classifier...
Train Accuracy: 0.8734 | F1: 0.8698
Test Accuracy:  0.8456 | F1: 0.8412
Performing 5-fold cross-validation...
CV F1 Score: 0.8501 (+/- 0.0178)

Training CVSS Score Regressor...
Train MSE: 0.4523 | MAE: 0.5234 | R²: 0.8234
Test MSE:  0.5234 | MAE: 0.5678 | R²: 0.7956

✓ SeverityPredictor training complete

================================================================================================
INITIALIZING CHAIN DETECTOR
================================================================================================
Chain patterns loaded: 25
Chains detectable: 15

[STEP 6/7] Model Evaluation
--------------------------------------------------------------------------------
Evaluating VulnerabilityPredictor...
Ensemble Accuracy: 0.8612
Ensemble F1 Score: 0.8578

Top 10 Most Important Features:
  1. tech_react: 0.0823
  2. cvss_score: 0.0756
  3. tech_nodejs: 0.0634
  4. vulnerability_type_encoded: 0.0598
  5. tech_stack_count: 0.0534
  6. has_api: 0.0487
  7. auth_required: 0.0456
  8. company_avg_severity: 0.0423
  9. tech_mongodb: 0.0398
  10. has_database: 0.0367

[STEP 7/7] Saving Models & Results
--------------------------------------------------------------------------------
  ✓ Saved vulnerability_predictor
  ✓ Saved severity_predictor
  ✓ Saved chain_detector
  ✓ Saved feature_engineer
  ✓ Saved metadata
  ✓ Saved training metrics
  ✓ Saved summary report

================================================================================================
✓ TRAINING PIPELINE COMPLETED SUCCESSFULLY
Duration: 0:47:23
================================================================================================
```

---

## Model Architecture

### VulnerabilityPredictor Architecture

```
Input: 156 features
    ↓
┌─────────────────────────────────────┐
│   Ensemble of 5 Models              │
├─────────────────────────────────────┤
│ 1. Random Forest (200 trees)        │
│    - max_depth: 15                  │
│    - min_samples_split: 5           │
│                                     │
│ 2. XGBoost (200 estimators)         │
│    - max_depth: 10                  │
│    - learning_rate: 0.1             │
│                                     │
│ 3. LightGBM (200 estimators)        │
│    - num_leaves: 31                 │
│    - learning_rate: 0.1             │
│                                     │
│ 4. CatBoost (200 iterations)        │
│    - depth: 10                      │
│    - learning_rate: 0.1             │
│                                     │
│ 5. Gradient Boosting (100 est.)    │
│    - max_depth: 5                   │
│    - learning_rate: 0.1             │
└─────────────────────────────────────┘
    ↓
Ensemble Method: Weighted Averaging
(weights based on validation F1 scores)
    ↓
Output: 42 vulnerability type probabilities
```

### Feature Groups (156 total)

| Feature Group | Count | Examples |
|---------------|-------|----------|
| Basic Features | 40 | cvss_score, severity, complexity |
| Technology Features | 25 | tech_react, has_database, has_cloud |
| Text Features (TF-IDF) | 100 | tfidf_0...tfidf_99 |
| Temporal Features | 10 | reported_year, season, disclosure_delay |
| Interaction Features | 15 | react_xss_interaction, db_sqli_interaction |
| Statistical Features | 10 | company_avg_bounty, vulntype_frequency |

---

## Monitoring Training

### Real-Time Monitoring

**Bash:**
```bash
# Monitor training in real-time
python scripts/train_model.py 2>&1 | tee training.log

# In another terminal, watch progress
tail -f training.log
```

**PowerShell:**
```powershell
# Monitor training in real-time
python scripts/train_model.py | Tee-Object -FilePath training.log

# In another terminal, watch progress
Get-Content training.log -Wait
```

### Training Metrics Files

After training, check these files:

```bash
data/results/
├── training_metrics.json       # Full metrics (JSON)
├── training_summary.txt         # Human-readable summary
├── feature_importance.csv       # Top features
└── confusion_matrices/          # Per-model confusion matrices
```

### View Training Metrics

**Bash:**
```bash
# View metrics
cat data/results/training_metrics.json | jq

# View summary
cat data/results/training_summary.txt

# View feature importance
column -t -s',' data/results/feature_importance.csv | less
```

**PowerShell:**
```powershell
# View metrics
Get-Content data/results/training_metrics.json | ConvertFrom-Json | ConvertTo-Json

# View summary
Get-Content data/results/training_summary.txt

# View feature importance
Import-Csv data/results/feature_importance.csv | Format-Table
```

---

## Evaluation & Metrics

### Model Evaluation Metrics

After training, evaluate models on test data:

**Bash:**
```bash
python scripts/evaluate_models.py \
  --models-dir data/models \
  --test-data data/processed/test_reports.pkl
```

**PowerShell:**
```powershell
python scripts/evaluate_models.py `
  --models-dir data/models `
  --test-data data/processed/test_reports.pkl
```

### Key Metrics

**VulnerabilityPredictor:**
- **Accuracy**: Overall prediction accuracy
- **F1 Score**: Weighted F1 across all classes
- **Precision/Recall**: Per-class metrics
- **Confusion Matrix**: Prediction breakdown
- **CV Score**: Cross-validation performance

**SeverityPredictor:**
- **Classification Accuracy**: Severity category accuracy
- **CVSS MAE**: Mean absolute error for CVSS scores
- **CVSS R²**: Coefficient of determination
- **MSE**: Mean squared error

### Understanding Metrics

| Metric | Good | Acceptable | Poor | Meaning |
|--------|------|------------|------|---------|
| Accuracy | >0.85 | 0.75-0.85 | <0.75 | Overall correctness |
| F1 Score | >0.85 | 0.75-0.85 | <0.75 | Balance of precision/recall |
| CV Score | >0.82 | 0.72-0.82 | <0.72 | Cross-validation stability |
| CVSS MAE | <0.6 | 0.6-1.0 | >1.0 | CVSS prediction error |
| CVSS R² | >0.75 | 0.60-0.75 | <0.60 | CVSS variance explained |

### Interpreting Results

**Good Model (Production Ready):**
```
Ensemble Test Accuracy: 0.8612
Ensemble Test F1 Score: 0.8578
CV F1 Score: 0.8501 (+/- 0.0178)

✓ Ready for production use
```

**Acceptable Model (Needs Improvement):**
```
Ensemble Test Accuracy: 0.7823
Ensemble Test F1 Score: 0.7756
CV F1 Score: 0.7689 (+/- 0.0289)

⚠ Consider:
  - Collecting more data
  - Feature engineering
  - Hyperparameter tuning
```

**Poor Model (Not Ready):**
```
Ensemble Test Accuracy: 0.6512
Ensemble Test F1 Score: 0.6423
CV F1 Score: 0.6234 (+/- 0.0456)

✗ Action needed:
  - Collect significantly more data
  - Review feature engineering
  - Check data quality
  - Consider different models
```

---

## Advanced Training

### Custom Training Pipeline

**Python API:**

```python
from src.training.pipeline import TrainingPipeline

# Initialize pipeline with custom config
pipeline = TrainingPipeline(config_path='config/custom_config.yaml')

# Override specific settings
pipeline.config['data_collection']['hackerone_limit'] = 10000
pipeline.config['training']['test_size'] = 0.15

# Run pipeline
pipeline.run_full_pipeline()

# Access trained models
vuln_predictor = pipeline.models['vulnerability_predictor']
severity_predictor = pipeline.models['severity_predictor']

# Get metrics
print(pipeline.metrics)
```

### Hyperparameter Tuning

**Create tuning script:**

```python
# scripts/tune_hyperparameters.py
from sklearn.model_selection import GridSearchCV
from src.models.vulnerability_classifier import VulnerabilityPredictor
from src.training.pipeline import TrainingPipeline

# Load data
pipeline = TrainingPipeline()
pipeline.raw_reports = pipeline.collect_data()
pipeline.processed_reports = pipeline.preprocess_data(pipeline.raw_reports)
features_df = pipeline.engineer_features(pipeline.processed_reports)

# Prepare data
X_train, X_test, y_train, y_test, _, _ = pipeline.split_data(
    features_df, pipeline.processed_reports
)

# Define parameter grid
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [10, 15, 20],
    'learning_rate': [0.05, 0.1, 0.15]
}

# Grid search
from xgboost import XGBClassifier
model = XGBClassifier()
grid_search = GridSearchCV(model, param_grid, cv=5, scoring='f1_weighted')
grid_search.fit(X_train, y_train)

print(f"Best parameters: {grid_search.best_params_}")
print(f"Best CV score: {grid_search.best_score_:.4f}")
```

**Run tuning:**
```bash
python scripts/tune_hyperparameters.py
```

### Training on Specific Vulnerability Types

**Filter data by vulnerability type:**

```python
from src.training.pipeline import TrainingPipeline

pipeline = TrainingPipeline()

# Load data
reports = pipeline.load_existing_data()

# Filter for specific types
target_types = ['XSS', 'SQL Injection', 'NoSQL Injection']
filtered_reports = [
    r for r in reports 
    if r.vulnerability_type in target_types
]

print(f"Filtered to {len(filtered_reports)} reports")

# Train on filtered data
pipeline.raw_reports = filtered_reports
pipeline.run_full_pipeline()
```

### Incremental Training (Adding New Data)

**Bash:**
```bash
# Collect new data
python scripts/collect_data.py \
  --source hackerone \
  --limit 1000 \
  --output data/new

# Merge with existing and retrain
python scripts/train_model.py \
  --skip-collection
```

---

## Troubleshooting

### Common Training Issues

#### Issue 1: Out of Memory

**Symptoms:**
```
MemoryError: Unable to allocate array
Killed (signal 9)
```

**Solutions:**

**Bash:**
```bash
# Reduce data size
python scripts/train_model.py --quick

# Or edit config
nano config/training_config.yaml
# Set lower limits:
# hackerone_limit: 2000
# bugcrowd_limit: 1000
# cve_limit: 1000
```

**PowerShell:**
```powershell
# Reduce data size
python scripts/train_model.py --quick

# Or edit config
notepad config/training_config.yaml
```

#### Issue 2: Slow Training

**Symptoms:**
```
Training taking > 2 hours
```

**Solutions:**

1. **Reduce cross-validation folds:**
```yaml
training:
  cv_folds: 3  # Instead of 5
```

2. **Reduce estimators:**
```yaml
models:
  xgboost:
    n_estimators: 100  # Instead of 200
```

3. **Skip cross-validation:**
```yaml
training:
  perform_cv: false
```

4. **Use fewer models:**
```bash
python scripts/train_model.py \
  --models vulnerability  # Only train vulnerability predictor
```

#### Issue 3: Poor Model Performance

**Symptoms:**
```
Test Accuracy: 0.62
Test F1 Score: 0.59
```

**Solutions:**

1. **Collect more data:**
```bash
python scripts/collect_data.py \
  --source all \
  --limit 15000
```

2. **Check data quality:**
```python
from src.collectors.data_sources import VulnerabilityReport
import pickle

with open('data/cache/hackerone_reports.pkl', 'rb') as f:
    reports = pickle.load(f)

# Check for issues
for report in reports[:10]:
    print(f"Type: {report.vulnerability_type}")
    print(f"Description length: {len(report.description)}")
    print(f"Has steps: {len(report.steps_to_reproduce) > 0}")
    print()
```

3. **Adjust preprocessing:**
```yaml
preprocessing:
  min_report_quality: 0.3  # Lower threshold
  remove_duplicates: true
```

#### Issue 4: Imbalanced Classes

**Symptoms:**
```
Warning: Class 'Other' has only 12 samples
```

**Solutions:**

1. **Use class weights (already enabled):**
```python
# In VulnerabilityPredictor
RandomForestClassifier(..., class_weight='balanced')
```

2. **Filter out rare classes:**
```python
from collections import Counter

# Count vulnerability types
type_counts = Counter(r.vulnerability_type for r in reports)

# Keep only types with >50 samples
min_samples = 50
filtered = [
    r for r in reports 
    if type_counts[r.vulnerability_type] >= min_samples
]
```

#### Issue 5: API Rate Limiting

**Symptoms:**
```
Rate limit reached, waiting 30 seconds...
Rate limit reached, waiting 30 seconds...
```

**Solutions:**

1. **Use API keys:**
```bash
export NVD_API_KEY="your_key"  # 5→50 requests/30s
python scripts/collect_data.py --source cve
```

2. **Use cached data:**
```bash
# Data is cached automatically
python scripts/train_model.py  # Uses cache
```

---

## Best Practices

### 1. Data Collection Best Practices

✅ **DO:**
- Use API keys for faster collection
- Enable caching for repeated runs
- Collect from multiple sources for diversity
- Verify data quality before training

❌ **DON'T:**
- Collect without rate limiting
- Skip deduplication
- Mix training and test data
- Ignore data quality issues

### 2. Training Best Practices

✅ **DO:**
- Start with quick training to verify setup
- Monitor training progress
- Use cross-validation
- Save all models and metrics
- Document any custom configurations

❌ **DON'T:**
- Skip validation
- Overtrain on small datasets
- Ignore poor metrics
- Delete training logs

### 3. Model Evaluation Best Practices

✅ **DO:**
- Evaluate on held-out test set
- Check per-class metrics
- Analyze confusion matrix
- Review feature importance
- Test on real-world examples

❌ **DON'T:**
- Evaluate only on training data
- Ignore class imbalance
- Skip cross-validation
- Trust single metric

### 4. Production Deployment Best Practices

✅ **DO:**
- Retrain periodically (monthly)
- Monitor prediction quality
- Version control models
- Document model versions
- Keep training data

❌ **DON'T:**
- Deploy without evaluation
- Use outdated models (>6 months)
- Lose training configurations
- Skip model versioning

---

## Training Checklist

### Pre-Training

- [ ] Python 3.10+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] At least 8GB RAM available
- [ ] 10GB+ disk space free
- [ ] API keys configured (optional)
- [ ] Configuration reviewed (`config/training_config.yaml`)

### During Training

- [ ] Monitor console output for errors
- [ ] Check memory usage
- [ ] Verify data collection completes
- [ ] Watch for warnings
- [ ] Track training time

### Post-Training

- [ ] Check model files exist (`data/models/`)
- [ ] Review training metrics (`data/results/`)
- [ ] Validate test accuracy (>0.75)
- [ ] Verify F1 score (>0.75)
- [ ] Test predictions on sample data
- [ ] Save training logs
- [ ] Document model version

---

## Training Schedule

### Recommended Retraining Frequency

| Use Case | Frequency | Reason |
|----------|-----------|--------|
| Production | Monthly | Keep up with new vulnerabilities |
| Development | Weekly | Rapid iteration |
| Research | As needed | Experiment with new data |
| Bug Bounty | Bi-weekly | Fresh vulnerability patterns |

### Automated Training (Cron/Task Scheduler)

**Bash (cron):**
```bash
# Edit crontab
crontab -e

# Add monthly training (1st of month at 2 AM)
0 2 1 * * cd /path/to/bugpredict-ai && source venv/bin/activate && python scripts/train_model.py >> logs/training_$(date +\%Y\%m\%d).log 2>&1
```

**PowerShell (Task Scheduler):**
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute 'python' -Argument 'scripts/train_model.py' -WorkingDirectory 'C:\bugpredict-ai'
$trigger = New-ScheduledTaskTrigger -Monthly -At 2am -DaysOfMonth 1
Register-ScheduledTask -TaskName "BugPredictAI-Training" -Action $action -Trigger $trigger
```

---

## Support

For training issues:

1. Check [Troubleshooting](#troubleshooting)
2. Review training logs in `data/results/`
3. Check GitHub Issues: https://github.com/yourusername/bugpredict-ai/issues
4. Join Discussions: https://github.com/yourusername/bugpredict-ai/discussions

---

**Happy Training! 🚀**

*For more documentation, see:*
- [README.md](../README.md) - General overview
- [API.md](API.md) - API documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
```

---

✅ **Complete Training Guide Created!**

**Includes:**
- ✅ **Step-by-step training instructions** (Bash & PowerShell)
- ✅ **Data collection guide** with all options
- ✅ **Complete configuration reference**
- ✅ **Training pipeline explanation** with visual diagrams
- ✅ **Model architecture details**
- ✅ **Monitoring & metrics guide**
- ✅ **Advanced training techniques**
- ✅ **Comprehensive troubleshooting** section
- ✅ **Best practices** checklist
- ✅ **Automated training** setup (cron/Task Scheduler)

This guide covers everything needed for successful model training! 🎓
