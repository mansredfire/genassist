## 📄 File: `docs/DEPLOYMENT.md` (Complete Production Deployment Guide)

```markdown
# 🚀 BugPredict AI - Production Deployment Guide

> Comprehensive guide for deploying BugPredict AI in production environments

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Docker Deployment](#docker-deployment)
3. [Cloud Deployment](#cloud-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Security Hardening](#security-hardening)
6. [Monitoring & Logging](#monitoring--logging)
7. [Scaling Considerations](#scaling-considerations)
8. [CI/CD Pipeline](#cicd-pipeline)
9. [Model Management](#model-management)
10. [Backup & Recovery](#backup--recovery)
11. [Performance Tuning](#performance-tuning)
12. [Production Checklist](#production-checklist)

---

## Overview

BugPredict AI can be deployed in various configurations:

- **Standalone Server**: Single server with all components
- **Containerized**: Docker containers for portability
- **Cloud**: AWS, GCP, Azure managed services
- **Kubernetes**: Scalable cluster deployment
- **Serverless**: AWS Lambda, Google Cloud Functions

### Architecture Patterns

```
┌─────────────────────────────────────────────────────────┐
│                   Load Balancer                         │
└─────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┴────────────────┐
        │                                 │
┌───────▼────────┐              ┌────────▼────────┐
│  API Server 1  │              │  API Server 2   │
│  (Flask/Gunicorn)│            │  (Flask/Gunicorn)│
└───────┬────────┘              └────────┬────────┘
        │                                 │
        └────────────────┬────────────────┘
                         │
                ┌────────▼────────┐
                │  Model Storage  │
                │  (Shared Volume)│
                └─────────────────┘
```

---

## Docker Deployment

### Basic Docker Setup

#### 1. Create Dockerfile

Create `Dockerfile`:

```dockerfile
# BugPredict AI Production Dockerfile
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/models data/cache data/results logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=api_server.py

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "300", "api_server:app"]
```

#### 2. Create .dockerignore

Create `.dockerignore`:

```
__pycache__
*.pyc
*.pyo
*.pyd
.Python
*.so
*.egg
*.egg-info
dist
build
.git
.gitignore
.env
venv/
.venv/
*.log
.pytest_cache
.coverage
htmlcov/
.DS_Store
notebooks/
docs/
tests/
*.md
data/cache/*
data/results/*
!data/models
```

#### 3. Build Docker Image

**Bash:**
```bash
# Build image
docker build -t bugpredict-ai:latest .

# Tag for versioning
docker tag bugpredict-ai:latest bugpredict-ai:v1.0.0

# Verify image
docker images bugpredict-ai
```

**PowerShell:**
```powershell
# Build image
docker build -t bugpredict-ai:latest .

# Tag for versioning
docker tag bugpredict-ai:latest bugpredict-ai:v1.0.0

# Verify image
docker images bugpredict-ai
```

#### 4. Run Container

**Bash:**
```bash
# Run container
docker run -d \
  --name bugpredict-api \
  -p 5000:5000 \
  -v $(pwd)/data/models:/app/data/models:ro \
  -v $(pwd)/data/cache:/app/data/cache \
  -v $(pwd)/logs:/app/logs \
  -e LOG_LEVEL=INFO \
  --restart unless-stopped \
  bugpredict-ai:latest

# Check logs
docker logs -f bugpredict-api

# Check health
curl http://localhost:5000/health
```

**PowerShell:**
```powershell
# Run container
docker run -d `
  --name bugpredict-api `
  -p 5000:5000 `
  -v ${PWD}/data/models:/app/data/models:ro `
  -v ${PWD}/data/cache:/app/data/cache `
  -v ${PWD}/logs:/app/logs `
  -e LOG_LEVEL=INFO `
  --restart unless-stopped `
  bugpredict-ai:latest

# Check logs
docker logs -f bugpredict-api

# Check health
curl http://localhost:5000/health
```

---

### Docker Compose Setup

#### Create docker-compose.yml

```yaml
version: '3.8'

services:
  # API Server
  api:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: bugpredict-api
    ports:
      - "5000:5000"
    volumes:
      - ./data/models:/app/data/models:ro
      - ./data/cache:/app/data/cache
      - ./logs:/app/logs
      - model-storage:/app/data/models
    environment:
      - LOG_LEVEL=INFO
      - WORKERS=4
      - MAX_REQUESTS=1000
      - MAX_REQUESTS_JITTER=100
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
  
  # Nginx reverse proxy
  nginx:
    image: nginx:alpine
    container_name: bugpredict-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - api
    restart: unless-stopped
  
  # Redis cache (optional)
  redis:
    image: redis:7-alpine
    container_name: bugpredict-redis
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped
  
  # Prometheus monitoring (optional)
  prometheus:
    image: prom/prometheus:latest
    container_name: bugpredict-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    restart: unless-stopped

volumes:
  model-storage:
  redis-data:
  prometheus-data:
```

#### Create nginx.conf

```nginx
events {
    worker_connections 1024;
}

http {
    upstream api_backend {
        least_conn;
        server api:5000 max_fails=3 fail_timeout=30s;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    
    server {
        listen 80;
        server_name bugpredict.example.com;
        
        # Redirect to HTTPS
        return 301 https://$server_name$request_uri;
    }
    
    server {
        listen 443 ssl http2;
        server_name bugpredict.example.com;
        
        # SSL certificates
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        
        # Security headers
        add_header Strict-Transport-Security "max-age=31536000" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        
        # Proxy settings
        location / {
            proxy_pass http://api_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 300s;
            proxy_read_timeout 300s;
            
            # Rate limiting
            limit_req zone=api_limit burst=20 nodelay;
        }
        
        # Health check endpoint (no rate limit)
        location /health {
            proxy_pass http://api_backend;
            access_log off;
        }
    }
}
```

#### Deploy with Docker Compose

**Bash:**
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale API servers
docker-compose up -d --scale api=3

# Stop services
docker-compose down

# Update and restart
docker-compose pull
docker-compose up -d
```

**PowerShell:**
```powershell
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale API servers
docker-compose up -d --scale api=3

# Stop services
docker-compose down
```

---

## Cloud Deployment

### AWS Deployment

#### Option 1: AWS ECS (Elastic Container Service)

**1. Push to ECR (Elastic Container Registry):**

**Bash:**
```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  123456789012.dkr.ecr.us-east-1.amazonaws.com

# Create repository
aws ecr create-repository --repository-name bugpredict-ai

# Tag image
docker tag bugpredict-ai:latest \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/bugpredict-ai:latest

# Push image
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/bugpredict-ai:latest
```

**2. Create ECS Task Definition:**

Create `ecs-task-definition.json`:

```json
{
  "family": "bugpredict-ai",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "containerDefinitions": [
    {
      "name": "bugpredict-api",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/bugpredict-ai:latest",
      "portMappings": [
        {
          "containerPort": 5000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "LOG_LEVEL",
          "value": "INFO"
        },
        {
          "name": "WORKERS",
          "value": "4"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/bugpredict-ai",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:5000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

**3. Deploy to ECS:**

```bash
# Register task definition
aws ecs register-task-definition \
  --cli-input-json file://ecs-task-definition.json

# Create ECS cluster
aws ecs create-cluster --cluster-name bugpredict-cluster

# Create service
aws ecs create-service \
  --cluster bugpredict-cluster \
  --service-name bugpredict-service \
  --task-definition bugpredict-ai:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345],securityGroups=[sg-12345],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=bugpredict-api,containerPort=5000"
```

#### Option 2: AWS Lambda (Serverless)

**1. Create Lambda Handler:**

Create `lambda_handler.py`:

```python
import json
import sys
import os

# Add layer path
sys.path.insert(0, '/opt/python')

from src.inference.predictor import ThreatPredictor

# Initialize predictor (cold start)
predictor = None

def lambda_handler(event, context):
    global predictor
    
    # Initialize on first invocation
    if predictor is None:
        model_bucket = os.environ.get('MODEL_BUCKET', 'bugpredict-models')
        # Download models from S3 if needed
        predictor = ThreatPredictor(models_dir='/tmp/models')
    
    try:
        # Parse request
        if event.get('body'):
            body = json.loads(event['body'])
        else:
            body = event
        
        # Analyze target
        results = predictor.analyze_target(body)
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(results)
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
```

**2. Package for Lambda:**

**Bash:**
```bash
# Create deployment package
mkdir lambda_package
pip install -r requirements.txt -t lambda_package/
cp -r src lambda_package/
cp lambda_handler.py lambda_package/

cd lambda_package
zip -r ../lambda_deployment.zip .
cd ..

# Upload to S3
aws s3 cp lambda_deployment.zip s3://my-bucket/lambda_deployment.zip

# Create Lambda function
aws lambda create-function \
  --function-name bugpredict-ai \
  --runtime python3.10 \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --handler lambda_handler.lambda_handler \
  --code S3Bucket=my-bucket,S3Key=lambda_deployment.zip \
  --timeout 300 \
  --memory-size 3008 \
  --environment Variables={MODEL_BUCKET=bugpredict-models}
```

---

### Google Cloud Platform (GCP) Deployment

#### GCP Cloud Run

**1. Build and Push to GCR:**

**Bash:**
```bash
# Configure Docker for GCR
gcloud auth configure-docker

# Build and tag
docker build -t gcr.io/my-project/bugpredict-ai:latest .

# Push to GCR
docker push gcr.io/my-project/bugpredict-ai:latest
```

**2. Deploy to Cloud Run:**

```bash
# Deploy
gcloud run deploy bugpredict-ai \
  --image gcr.io/my-project/bugpredict-ai:latest \
  --platform managed \
  --region us-central1 \
  --memory 4Gi \
  --cpu 2 \
  --timeout 300 \
  --max-instances 10 \
  --allow-unauthenticated

# Get URL
gcloud run services describe bugpredict-ai \
  --platform managed \
  --region us-central1 \
  --format 'value(status.url)'
```

---

### Azure Deployment

#### Azure Container Instances

**Bash:**
```bash
# Login to Azure
az login

# Create resource group
az group create --name bugpredict-rg --location eastus

# Create container registry
az acr create --resource-group bugpredict-rg \
  --name bugpredictacr --sku Basic

# Login to ACR
az acr login --name bugpredictacr

# Tag and push image
docker tag bugpredict-ai:latest \
  bugpredictacr.azurecr.io/bugpredict-ai:latest
docker push bugpredictacr.azurecr.io/bugpredict-ai:latest

# Deploy container instance
az container create \
  --resource-group bugpredict-rg \
  --name bugpredict-api \
  --image bugpredictacr.azurecr.io/bugpredict-ai:latest \
  --cpu 2 \
  --memory 4 \
  --registry-login-server bugpredictacr.azurecr.io \
  --registry-username $(az acr credential show --name bugpredictacr --query username -o tsv) \
  --registry-password $(az acr credential show --name bugpredictacr --query passwords[0].value -o tsv) \
  --dns-name-label bugpredict-api \
  --ports 5000

# Get FQDN
az container show \
  --resource-group bugpredict-rg \
  --name bugpredict-api \
  --query ipAddress.fqdn
```

---

## Kubernetes Deployment

### Kubernetes Manifests

#### 1. Deployment

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bugpredict-api
  labels:
    app: bugpredict-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: bugpredict-api
  template:
    metadata:
      labels:
        app: bugpredict-api
    spec:
      containers:
      - name: api
        image: bugpredict-ai:latest
        ports:
        - containerPort: 5000
        env:
        - name: LOG_LEVEL
          value: "INFO"
        - name: WORKERS
          value: "4"
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        volumeMounts:
        - name: models
          mountPath: /app/data/models
          readOnly: true
        - name: cache
          mountPath: /app/data/cache
      volumes:
      - name: models
        persistentVolumeClaim:
          claimName: models-pvc
      - name: cache
        emptyDir: {}
```

#### 2. Service

Create `k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: bugpredict-api-service
spec:
  type: LoadBalancer
  selector:
    app: bugpredict-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5000
```

#### 3. Persistent Volume

Create `k8s/pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: models-pvc
spec:
  accessModes:
  - ReadOnlyMany
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
```

#### 4. Horizontal Pod Autoscaler

Create `k8s/hpa.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: bugpredict-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: bugpredict-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### Deploy to Kubernetes

**Bash:**
```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment
kubectl get deployments
kubectl get pods
kubectl get services

# Get service URL
kubectl get service bugpredict-api-service

# View logs
kubectl logs -f deployment/bugpredict-api

# Scale manually
kubectl scale deployment bugpredict-api --replicas=5

# Update image
kubectl set image deployment/bugpredict-api \
  api=bugpredict-ai:v2.0.0

# Rollback
kubectl rollout undo deployment/bugpredict-api

# Check autoscaler
kubectl get hpa
```

**PowerShell:**
```powershell
# Same commands work in PowerShell
kubectl apply -f k8s/
kubectl get deployments
kubectl get pods
```

---

## Security Hardening

### 1. API Authentication

Add JWT authentication to `api_server.py`:

```python
from flask import Flask, request, jsonify
from functools import wraps
import jwt
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me-in-production')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Remove 'Bearer ' prefix
            token = token.split()[1] if ' ' in token else token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

@app.route('/api/v1/analyze', methods=['POST'])
@token_required
def analyze():
    # Your analysis code
    pass
```

### 2. Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"]
)

@app.route('/api/v1/analyze', methods=['POST'])
@limiter.limit("10 per minute")
@token_required
def analyze():
    pass
```

### 3. Input Validation

```python
from flask import request
from marshmallow import Schema, fields, ValidationError

class TargetSchema(Schema):
    domain = fields.Str(required=True)
    technology_stack = fields.List(fields.Str())
    has_api = fields.Bool()

@app.route('/api/v1/analyze', methods=['POST'])
@token_required
def analyze():
    schema = TargetSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Proceed with analysis
    results = predictor.analyze_target(data)
    return jsonify(results)
```

### 4. SSL/TLS Configuration

**Generate self-signed certificate (development):**

**Bash:**
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout ssl/key.pem \
  -out ssl/cert.pem \
  -days 365 -nodes \
  -subj "/CN=bugpredict.local"
```

**Production: Use Let's Encrypt:**

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d bugpredict.example.com

# Auto-renewal
sudo certbot renew --dry-run
```

### 5. Security Headers

Add to `api_server.py`:

```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## Monitoring & Logging

### 1. Application Logging

Create `logging_config.py`:

```python
import logging
import logging.handlers
import os

def setup_logging(log_level='INFO'):
    """Configure application logging"""
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_format)
    
    # File handler (rotating)
    file_handler = logging.handlers.RotatingFileHandler(
        'logs/bugpredict.log',
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_format)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger
```

### 2. Prometheus Metrics

Add to `api_server.py`:

```python
from prometheus_flask_exporter import PrometheusMetrics

app = Flask(__name__)
metrics = PrometheusMetrics(app)

# Custom metrics
analysis_counter = metrics.counter(
    'bugpredict_analysis_total',
    'Total number of analyses performed',
    labels={'risk_level': lambda: 'unknown'}
)

analysis_duration = metrics.histogram(
    'bugpredict_analysis_duration_seconds',
    'Analysis duration in seconds'
)

@app.route('/api/v1/analyze', methods=['POST'])
@analysis_duration
def analyze():
    data = request.get_json()
    results = predictor.analyze_target(data)
    
    analysis_counter.labels(risk_level=results['risk_level']).inc()
    
    return jsonify(results)
```

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'bugpredict-api'
    static_configs:
      - targets: ['api:5000']
```

### 3. Structured Logging

```python
import structlog

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Usage
logger.info("analysis_started", domain=domain, user_id=user_id)
logger.warning("high_risk_detected", risk_score=8.5, domain=domain)
logger.error("analysis_failed", error=str(e), domain=domain)
```

### 4. Health Checks

Enhanced health check endpoint:

```python
import psutil
import time

start_time = time.time()

@app.route('/health', methods=['GET'])
def health():
    """Detailed health check"""
    
    # Check model availability
    models_ok = all([
        predictor.models.get('vulnerability_predictor'),
        predictor.models.get('severity_predictor'),
        predictor.models.get('chain_detector')
    ])
    
    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    uptime = time.time() - start_time
    
    health_data = {
        'status': 'healthy' if models_ok else 'degraded',
        'uptime_seconds': uptime,
        'models_loaded': models_ok,
        'system': {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent
        }
    }
    
    status_code = 200 if models_ok else 503
    return jsonify(health_data), status_code
```

---

## Scaling Considerations

### Horizontal Scaling

**Load Balancing Strategies:**

1. **Round Robin**: Distribute evenly across instances
2. **Least Connections**: Send to instance with fewest connections
3. **IP Hash**: Same client always goes to same instance

**Stateless Design:**
- No session storage in application
- Models loaded from shared storage
- Cache in Redis/Memcached

### Vertical Scaling

**Resource Requirements per Analysis:**

| Complexity | CPU | Memory | Time |
|------------|-----|--------|------|
| Simple | 0.5 cores | 1GB | ~2s |
| Medium | 1 core | 2GB | ~5s |
| Complex | 2 cores | 4GB | ~10s |

**Recommended Instance Sizes:**

- **Small**: 2 CPU, 4GB RAM → ~20 concurrent requests
- **Medium**: 4 CPU, 8GB RAM → ~40 concurrent requests
- **Large**: 8 CPU, 16GB RAM → ~80 concurrent requests

### Caching Strategy

```python
import redis
import json
import hashlib

redis_client = redis.Redis(host='redis', port=6379, db=0)

def analyze_with_cache(target_info):
    """Analyze with Redis caching"""
    
    # Generate cache key
    cache_key = hashlib.md5(
        json.dumps(target_info, sort_keys=True).encode()
    ).hexdigest()
    
    # Check cache
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    
    # Perform analysis
    results = predictor.analyze_target(target_info)
    
    # Cache results (TTL: 1 hour)
    redis_client.setex(cache_key, 3600, json.dumps(results))
    
    return results
```

---

## CI/CD Pipeline

### GitHub Actions Deployment

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Production

on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests
      run: pytest tests/ -v --cov=src
  
  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Login to Docker Hub
      uses: docker/login-action@v2
      with:
        username: ${{ secrets.DOCKER_USERNAME }}
        password: ${{ secrets.DOCKER_PASSWORD }}
    
    - name: Build and push
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: |
          yourusername/bugpredict-ai:latest
          yourusername/bugpredict-ai:${{ github.sha }}
  
  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
    - name: Deploy to production
      run: |
        # SSH to server and pull new image
        ssh user@production-server << 'EOF'
          cd /opt/bugpredict-ai
          docker-compose pull
          docker-compose up -d
        EOF
```

---

## Model Management

### Model Versioning

```python
import os
import shutil
from datetime import datetime

class ModelVersionManager:
    def __init__(self, models_dir='data/models'):
        self.models_dir = models_dir
        self.versions_dir = os.path.join(models_dir, 'versions')
        os.makedirs(self.versions_dir, exist_ok=True)
    
    def save_version(self, version_name=None):
        """Save current models as a version"""
        
        if version_name is None:
            version_name = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        version_dir = os.path.join(self.versions_dir, version_name)
        
        # Copy current models to version directory
        shutil.copytree(self.models_dir, version_dir, ignore=shutil.ignore_patterns('versions'))
        
        print(f"Saved model version: {version_name}")
        return version_name
    
    def rollback(self, version_name):
        """Rollback to a previous version"""
        
        version_dir = os.path.join(self.versions_dir, version_name)
        
        if not os.path.exists(version_dir):
            raise ValueError(f"Version {version_name} not found")
        
        # Backup current version
        self.save_version('backup_before_rollback')
        
        # Copy version models to current
        for item in os.listdir(version_dir):
            if item == 'versions':
                continue
            
            src = os.path.join(version_dir, item)
            dst = os.path.join(self.models_dir, item)
            
            if os.path.isdir(src):
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
        
        print(f"Rolled back to version: {version_name}")
    
    def list_versions(self):
        """List all saved versions"""
        
        versions = sorted(os.listdir(self.versions_dir), reverse=True)
        return versions
```

**Usage:**

```bash
# In deployment script
python - <<EOF
from model_manager import ModelVersionManager

manager = ModelVersionManager()

# Save current version before update
manager.save_version('v1.0.0')

# If something goes wrong, rollback
# manager.rollback('v1.0.0')
EOF
```

---

## Backup & Recovery

### Automated Backup Script

Create `backup.sh`:

```bash
#!/bin/bash
# BugPredict AI Backup Script

BACKUP_DIR="/backups/bugpredict"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$TIMESTAMP"

mkdir -p $BACKUP_PATH

# Backup models
echo "Backing up models..."
tar -czf $BACKUP_PATH/models.tar.gz data/models/

# Backup configuration
echo "Backing up configuration..."
cp -r config $BACKUP_PATH/

# Backup database (if using one)
# pg_dump dbname > $BACKUP_PATH/database.sql

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "backup_*" -mtime +7 -exec rm -rf {} \;

echo "Backup completed: $BACKUP_PATH"
```

**Schedule with cron:**

```bash
# Daily backup at 2 AM
0 2 * * * /opt/bugpredict-ai/backup.sh >> /var/log/bugpredict-backup.log 2>&1
```

---

## Performance Tuning

### Gunicorn Configuration

Create `gunicorn.conf.py`:

```python
import multiprocessing

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gthread"
threads = 4
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100

# Timeouts
timeout = 300
keepalive = 5

# Logging
accesslog = "logs/access.log"
errorlog = "logs/error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "bugpredict-api"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (if needed)
# keyfile = "ssl/key.pem"
# certfile = "ssl/cert.pem"
```

Run with:

```bash
gunicorn -c gunicorn.conf.py api_server:app
```

---

## Production Checklist

### Pre-Deployment

- [ ] All tests passing
- [ ] Security scan completed
- [ ] Models trained and validated
- [ ] Configuration reviewed
- [ ] SSL certificates obtained
- [ ] Backup strategy in place
- [ ] Monitoring configured
- [ ] Documentation updated
- [ ] Team trained on deployment process

### Deployment

- [ ] Database migrations run (if applicable)
- [ ] Models uploaded to shared storage
- [ ] Environment variables set
- [ ] Health checks passing
- [ ] Load balancer configured
- [ ] DNS records updated
- [ ] SSL configured
- [ ] Rate limiting enabled
- [ ] Logging configured

### Post-Deployment

- [ ] Smoke tests passed
- [ ] Monitoring dashboards reviewed
- [ ] Error rates normal
- [ ] Performance metrics acceptable
- [ ] Backup verified
- [ ] Rollback plan tested
- [ ] Documentation updated with deployment notes
- [ ] Stakeholders notified

---

## Support

For deployment issues:
- GitHub Issues: https://github.com/yourusername/bugpredict-ai/issues
- Documentation: https://bugpredict-ai.readthedocs.io
- Deployment Guide: This document

---

**Happy Deploying! 🚀**
```

Ready for the next guide: **ARCHITECTURE.md**? 🏗️
