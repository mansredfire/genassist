#!/usr/bin/env python3
"""
BugPredict AI Complete Project Generator
Generates all files needed for the BugPredict AI project
Run: python generate_bugpredict_ai.py
"""

import os
from pathlib import Path


def create_file(path: str, content: str):
    """Create a file with given content"""
    filepath = Path(path)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✓ Created: {path}")


def create_empty_file(path: str):
    """Create an empty file (like .gitkeep)"""
    create_file(path, "")


# ============================================================================
# ALL PROJECT FILES
# ============================================================================

ALL_FILES = {
    # ========================================================================
    # ROOT CONFIGURATION FILES
    # ========================================================================
    
    ".gitignore": """# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
.env
.venv
env/
venv/
ENV/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Project specific
data/raw/*
data/processed/*
data/features/*
data/models/*.pkl
data/models/*.h5
!data/raw/.gitkeep
!data/processed/.gitkeep
!data/features/.gitkeep
!data/models/.gitkeep

# Logs
*.log
logs/

# Secrets
*.key
*.pem
secrets.yaml
config/secrets.yaml

# MLflow
mlruns/
mlartifacts/

# Large files
*.zip
*.tar.gz
*.csv
!data/examples/*.csv

# Jupyter
.ipynb_checkpoints
*.ipynb

# Testing
.pytest_cache/
.coverage
htmlcov/
coverage.xml
""",

    "LICENSE": """MIT License

Copyright (c) 2024 BugPredict AI Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
""",

    "README.md": """# 🤖 BugPredict AI

**AI-Powered Vulnerability Prediction for Bug Bounty Hunters**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## 📋 Overview

BugPredict AI uses machine learning to predict the most likely vulnerabilities in a target application based on technology stack, historical data, and patterns learned from thousands of bug bounty reports.

## ✨ Features

- 🎯 **Vulnerability Prediction**: ML-powered prediction of likely vulnerabilities
- 📊 **Severity Assessment**: Automatic severity rating
- ⛓️ **Chain Detection**: Identify vulnerability chains
- 🎨 **Test Strategy**: Generate prioritized testing plans
- 📝 **Nuclei Templates**: Auto-generate testing templates
- 🌐 **Multiple Interfaces**: CLI, API, and Web UI

## 🚀 Quick Start
```bash
