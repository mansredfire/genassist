# src/training/pipeline.py

import pandas as pd
import numpy as np
from typing import List, Dict, Tuple
import pickle
import json
from pathlib import Path
from datetime import datetime
import mlflow
import logging

class TrainingPipeline:
    """
    Complete ML training pipeline for BugPredict AI
    """
    
    def __init__(self, config_path: str = "config/training_config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.collectors = []
        self.feature_engineer = None
        self.models = {}
        self.metrics = {}
        
    def _load_config(self, config_path: str) -> Dict:
        """Load training configuration"""
        import yaml
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('training.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def run_full_pipeline(self):
        """Execute complete training pipeline"""
        
        self.logger.info("Starting BugPredict AI Training Pipeline")
        
        try:
            # Step 1: Data Collection
            self.logger.info("Step 1/7: Collecting data...")
            reports = self.collect_data()
            self.logger.info(f"Collected {len(reports)} vulnerability reports")
            
            # Step 2: Data Preprocessing
            self.logger.info("Step 2/7: Preprocessing data...")
            clean_reports = self.preprocess_data(reports)
            self.logger.info(f"Cleaned data: {len(clean_reports)} reports")
            
            # Step 3: Feature Engineering
            self.logger.info("Step 3/7: Engineering features...")
            features_df = self.engineer_features(clean_reports)
            self.logger.info(f"Created {features_df.shape[1]} features")
            
            # Step 4: Train/Test Split
            self.logger.info("Step 4/7: Splitting data...")
            X_train, X_test, y_train, y_test = self.split_data(features_df)
            
            # Step 5: Model Training
            self.logger.info("Step 5/7: Training models...")
            self.train_models(X_train, X_test, y_train, y_test)
            
            # Step 6: Model Evaluation
            self.logger.info("Step 6/7: Evaluating models...")
            self.evaluate_models(X_test, y_test)
            
            # Step 7: Model Persistence
            self.logger.info("Step 7/7: Saving models...")
            self.save_models()
            
            self.logger.info("Training pipeline completed successfully!")
            
        except Exception as e:
            self.logger.error(f"Pipeline failed: {str(e)}")
            raise
    
    def collect_data(self) -> List[VulnerabilityReport]:
        """Collect data from all sources"""
        
        all_reports = []
        
        # HackerOne
        if self.config.get('collect_hackerone', True):
            self.logger.info("Collecting from HackerOne...")
            h1_collector = HackerOneCollector(
                api_token=self.config.get('hackerone_token')
            )
            h1_reports = h1_collector.collect(
                limit=self.config.get('hackerone_limit', 5000)
            )
            all_reports.extend(h1_reports)
            self.logger.info(f"HackerOne: {len(h1_reports)} reports")
        
        # Bugcrowd
        if self.config.get('collect_bugcrowd', True):
            self.logger.info("Collecting from Bugcrowd...")
            bc_collector = BugcrowdCollector(
                api_token=self.config.get('bugcrowd_token')
            )
            bc_reports = bc_collector.collect(
                limit=self.config.get('bugcrowd_limit', 5000)
            )
            all_reports.extend(bc_reports)
            self.logger.info(f"Bugcrowd: {len(bc_reports)} reports")
        
        # CVE/NVD
        if self.config.get('collect_cve', True):
            self.logger.info("Collecting from NVD...")
            cve_collector = CVECollector(
                api_key=self.config.get('nvd_api_key')
            )
            
            start_date = datetime(2020, 1, 1)
            end_date = datetime.now()
            
            cve_reports = cve_collector.collect(
                start_date=start_date,
                end_date=end_date,
                keywords=['web', 'api', 'application']
            )
            all_reports.extend(cve_reports)
            self.logger.info(f"NVD: {len(cve_reports)} reports")
        
        # GitHub Security Advisories
        if self.config.get('collect_github', True):
            self.logger.info("Collecting from GitHub...")
            # Implementation for GitHub Security Advisories
            pass
        
        return all_reports
    
    def preprocess_data(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """Clean and preprocess data"""
        
        from src.preprocessing.normalizer import DataNormalizer
        from src.preprocessing.deduplicator import Deduplicator
        from src.preprocessing.enricher import DataEnricher
        
        # Normalize
        normalizer = DataNormalizer()
        normalized = normalizer.normalize(reports)
        
        # Deduplicate
        deduplicator = Deduplicator()
        deduplicated = deduplicator.deduplicate(normalized)
        
        # Enrich with additional data
        enricher = DataEnricher()
        enriched = enricher.enrich(deduplicated)
        
        return enriched
    
    def engineer_features(self, reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """Transform reports into features"""
        
        self.feature_engineer = FeatureEngineer()
        features_df = self.feature_engineer.fit_transform(reports)
        
        # Save feature names
        with open('data/models/feature_names.json', 'w') as f:
            json.dump(list(features_df.columns), f)
        
        return features_df
    
    def split_data(self, features_df: pd.DataFrame) -> Tuple:
        """Split data into train/test sets"""
        
        from sklearn.model_selection import train_test_split
        
        # Separate features and target
        X = features_df.drop(['vuln_type'], axis=1)
        y = features_df['vuln_type']
        
        # Stratified split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.config.get('test_size', 0.2),
            random_state=42,
            stratify=y
        )
        
        return X_train, X_test, y_train, y_test
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train all models"""
        
        # Vulnerability Type Classifier
        self.logger.info("Training vulnerability classifier...")
        vuln_predictor = VulnerabilityPredictor(model_type='ensemble')
        vuln_predictor.build_models()
        vuln_results = vuln_predictor.train(X_train, y_train)
        self.models['vulnerability_predictor'] = vuln_predictor
        self.metrics['vulnerability_predictor'] = vuln_results
        
        # Severity Predictor
        self.logger.info("Training severity predictor...")
        severity_predictor = SeverityPredictor()
        severity_predictor.build_model()
        
        # Use severity from features
        y_severity_train = X_train['severity_encoded'] if 'severity_encoded' in X_train.columns else None
        if y_severity_train is not None:
            severity_predictor.train(X_train.drop(['severity_encoded'], axis=1), y_severity_train)
            self.models['severity_predictor'] = severity_predictor
        
        # Chain Detector
        self.logger.info("Initializing chain detector...")
        chain_detector = ChainDetector()
        self.models['chain_detector'] = chain_detector
        
        # Log metrics to MLflow
        if self.config.get('use_mlflow', True):
            self._log_to_mlflow(vuln_results)
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate model performance"""
        
        from sklearn.metrics import classification_report, accuracy_score, f1_score
        
        vuln_predictor = self.models['vulnerability_predictor']
        
        # Get ensemble predictions
        y_pred, y_proba = vuln_predictor.ensemble_predict(X_test, method='averaging')
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        self.logger.info(f"Ensemble Accuracy: {accuracy:.4f}")
        self.logger.info(f"Ensemble F1 Score: {f1:.4f}")
        
        # Detailed classification report
        report = classification_report(y_test, y_pred)
        self.logger.info(f"\nClassification Report:\n{report}")
        
        # Save evaluation results
        eval_results = {
            'accuracy': accuracy,
            'f1_score': f1,
            'classification_report': report,
            'timestamp': datetime.now().isoformat()
        }
        
        with open('data/models/evaluation_results.json', 'w') as f:
            json.dump(eval_results, f, indent=2)
    
    def save_models(self):
        """Save trained models"""
        
        models_dir = Path('data/models')
        models_dir.mkdir(parents=True, exist_ok=True)
        
        # Save each model
        for name, model in self.models.items():
            model_path = models_dir / f"{name}.pkl"
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            self.logger.info(f"Saved {name} to {model_path}")
        
        # Save feature engineer
        with open(models_dir / 'feature_engineer.pkl', 'wb') as f:
            pickle.dump(self.feature_engineer, f)
        
        # Save metadata
        metadata = {
            'training_date': datetime.now().isoformat(),
            'num_training_samples': len(self.metrics.get('vulnerability_predictor', {})),
            'model_versions': {name: '1.0' for name in self.models.keys()},
            'config': self.config
        }
        
        with open(models_dir / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _log_to_mlflow(self, results: Dict):
        """Log training metrics to MLflow"""
        
        mlflow.set_experiment("bugpredict_training")
        
        with mlflow.start_run():
            # Log parameters
            mlflow.log_params(self.config)
            
            # Log metrics
            for model_name, metrics in results.items():
                mlflow.log_metric(f"{model_name}_accuracy", metrics['test_accuracy'])
                mlflow.log_metric(f"{model_name}_cv_mean", metrics['cv_mean'])
            
            # Log models
            for name, model in self.models.items():
                mlflow.sklearn.log_model(model, name)
