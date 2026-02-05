"""Training pipeline for BugPredict AI models"""

import logging
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
from datetime import datetime

from ..collectors.data_sources import VulnerabilityReport
from ..features.feature_engineer import FeatureEngineer


class TrainingPipeline:
    """Complete training pipeline for vulnerability prediction models"""
    
    def __init__(self, models_dir: str = "data/models"):
        """
        Initialize the training pipeline
        
        Args:
            models_dir: Directory to save trained models
        """
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.feature_engineer = FeatureEngineer()
        
        # Storage for processed data
        self.raw_reports = []
        self.processed_reports = []
        self.feature_data = None
        
        # Models
        self.vulnerability_model = None
        self.severity_model = None
        self.chain_detector = None
        
        # Label encoders
        self.vulnerability_label_encoder = None
        self.severity_label_encoder = None
        
        # Setup logging
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        # Console handler
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def load_data(self, data_path: str) -> List[VulnerabilityReport]:
        """
        Load vulnerability reports from file
        
        Args:
            data_path: Path to the data file (pickle format)
            
        Returns:
            List of VulnerabilityReport objects
        """
        self.logger.info(f"Loading data from {data_path}...")
        
        with open(data_path, 'rb') as f:
            reports = pickle.load(f)
        
        self.raw_reports = reports
        self.logger.info(f"Loaded {len(reports)} reports")
        
        return reports
    
    def preprocess_reports(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Preprocess vulnerability reports
        
        Args:
            reports: List of raw VulnerabilityReport objects
            
        Returns:
            List of preprocessed reports
        """
        self.logger.info("Preprocessing data...")
        
        # Store raw reports
        self.raw_reports = reports
        
        # For now, just pass through (no normalization/deduplication needed for CSV/JSON imports)
        self.processed_reports = reports
        
        self.logger.info(f"Preprocessed {len(self.processed_reports)} reports")
        
        return self.processed_reports
    
    def engineer_features(self, reports: Optional[List[VulnerabilityReport]] = None) -> pd.DataFrame:
        """
        Engineer features from preprocessed reports
        
        Args:
            reports: List of preprocessed reports (uses self.processed_reports if None)
            
        Returns:
            DataFrame with engineered features
        """
        self.logger.info("Engineering features...")
        
        if reports is None:
            reports = self.processed_reports
        
        # Extract features
        feature_data = self.feature_engineer.fit_transform(reports)
        
        # Save feature engineer
        feature_engineer_path = self.models_dir / 'feature_engineer.pkl'
        self.feature_engineer.save(str(feature_engineer_path))
        self.logger.info(f"Saved feature engineer to {feature_engineer_path}")
        
        self.feature_data = feature_data
        
        # Get only numeric columns for training
        numeric_cols = feature_data.select_dtypes(include=['int64', 'float64']).columns.tolist()
        self.logger.info(f"Engineered {len(numeric_cols)} numeric features")
        
        return feature_data
    
    def train_vulnerability_model(self, feature_data: Optional[pd.DataFrame] = None):
        """Train the vulnerability type classifier"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, accuracy_score
        from sklearn.preprocessing import LabelEncoder
        
        self.logger.info("Training vulnerability classifier...")
        
        if feature_data is None:
            feature_data = self.feature_data
        
        # Get only numeric columns
        numeric_cols = feature_data.select_dtypes(include=['int64', 'float64']).columns.tolist()
        X = feature_data[numeric_cols]
        
        # Get target from processed reports
        y = [getattr(r, 'vulnerability_type', 'Unknown') for r in self.processed_reports]
        
        # Encode target
        le = LabelEncoder()
        y_encoded = le.fit_transform(y)
        
        # Split data (with or without stratification based on dataset size)
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
            )
        except ValueError:
            # Not enough samples for stratification
            self.logger.warning("Too few samples for stratification, splitting without stratify")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42
            )
        
        # Train model
        self.vulnerability_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        
        self.vulnerability_model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.vulnerability_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        self.logger.info(f"Vulnerability classifier accuracy: {accuracy:.3f}")
        
        # Store label encoder
        self.vulnerability_label_encoder = le
        
        return self.vulnerability_model
    
    def train_severity_model(self, feature_data: Optional[pd.DataFrame] = None):
        """Train the severity predictor"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, accuracy_score
        from sklearn.preprocessing import LabelEncoder
        
        self.logger.info("Training severity predictor...")
        
        if feature_data is None:
            feature_data = self.feature_data
        
        # Get only numeric columns
        numeric_cols = feature_data.select_dtypes(include=['int64', 'float64']).columns.tolist()
        X = feature_data[numeric_cols]
        
        # Get target from processed reports
        y = [getattr(r, 'severity', 'medium') for r in self.processed_reports]
        
        # Encode target
        le = LabelEncoder()
        y_encoded = le.fit_transform(y)
        
        # Split data (with or without stratification based on dataset size)
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
            )
        except ValueError:
            # Not enough samples for stratification
            self.logger.warning("Too few samples for stratification, splitting without stratify")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42
            )
        
        # Train model
        self.severity_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42,
            n_jobs=-1
        )
        
        self.severity_model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.severity_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        self.logger.info(f"Severity predictor accuracy: {accuracy:.3f}")
        
        # Store label encoder
        self.severity_label_encoder = le
        
        return self.severity_model
    
    def train_chain_detector(self, reports: Optional[List[VulnerabilityReport]] = None):
        """Train the vulnerability chain detector"""
        self.logger.info("Training chain detector...")
        
        if reports is None:
            reports = self.processed_reports
        
        # For now, use a simple heuristic-based detector
        try:
            from ..models.chain_detector import ChainDetector
            self.chain_detector = ChainDetector()
            
            # Train on reports (if the detector has a train method)
            if hasattr(self.chain_detector, 'train'):
                self.chain_detector.train(reports)
        except ImportError:
            self.logger.warning("ChainDetector not found, creating placeholder")
            # Create a simple placeholder
            class SimpleChainDetector:
                def detect_chains(self, reports):
                    return []
            
            self.chain_detector = SimpleChainDetector()
        
        self.logger.info("Chain detector ready")
        
        return self.chain_detector
    
    def save_models(self):
        """Save all trained models"""
        import pickle
        from pathlib import Path
        
        self.logger.info("Saving models...")
        
        models_dir = Path(self.models_dir)
        models_dir.mkdir(parents=True, exist_ok=True)
        
        # Save vulnerability classifier
        if hasattr(self, 'vulnerability_model') and self.vulnerability_model is not None:
            vuln_model_path = models_dir / 'vulnerability_classifier.pkl'
            with open(vuln_model_path, 'wb') as f:
                pickle.dump({
                    'model': self.vulnerability_model,
                    'label_encoder': self.vulnerability_label_encoder
                }, f)
            self.logger.info(f"  -> Saved vulnerability_classifier.pkl")
        
        # Save severity predictor
        if hasattr(self, 'severity_model') and self.severity_model is not None:
            severity_model_path = models_dir / 'severity_predictor.pkl'
            with open(severity_model_path, 'wb') as f:
                pickle.dump({
                    'model': self.severity_model,
                    'label_encoder': self.severity_label_encoder
                }, f)
            self.logger.info(f"  -> Saved severity_predictor.pkl")
        
        # Save chain detector
        if hasattr(self, 'chain_detector') and self.chain_detector is not None:
            chain_detector_path = models_dir / 'chain_detector.pkl'
            with open(chain_detector_path, 'wb') as f:
                pickle.dump(self.chain_detector, f)
            self.logger.info(f"  -> Saved chain_detector.pkl")
        
        self.logger.info(f"All models saved to: {models_dir}")
    
    def train_all(self, reports: List[VulnerabilityReport]):
        """
        Complete training pipeline
        
        Args:
            reports: List of raw vulnerability reports
        """
        # Preprocess
        self.preprocess_reports(reports)
        
        # Engineer features
        self.engineer_features()
        
        # Train models
        self.train_vulnerability_model()
        self.train_severity_model()
        self.train_chain_detector()
        
        # Save everything
        self.save_models()
        
        self.logger.info("Training complete!")
