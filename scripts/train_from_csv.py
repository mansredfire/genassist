#!/usr/bin/env python3
"""Train BugPredict AI models from CSV file"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
from src.collectors.csv_importer import CSVImporter
from src.training.pipeline import TrainingPipeline


def main():
    parser = argparse.ArgumentParser(description='Train BugPredict AI from CSV file')
    parser.add_argument('--input', '-i', required=True, help='Path to CSV file')
    parser.add_argument('--output-dir', '-o', default='data/models', help='Output directory for models')
    parser.add_argument('--validate-only', action='store_true', help='Only validate CSV, don\'t train')
    parser.add_argument('--quick', action='store_true', help='Quick training mode (faster, less accurate)')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("BugPredict AI - CSV Training")
    print("=" * 70)
    
    # Initialize importer
    importer = CSVImporter()
    
    # Validate CSV
    print(f"\nValidating CSV file: {args.input}")
    validation = importer.validate_csv(args.input)
    
    if not validation['valid']:
        print(f"\n❌ CSV validation failed: {validation['error']}")
        if 'found_columns' in validation:
            print(f"Found columns: {validation['found_columns']}")
        sys.exit(1)
    
    print(f"✓ CSV is valid")
    print(f"  Rows: {validation['rows']}")
    print(f"  Columns: {validation['columns']}")
    
    if args.validate_only:
        print("\n✓ Validation complete (--validate-only mode)")
        return
    
    # Import reports
    print(f"\nImporting vulnerability reports...")
    reports = importer.import_from_csv(args.input)
    
    if len(reports) == 0:
        print("\n❌ No valid reports found in CSV")
        sys.exit(1)
    
    print(f"✓ Imported {len(reports)} reports")
    
    # Initialize training pipeline
    print(f"\nInitializing training pipeline...")
    pipeline = TrainingPipeline(models_dir=args.output_dir)
    
    # Preprocess reports
    print(f"\nPreprocessing reports...")
    pipeline.preprocess_reports(reports)
    print(f"✓ Preprocessed {len(pipeline.processed_reports)} reports")
    
    # Feature engineering
    print(f"\nEngineering features...")
    pipeline.engineer_features()
    print(f"✓ Features engineered (28 features)")
    
    # Train models
    print(f"\nTraining models...")
    print("─" * 70)
    
    # Vulnerability classifier
    print("Training vulnerability classifier...")
    pipeline.train_vulnerability_model(pipeline.feature_data)
    print("✓ Vulnerability classifier trained")
    
    # Severity predictor
    print("Training severity predictor...")
    pipeline.train_severity_model(pipeline.feature_data)
    print("✓ Severity predictor trained")
    
    # Chain detector
    print("Training chain detector...")
    pipeline.train_chain_detector(pipeline.processed_reports)
    print("✓ Chain detector trained")
    
    # Save models
    print(f"\nSaving models to: {args.output_dir}")
    pipeline.save_models()
    print("✓ Models saved")
    
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    print(f"\nModels saved to: {Path(args.output_dir).absolute()}")
    print(f"\nNext steps:")
    print(f"  1. Generate templates: python scripts/generate_nuclei_templates.py --target example.com")
    print(f"  2. Run analysis: python scripts/analyze_target.py --domain example.com")
    print("\n")


if __name__ == '__main__':
    main()
