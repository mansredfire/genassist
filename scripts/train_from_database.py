#!/usr/bin/env python3
"""Train BugPredict AI models from database"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
from src.collectors.database_importer import DatabaseImporter
from src.training.pipeline import TrainingPipeline


def main():
    parser = argparse.ArgumentParser(description='Train BugPredict AI from database')
    parser.add_argument('--db', required=True, help='Database connection string')
    parser.add_argument('--table', help='Table name')
    parser.add_argument('--output-dir', '-o', default='data/models', help='Output directory for models')
    parser.add_argument('--limit', type=int, help='Limit number of records')
    parser.add_argument('--where', help='WHERE clause filter')
    parser.add_argument('--list-tables', action='store_true', help='List all tables and exit')
    parser.add_argument('--schema', help='Show schema for table and exit')
    parser.add_argument('--validate-only', action='store_true', help='Only validate connection')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("BugPredict AI - Database Training")
    print("=" * 70)
    
    # Initialize importer
    importer = DatabaseImporter(connection_string=args.db)
    
    # Validate connection
    print(f"\nValidating database connection...")
    validation = importer.validate_connection()
    
    if not validation['valid']:
        print(f"\n❌ Database connection failed: {validation['error']}")
        sys.exit(1)
    
    print(f"✓ Connected to {validation['database_type']} database")
    
    # List tables if requested
    if args.list_tables:
        print(f"\nAvailable tables:")
        tables = importer.list_tables()
        for table in tables:
            print(f"  - {table}")
        importer.disconnect()
        return
    
    # Show schema if requested
    if args.schema:
        print(f"\nSchema for table '{args.schema}':")
        schema = importer.get_table_schema(args.schema)
        for col in schema:
            nullable = "NULL" if col['nullable'] else "NOT NULL"
            print(f"  {col['name']:30} {col['type']:20} {nullable}")
        importer.disconnect()
        return
    
    if args.validate_only:
        print("\n✓ Validation complete (--validate-only mode)")
        importer.disconnect()
        return
    
    # Require table name for import
    if not args.table:
        print("\n❌ Error: --table is required for import")
        print("Use --list-tables to see available tables")
        sys.exit(1)
    
    # Import reports
    print(f"\nImporting from table: {args.table}")
    if args.where:
        print(f"Filter: {args.where}")
    if args.limit:
        print(f"Limit: {args.limit} records")
    
    reports = importer.import_from_table(
        table_name=args.table,
        limit=args.limit,
        where_clause=args.where
    )
    
    if len(reports) == 0:
        print("\n❌ No valid reports found in database")
        importer.disconnect()
        sys.exit(1)
    
    print(f"✓ Imported {len(reports)} reports")
    
    # Close database connection
    importer.disconnect()
    
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
    print("\n")


if __name__ == '__main__':
    main()
