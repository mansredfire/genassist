#!/usr/bin/env python3
"""
Model training script
Trains BugPredict AI models
"""

import argparse
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.training.pipeline import TrainingPipeline


def main():
    parser = argparse.ArgumentParser(description='Train BugPredict AI models')
    
    parser.add_argument(
        '--config',
        type=str,
        default='config/training_config.yaml',
        help='Path to training configuration file'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick training with reduced data (for testing)'
    )
    
    parser.add_argument(
        '--skip-collection',
        action='store_true',
        help='Skip data collection (use cached data)'
    )
    
    parser.add_argument(
        '--models',
        nargs='+',
        choices=['vulnerability', 'severity', 'chain', 'all'],
        default=['all'],
        help='Which models to train'
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("BUGPREDICT AI - MODEL TRAINING")
    print("="*70)
    
    # Initialize pipeline
    pipeline = TrainingPipeline(config_path=args.config)
    
    # Quick mode adjustments
    if args.quick:
        print("\n⚡ Quick training mode enabled")
        pipeline.config['data_collection']['hackerone_limit'] = 500
        pipeline.config['data_collection']['bugcrowd_limit'] = 200
        pipeline.config['data_collection']['cve_limit'] = 300
    
    # Run training
    try:
        pipeline.run_full_pipeline()
        
        print("\n✅ Training completed successfully!")
        print(f"Models saved to: {pipeline.models_dir}")
        print(f"Results saved to: {pipeline.results_dir}")
        
    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
