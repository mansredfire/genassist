#!/usr/bin/env python3
"""
Migration script to upgrade BugPredict AI with enhanced vulnerability types

This script:
1. Backs up existing models
2. Reprocesses existing data with enhanced extractor
3. Retrains models with new vulnerability types
4. Validates enhanced detection
5. Creates migration report
"""

import sys
import shutil
import pickle
import json
from pathlib import Path
from datetime import datetime
import argparse

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collectors.data_sources import VulnerabilityReport
from src.collectors.enhanced_extractor import EnhancedVulnerabilityExtractor
from src.features.feature_engineer import FeatureEngineer
from src.models.vulnerability_classifier import VulnerabilityPredictor
from src.models.severity_predictor import SeverityPredictor
from src.models.chain_detector import ChainDetector
from src.training.pipeline import TrainingPipeline


class MigrationManager:
    """Manages migration to enhanced vulnerability detection"""
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.backup_dir = Path('data/backup') / datetime.now().strftime('%Y%m%d_%H%M%S')
        self.models_dir = Path('data/models')
        self.data_dir = Path('data')
        
        self.enhanced_extractor = EnhancedVulnerabilityExtractor()
        
        self.migration_stats = {
            'reports_reprocessed': 0,
            'vulnerability_types_updated': 0,
            'new_types_detected': {},
            'models_retrained': [],
            'errors': []
        }
    
    def run_migration(self):
        """Execute complete migration process"""
        
        print("="*70)
        print("BUGPREDICT AI - ENHANCED VULNERABILITY TYPE MIGRATION")
        print("="*70)
        print(f"\nMode: {'DRY RUN' if self.dry_run else 'LIVE MIGRATION'}")
        print(f"Backup directory: {self.backup_dir}\n")
        
        try:
            # Step 1: Backup
            print("[STEP 1/6] Backing up existing models and data...")
            self.backup_existing_data()
            
            # Step 2: Load existing data
            print("\n[STEP 2/6] Loading existing vulnerability data...")
            reports = self.load_existing_data()
            
            if not reports:
                print("⚠ No existing data found. Will proceed with fresh training.")
                reports = []
            else:
                print(f"✓ Loaded {len(reports)} existing reports")
            
            # Step 3: Reprocess with enhanced extractor
            print("\n[STEP 3/6] Reprocessing reports with enhanced vulnerability detection...")
            enhanced_reports = self.reprocess_reports(reports)
            
            # Step 4: Generate migration statistics
            print("\n[STEP 4/6] Analyzing migration impact...")
            self.analyze_changes(reports, enhanced_reports)
            
            # Step 5: Retrain models
            if not self.dry_run:
                print("\n[STEP 5/6] Retraining models with enhanced data...")
                self.retrain_models(enhanced_reports)
            else:
                print("\n[STEP 5/6] Skipping model retraining (dry run mode)")
            
            # Step 6: Generate report
            print("\n[STEP 6/6] Generating migration report...")
            self.generate_migration_report()
            
            print("\n" + "="*70)
            print("✓ MIGRATION COMPLETED SUCCESSFULLY")
            print("="*70)
            
            if self.dry_run:
                print("\n⚠ This was a DRY RUN - no changes were made")
                print("Run without --dry-run to apply changes")
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            import traceback
            traceback.print_exc()
            
            if not self.dry_run:
                print("\n🔄 Attempting to restore from backup...")
                self.restore_backup()
            
            sys.exit(1)
    
    def backup_existing_data(self):
        """Backup existing models and processed data"""
        
        if self.dry_run:
            print("  [DRY RUN] Would backup data to:", self.backup_dir)
            return
        
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup models
        if self.models_dir.exists():
            shutil.copytree(
                self.models_dir, 
                self.backup_dir / 'models',
                dirs_exist_ok=True
            )
            print(f"  ✓ Backed up models to {self.backup_dir / 'models'}")
        
        # Backup processed data
        processed_dir = self.data_dir / 'processed'
        if processed_dir.exists():
            shutil.copytree(
                processed_dir,
                self.backup_dir / 'processed',
                dirs_exist_ok=True
            )
            print(f"  ✓ Backed up processed data to {self.backup_dir / 'processed'}")
        
        # Backup features
        features_dir = self.data_dir / 'features'
        if features_dir.exists():
            shutil.copytree(
                features_dir,
                self.backup_dir / 'features',
                dirs_exist_ok=True
            )
            print(f"  ✓ Backed up features to {self.backup_dir / 'features'}")
    
    def load_existing_data(self) -> list:
        """Load existing vulnerability reports from all sources"""
        
        all_reports = []
        
        # Load from cache
        cache_files = [
            'data/cache/hackerone_reports.pkl',
            'data/cache/bugcrowd_reports.pkl',
            'data/cache/cve_reports.pkl'
        ]
        
        for cache_file in cache_files:
            path = Path(cache_file)
            if path.exists():
                try:
                    with open(path, 'rb') as f:
                        reports = pickle.load(f)
                        all_reports.extend(reports)
                        print(f"  ✓ Loaded {len(reports)} reports from {path.name}")
                except Exception as e:
                    print(f"  ✗ Error loading {path.name}: {e}")
                    self.migration_stats['errors'].append(f"Load error: {path.name} - {e}")
        
        # Load from processed directory
        processed_files = list(Path('data/processed').glob('*.pkl'))
        for pfile in processed_files:
            try:
                with open(pfile, 'rb') as f:
                    reports = pickle.load(f)
                    # Avoid duplicates
                    existing_ids = {r.report_id for r in all_reports}
                    new_reports = [r for r in reports if r.report_id not in existing_ids]
                    all_reports.extend(new_reports)
                    print(f"  ✓ Loaded {len(new_reports)} unique reports from {pfile.name}")
            except Exception as e:
                print(f"  ✗ Error loading {pfile.name}: {e}")
        
        return all_reports
    
    def reprocess_reports(self, reports: list) -> list:
        """Reprocess reports with enhanced vulnerability type detection"""
        
        enhanced_reports = []
        type_changes = {}
        
        for report in reports:
            # Extract vulnerability type with enhanced extractor
            new_type = self.enhanced_extractor.extract_vulnerability_type(
                report.description,
                weakness_name='',
                cwe_id=report.cwe_id
            )
            
            old_type = report.vulnerability_type
            
            # Track changes
            if old_type != new_type:
                self.migration_stats['vulnerability_types_updated'] += 1
                
                if new_type not in type_changes:
                    type_changes[new_type] = {'count': 0, 'from_types': set()}
                
                type_changes[new_type]['count'] += 1
                type_changes[new_type]['from_types'].add(old_type)
            
            # Create updated report
            enhanced_report = VulnerabilityReport(
                report_id=report.report_id,
                platform=report.platform,
                target_domain=report.target_domain,
                target_company=report.target_company,
                target_program=report.target_program,
                vulnerability_type=new_type,  # Updated type
                severity=report.severity,
                cvss_score=report.cvss_score,
                technology_stack=report.technology_stack,
                endpoint=report.endpoint,
                http_method=report.http_method,
                vulnerability_location=report.vulnerability_location,
                description=report.description,
                steps_to_reproduce=report.steps_to_reproduce,
                impact=report.impact,
                remediation=report.remediation,
                reported_date=report.reported_date,
                disclosed_date=report.disclosed_date,
                bounty_amount=report.bounty_amount,
                researcher_reputation=report.researcher_reputation,
                authentication_required=report.authentication_required,
                privileges_required=report.privileges_required,
                user_interaction=report.user_interaction,
                complexity=report.complexity,
                tags=report.tags,
                owasp_category=report.owasp_category,
                cwe_id=report.cwe_id,
                raw_data=report.raw_data
            )
            
            enhanced_reports.append(enhanced_report)
            self.migration_stats['reports_reprocessed'] += 1
        
        self.migration_stats['new_types_detected'] = {
            k: {'count': v['count'], 'from_types': list(v['from_types'])}
            for k, v in type_changes.items()
        }
        
        print(f"  ✓ Reprocessed {len(enhanced_reports)} reports")
        print(f"  ✓ Updated {self.migration_stats['vulnerability_types_updated']} vulnerability types")
        print(f"  ✓ Detected {len(type_changes)} new vulnerability type mappings")
        
        return enhanced_reports
    
    def analyze_changes(self, old_reports: list, new_reports: list):
        """Analyze changes between old and new reports"""
        
        if not old_reports:
            print("  No existing data to compare")
            return
        
        # Count vulnerability types
        old_types = {}
        new_types = {}
        
        for report in old_reports:
            vtype = report.vulnerability_type
            old_types[vtype] = old_types.get(vtype, 0) + 1
        
        for report in new_reports:
            vtype = report.vulnerability_type
            new_types[vtype] = new_types.get(vtype, 0) + 1
        
        # Find new types
        added_types = set(new_types.keys()) - set(old_types.keys())
        removed_types = set(old_types.keys()) - set(new_types.keys())
        
        print(f"\n  Vulnerability Type Changes:")
        print(f"  {'='*60}")
        print(f"  Total types before: {len(old_types)}")
        print(f"  Total types after:  {len(new_types)}")
        print(f"  New types detected: {len(added_types)}")
        
        if added_types:
            print(f"\n  New Types:")
            for vtype in sorted(added_types):
                count = new_types[vtype]
                print(f"    • {vtype}: {count} reports")
        
        if removed_types:
            print(f"\n  Removed Types (reclassified):")
            for vtype in sorted(removed_types):
                count = old_types[vtype]
                print(f"    • {vtype}: {count} reports")
        
        # Show top changes
        print(f"\n  Top Type Changes:")
        if self.migration_stats['new_types_detected']:
            sorted_changes = sorted(
                self.migration_stats['new_types_detected'].items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )
            
            for vtype, info in sorted_changes[:10]:
                print(f"    • {vtype}: {info['count']} reports")
                print(f"      (from: {', '.join(info['from_types'])})")
    
    def retrain_models(self, reports: list):
        """Retrain models with enhanced reports"""
        
        if not reports:
            print("  ⚠ No data available for training")
            return
        
        # Save enhanced reports
        enhanced_cache_dir = self.data_dir / 'cache'
        enhanced_cache_dir.mkdir(parents=True, exist_ok=True)
        
        cache_file = enhanced_cache_dir / 'enhanced_reports.pkl'
        with open(cache_file, 'wb') as f:
            pickle.dump(reports, f)
        print(f"  ✓ Saved enhanced reports to {cache_file}")
        
        # Create temporary training config
        temp_config = {
            'data_collection': {
                'collect_hackerone': False,
                'collect_bugcrowd': False,
                'collect_cve': False
            },
            'preprocessing': {
                'remove_duplicates': True,
                'normalize_text': True,
                'min_report_quality': 0.5
            },
            'training': {
                'test_size': 0.2,
                'validation_size': 0.1,
                'random_state': 42
            },
            'output': {
                'models_dir': 'data/models',
                'save_feature_importance': True
            }
        }
        
        # Save temp config
        temp_config_path = Path('config/migration_config.yaml')
        temp_config_path.parent.mkdir(parents=True, exist_ok=True)
        
        import yaml
        with open(temp_config_path, 'w') as f:
            yaml.dump(temp_config, f)
        
        # Initialize pipeline
        pipeline = TrainingPipeline(config_path=str(temp_config_path))
        
        # Override data collection - use our enhanced reports
        pipeline.raw_reports = reports
        
        print("\n  Starting training pipeline...")
        
        try:
            # Preprocess
            print("  Preprocessing data...")
            pipeline.processed_reports = pipeline.preprocess_data(reports)
            
            # Feature engineering
            print("  Engineering features...")
            pipeline.features_df = pipeline.engineer_features(pipeline.processed_reports)
            
            # Split data
            print("  Splitting data...")
            X_train, X_test, y_train, y_test, y_severity, y_cvss = pipeline.split_data(
                pipeline.features_df,
                pipeline.processed_reports
            )
            
            # Train models
            print("  Training models...")
            pipeline.train_models(X_train, X_test, y_train, y_test, y_severity, y_cvss)
            
            # Evaluate
            print("  Evaluating models...")
            pipeline.evaluate_models(X_test, y_test)
            
            # Save
            print("  Saving models...")
            pipeline.save_models()
            pipeline.save_metrics()
            
            self.migration_stats['models_retrained'] = list(pipeline.models.keys())
            
            print("\n  ✓ Models retrained successfully")
            
        except Exception as e:
            print(f"\n  ✗ Training failed: {e}")
            self.migration_stats['errors'].append(f"Training error: {e}")
            raise
        
        finally:
            # Cleanup temp config
            if temp_config_path.exists():
                temp_config_path.unlink()
    
    def generate_migration_report(self):
        """Generate comprehensive migration report"""
        
        report_dir = self.data_dir / 'migration_reports'
        report_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = report_dir / f'migration_report_{timestamp}.json'
        
        report = {
            'migration_date': datetime.now().isoformat(),
            'mode': 'dry_run' if self.dry_run else 'live',
            'backup_location': str(self.backup_dir),
            'statistics': self.migration_stats,
            'new_vulnerability_types': list(self.migration_stats['new_types_detected'].keys()),
            'enhanced_features': [
                'NoSQL Injection detection',
                'Race Condition detection',
                'GraphQL vulnerability detection',
                'API abuse detection',
                'Cloud misconfiguration detection',
                'JWT vulnerability detection',
                'Advanced authentication issues',
                'Business logic flaw detection',
                'Enhanced chain detection (25+ patterns)'
            ]
        }
        
        # Save JSON report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n  ✓ Saved migration report to {report_file}")
        
        # Generate text report
        text_report_file = report_dir / f'migration_report_{timestamp}.txt'
        
        with open(text_report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("BUGPREDICT AI - MIGRATION REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Migration Date: {report['migration_date']}\n")
            f.write(f"Mode: {report['mode'].upper()}\n")
            f.write(f"Backup Location: {report['backup_location']}\n\n")
            
            f.write("-"*70 + "\n")
            f.write("STATISTICS\n")
            f.write("-"*70 + "\n")
            f.write(f"Reports Reprocessed: {self.migration_stats['reports_reprocessed']}\n")
            f.write(f"Vulnerability Types Updated: {self.migration_stats['vulnerability_types_updated']}\n")
            f.write(f"New Types Detected: {len(self.migration_stats['new_types_detected'])}\n")
            f.write(f"Models Retrained: {', '.join(self.migration_stats['models_retrained'])}\n")
            
            if self.migration_stats['new_types_detected']:
                f.write("\n" + "-"*70 + "\n")
                f.write("NEW VULNERABILITY TYPE MAPPINGS\n")
                f.write("-"*70 + "\n")
                
                for vtype, info in sorted(
                    self.migration_stats['new_types_detected'].items(),
                    key=lambda x: x[1]['count'],
                    reverse=True
                ):
                    f.write(f"\n{vtype}:\n")
                    f.write(f"  Count: {info['count']}\n")
                    f.write(f"  Reclassified from: {', '.join(info['from_types'])}\n")
            
            if self.migration_stats['errors']:
                f.write("\n" + "-"*70 + "\n")
                f.write("ERRORS\n")
                f.write("-"*70 + "\n")
                for error in self.migration_stats['errors']:
                    f.write(f"  • {error}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("ENHANCED FEATURES\n")
            f.write("="*70 + "\n")
            for feature in report['enhanced_features']:
                f.write(f"  ✓ {feature}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")
        
        print(f"  ✓ Saved text report to {text_report_file}")
        
        # Print summary
        print("\n" + "="*70)
        print("MIGRATION SUMMARY")
        print("="*70)
        print(f"Reports processed: {self.migration_stats['reports_reprocessed']}")
        print(f"Types updated: {self.migration_stats['vulnerability_types_updated']}")
        print(f"New types: {len(self.migration_stats['new_types_detected'])}")
        print(f"Models retrained: {len(self.migration_stats['models_retrained'])}")
        
        if self.migration_stats['errors']:
            print(f"\n⚠ Errors encountered: {len(self.migration_stats['errors'])}")
            for error in self.migration_stats['errors'][:5]:
                print(f"  • {error}")
    
    def restore_backup(self):
        """Restore from backup in case of failure"""
        
        print(f"Restoring from backup: {self.backup_dir}")
        
        try:
            # Restore models
            backup_models = self.backup_dir / 'models'
            if backup_models.exists() and self.models_dir.exists():
                shutil.rmtree(self.models_dir)
                shutil.copytree(backup_models, self.models_dir)
                print("  ✓ Restored models")
            
            # Restore processed data
            backup_processed = self.backup_dir / 'processed'
            processed_dir = self.data_dir / 'processed'
            if backup_processed.exists() and processed_dir.exists():
                shutil.rmtree(processed_dir)
                shutil.copytree(backup_processed, processed_dir)
                print("  ✓ Restored processed data")
            
            print("✓ Backup restored successfully")
            
        except Exception as e:
            print(f"✗ Restore failed: {e}")
            print("Please manually restore from:", self.backup_dir)


def main():
    parser = argparse.ArgumentParser(
        description='Migrate BugPredict AI to enhanced vulnerability detection'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview changes without applying them'
    )
    
    parser.add_argument(
        '--skip-backup',
        action='store_true',
        help='Skip backup step (not recommended)'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force migration even if data exists'
    )
    
    args = parser.parse_args()
    
    if not args.dry_run and not args.force:
        print("⚠ This will modify your existing BugPredict AI installation.")
        print("⚠ A backup will be created, but please ensure you have backups.")
        response = input("\nContinue with migration? (yes/no): ")
        
        if response.lower() not in ['yes', 'y']:
            print("Migration cancelled.")
            sys.exit(0)
    
    # Run migration
    manager = MigrationManager(dry_run=args.dry_run)
    
    if args.skip_backup:
        print("⚠ Skipping backup as requested")
        manager.backup_existing_data = lambda: print("  [SKIPPED] Backup")
    
    manager.run_migration()


if __name__ == '__main__':
    main()
