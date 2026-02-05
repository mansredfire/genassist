#!/usr/bin/env python3
"""Create complete database importer files"""

from pathlib import Path

# FULL Database Importer with all features
db_importer_content = '''"""Database importer for vulnerability reports - Database Agnostic"""

from typing import List, Dict, Any, Optional
import logging

from .data_sources import VulnerabilityReport


class DatabaseImporter:
    """
    Import vulnerability reports from any SQL database
    
    Supported databases:
    - SQLite (sqlite:///path/to/db.sqlite)
    - PostgreSQL (postgresql://user:pass@host:port/dbname)
    - MySQL (mysql://user:pass@host:port/dbname)
    - SQL Server (mssql+pyodbc://user:pass@host:port/dbname)
    """
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.engine = None
        self.session = None
        self.reports = []
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def connect(self):
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            
            self.logger.info("Connecting to database...")
            self.engine = create_engine(self.connection_string)
            Session = sessionmaker(bind=self.engine)
            self.session = Session()
            self.logger.info("✓ Database connected")
            
        except ImportError:
            raise ImportError("SQLAlchemy not installed. Install with: pip install sqlalchemy")
        except Exception as e:
            raise ConnectionError(f"Failed to connect: {e}")
    
    def disconnect(self):
        if self.session:
            self.session.close()
            self.logger.info("Database connection closed")
    
    def import_from_table(
        self,
        table_name: str,
        column_mapping: Optional[Dict[str, str]] = None,
        limit: Optional[int] = None,
        where_clause: Optional[str] = None
    ) -> List[VulnerabilityReport]:
        """Import vulnerability reports from database table"""
        from sqlalchemy import text
        
        if not self.session:
            self.connect()
        
        # Default column mapping
        if column_mapping is None:
            column_mapping = {
                'report_id': 'report_id',
                'target_domain': 'target_domain',
                'target_company': 'target_company',
                'vulnerability_type': 'vulnerability_type',
                'severity': 'severity',
                'cvss_score': 'cvss_score'
            }
        
        # Build query
        query = f"SELECT * FROM {table_name}"
        if where_clause:
            query += f" WHERE {where_clause}"
        if limit:
            query += f" LIMIT {limit}"
        
        self.logger.info(f"Executing query: {query}")
        
        # Execute query
        result = self.session.execute(text(query))
        rows = result.fetchall()
        
        self.logger.info(f"Found {len(rows)} records")
        
        # Convert to VulnerabilityReport objects
        reports = []
        
        for row in rows:
            try:
                row_dict = dict(row._mapping)
                mapped_data = self._map_columns(row_dict, column_mapping)
                
                report = VulnerabilityReport(
                    report_id=str(mapped_data.get('report_id', '')),
                    platform='database',
                    target_domain=str(mapped_data.get('target_domain', 'unknown')),
                    target_company=str(mapped_data.get('target_company', 'Unknown')),
                    target_program=str(mapped_data.get('target_program', mapped_data.get('target_company', 'Unknown'))),
                    vulnerability_type=str(mapped_data.get('vulnerability_type', 'Unknown')),
                    severity=str(mapped_data.get('severity', 'medium')),
                    cvss_score=float(mapped_data.get('cvss_score', 0.0)),
                    technology_stack=self._parse_tech_stack(mapped_data.get('tech_stack', '')),
                    endpoint=str(mapped_data.get('endpoint', '/')),
                    http_method=str(mapped_data.get('http_method', 'GET')),
                    vulnerability_location='web',
                    description=str(mapped_data.get('description', '')),
                    steps_to_reproduce=[],
                    impact=str(mapped_data.get('impact', '')),
                    remediation=str(mapped_data.get('remediation', '')),
                    reported_date=None,
                    disclosed_date=None,
                    bounty_amount=float(mapped_data.get('bounty_amount', 0.0)),
                    researcher_reputation=int(mapped_data.get('researcher_reputation', 0)),
                    authentication_required=bool(mapped_data.get('auth_required', False)),
                    privileges_required=str(mapped_data.get('privileges_required', 'none')),
                    user_interaction=bool(mapped_data.get('user_interaction', False)),
                    complexity=str(mapped_data.get('complexity', 'medium')),
                    tags=[],
                    owasp_category=str(mapped_data.get('owasp_category', '')),
                    cwe_id=int(mapped_data.get('cwe_id', 0)),
                    raw_data={}
                )
                
                reports.append(report)
                
            except Exception as e:
                self.logger.warning(f"Skipping row due to error: {e}")
                continue
        
        self.logger.info(f"✓ Imported {len(reports)} reports from database")
        self.reports = reports
        return reports
    
    def _map_columns(self, row_dict: Dict, column_mapping: Dict) -> Dict:
        """Map database columns to VulnerabilityReport fields"""
        mapped = {}
        
        for db_col, report_field in column_mapping.items():
            if db_col in row_dict:
                mapped[report_field] = row_dict[db_col]
        
        # Include unmapped columns
        for col, value in row_dict.items():
            if col not in column_mapping.values():
                mapped[col] = value
        
        return mapped
    
    def _parse_tech_stack(self, tech_stack):
        """Parse technology stack from database field"""
        if not tech_stack:
            return []
        
        if isinstance(tech_stack, list):
            return tech_stack
        
        if isinstance(tech_stack, str):
            if tech_stack.startswith('['):
                import json
                return json.loads(tech_stack)
            else:
                return [t.strip() for t in tech_stack.split(',')]
        
        return []
    
    def validate_connection(self) -> Dict[str, Any]:
        """Validate database connection"""
        try:
            if not self.session:
                self.connect()
            
            from sqlalchemy import text
            result = self.session.execute(text("SELECT 1"))
            result.fetchone()
            
            return {
                'valid': True,
                'connection': 'successful',
                'database_type': self.engine.name
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    def list_tables(self) -> List[str]:
        """List all tables in the database"""
        from sqlalchemy import inspect
        
        if not self.engine:
            self.connect()
        
        inspector = inspect(self.engine)
        return inspector.get_table_names()
    
    def get_table_schema(self, table_name: str) -> List[Dict[str, Any]]:
        """Get schema information for a table"""
        from sqlalchemy import inspect
        
        if not self.engine:
            self.connect()
        
        inspector = inspect(self.engine)
        columns = inspector.get_columns(table_name)
        
        return [
            {
                'name': col['name'],
                'type': str(col['type']),
                'nullable': col['nullable']
            }
            for col in columns
        ]
'''

# FULL Training Script with all features
train_db_content = '''#!/usr/bin/env python3
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
    print("\\nValidating database connection...")
    validation = importer.validate_connection()
    
    if not validation['valid']:
        print(f"\\n❌ Database connection failed: {validation['error']}")
        sys.exit(1)
    
    print(f"✓ Connected to {validation['database_type']} database")
    
    # List tables if requested
    if args.list_tables:
        print("\\nAvailable tables:")
        tables = importer.list_tables()
        for table in tables:
            print(f"  - {table}")
        importer.disconnect()
        return
    
    # Show schema if requested
    if args.schema:
        print(f"\\nSchema for table '{args.schema}':")
        schema = importer.get_table_schema(args.schema)
        for col in schema:
            nullable = "NULL" if col['nullable'] else "NOT NULL"
            print(f"  {col['name']:30} {col['type']:20} {nullable}")
        importer.disconnect()
        return
    
    if args.validate_only:
        print("\\n✓ Validation complete (--validate-only mode)")
        importer.disconnect()
        return
    
    # Require table name for import
    if not args.table:
        print("\\n❌ Error: --table is required for import")
        print("Use --list-tables to see available tables")
        sys.exit(1)
    
    # Import reports
    print(f"\\nImporting from table: {args.table}")
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
        print("\\n❌ No valid reports found in database")
        importer.disconnect()
        sys.exit(1)
    
    print(f"✓ Imported {len(reports)} reports")
    
    # Close database connection
    importer.disconnect()
    
    # Initialize training pipeline
    print("\\nInitializing training pipeline...")
    pipeline = TrainingPipeline(models_dir=args.output_dir)
    
    # Preprocess reports
    print("\\nPreprocessing reports...")
    pipeline.preprocess_reports(reports)
    print(f"✓ Preprocessed {len(pipeline.processed_reports)} reports")
    
    # Feature engineering
    print("\\nEngineering features...")
    pipeline.engineer_features()
    print("✓ Features engineered (28 features)")
    
    # Train models
    print("\\nTraining models...")
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
    print(f"\\nSaving models to: {args.output_dir}")
    pipeline.save_models()
    print("✓ Models saved")
    
    print("\\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    print(f"\\nModels saved to: {Path(args.output_dir).absolute()}")
    print("\\nNext steps:")
    print("  1. Generate templates: python scripts/generate_nuclei_templates.py --target example.com")
    print("\\n")


if __name__ == '__main__':
    main()
'''

# Create files
print("Creating COMPLETE database files...")
print()

Path('src/collectors/database_importer.py').write_text(db_importer_content, encoding='utf-8')
print("✓ Created src/collectors/database_importer.py (FULL VERSION)")

Path('scripts/train_from_database.py').write_text(train_db_content, encoding='utf-8')
print("✓ Created scripts/train_from_database.py (FULL VERSION)")

print()
print("=" * 70)
print("✅ COMPLETE DATABASE SUPPORT ADDED!")
print("=" * 70)
print()
print("Supported Databases:")
print("  ✅ SQLite (no server needed)")
print("  ✅ PostgreSQL")
print("  ✅ MySQL/MariaDB")
print("  ✅ SQL Server")
print()
print("Next steps:")
print("  1. pip install sqlalchemy")
print("  2. python scripts/train_from_database.py --db 'sqlite:///data/test.db' --validate-only")
print()
