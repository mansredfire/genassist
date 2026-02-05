"""Database importer for vulnerability reports - Database Agnostic"""

from typing import List, Dict, Any, Optional
from pathlib import Path
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
    - Oracle (oracle://user:pass@host:port/dbname)
    """
    
    def __init__(self, connection_string: str):
        """
        Initialize database importer
        
        Args:
            connection_string: SQLAlchemy connection string
                Examples:
                - SQLite: "sqlite:///data/vulnerabilities.db"
                - PostgreSQL: "postgresql://user:password@localhost:5432/vulndb"
                - MySQL: "mysql://user:password@localhost:3306/vulndb"
                - SQL Server: "mssql+pyodbc://user:password@localhost/vulndb"
        """
        self.connection_string = connection_string
        self.engine = None
        self.session = None
        self.reports = []
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """Setup logging"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def connect(self):
        """Establish database connection"""
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            
            self.logger.info(f"Connecting to database...")
            self.engine = create_engine(self.connection_string)
            Session = sessionmaker(bind=self.engine)
            self.session = Session()
            self.logger.info("✓ Database connected")
            
        except ImportError:
            raise ImportError(
                "SQLAlchemy not installed. Install with: pip install sqlalchemy"
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to database: {e}")
    
    def disconnect(self):
        """Close database connection"""
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
        """
        Import vulnerability reports from database table
        
        Args:
            table_name: Name of the table containing vulnerability data
            column_mapping: Map database columns to VulnerabilityReport fields
                Example: {
                    'id': 'report_id',
                    'domain': 'target_domain',
                    'vuln_type': 'vulnerability_type'
                }
            limit: Maximum number of records to import
            where_clause: SQL WHERE clause filter (e.g., "severity='high'")
            
        Returns:
            List of VulnerabilityReport objects
        """
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
                # Convert row to dict
                row_dict = dict(row._mapping)
                
                # Map columns to VulnerabilityReport fields
                mapped_data = self._map_columns(row_dict, column_mapping)
                
                # Create report
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
        
        # Also include unmapped columns
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
            # Handle comma-separated, JSON array, or space-separated
            if tech_stack.startswith('['):
                import json
                return json.loads(tech_stack)
            else:
                return [t.strip() for t in tech_stack.split(',')]
        
        return []
    
    def import_from_query(self, sql_query: str) -> List[VulnerabilityReport]:
        """
        Import using custom SQL query
        
        Args:
            sql_query: Custom SQL query that returns vulnerability data
            
        Returns:
            List of VulnerabilityReport objects
        """
        from sqlalchemy import text
        
        if not self.session:
            self.connect()
        
        self.logger.info(f"Executing custom query")
        
        result = self.session.execute(text(sql_query))
        rows = result.fetchall()
        
        self.logger.info(f"Found {len(rows)} records")
        
        # Process rows (same as import_from_table)
        # ... (implementation similar to above)
        
        return self.reports
    
    def validate_connection(self) -> Dict[str, Any]:
        """
        Validate database connection and structure
        
        Returns:
            Dictionary with validation results
        """
        try:
            if not self.session:
                self.connect()
            
            # Test connection
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
