"""Data collectors for BugPredict AI"""

from .data_sources import VulnerabilityReport, VulnerabilityType, Severity, DataCollector
from .enhanced_extractor import EnhancedVulnerabilityExtractor
from .csv_importer import CSVImporter
from .json_importer import JSONImporter
from .database_importer import DatabaseImporter

__all__ = [
    'VulnerabilityReport',
    'VulnerabilityType',
    'Severity',
    'DataCollector',
    'EnhancedVulnerabilityExtractor',
    'CSVImporter',
    'JSONImporter',
    'DatabaseImporter'
]
```

---

### **4. Update `requirements.txt`**

Add SQLAlchemy:
```
sqlalchemy>=2.0.0
