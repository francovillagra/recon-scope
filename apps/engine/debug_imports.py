import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

try:
    from app.config import settings
    print("OK config")
    print(f"  DATABASE_URL starts with: {str(settings.DATABASE_URL)[:30]}")
except Exception as e:
    print(f"FAILED config: {e}")

try:
    from app.database import _make_url
    print("OK database")
except Exception as e:
    print(f"FAILED database: {e}")

try:
    from app.models import Base
    print("OK models")
    print(f"  tables: {list(Base.metadata.tables.keys())}")
except Exception as e:
    print(f"FAILED models: {e}")
