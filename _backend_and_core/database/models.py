from sqlalchemy import Column, Integer, String, DateTime
from database.db_config import Base
import datetime

# Scan History Table - Jo user ke scan kiye hue links save karega
class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    verdict = Column(String)      # Safe, Suspicious, Malicious
    risk_score = Column(Integer)  # 0 to 100
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

# (Aap chaho toh yahan ek User model bhi bana sakte ho login/signup ke liye)