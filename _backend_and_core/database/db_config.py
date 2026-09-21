from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Hum locally SQLite use kar rahe hain, jo project folder me 'phishguard.db' file banayega
SQLALCHEMY_DATABASE_URL = "sqlite:///./phishguard.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# DB Session lene ka function (Jo har API request me use hoga)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()