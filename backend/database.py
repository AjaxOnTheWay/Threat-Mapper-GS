import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Fetches the connection string from your .env file, fallback to local sqlite if not provided
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite:///./threat_mapper.db"

# The engine handles the connection (supporting SQLite and PostgreSQL)
connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args)

# SessionLocal is the factory that generates new database sessions for each request
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the parent class all our database models will inherit from
Base = declarative_base()

def get_db():
    """Dependency to generate a database session and close it after the request finishes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()