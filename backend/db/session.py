import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Database URL with Postgres as target and SQLite fallback for local test/dev
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:postgres@localhost:5432/secops_guardian"
)

# If SQLite is configured (e.g. in test or fallback), set check_same_thread=False
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

try:
    engine = create_engine(
        DATABASE_URL,
        connect_args=connect_args,
        pool_pre_ping=True,
    )
except Exception:
    # Graceful fallback to sqlite file if postgres connection fails at engine init
    fallback_url = "sqlite:///./secops_fallback.db"
    engine = create_engine(fallback_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Ensure all declared tables exist (useful for testbeds/initial bootstrap)."""
    Base.metadata.create_all(bind=engine)
