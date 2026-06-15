from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings


if not settings.database_url:
    raise RuntimeError("DATABASE_URL is not set. Add it to your .env file.")

engine = create_engine(settings.database_url)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

sl = SessionLocal
