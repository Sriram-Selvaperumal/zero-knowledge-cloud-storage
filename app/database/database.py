import os
from dotenv import load_dotenv
from sqlalchemy import create_engine as ce
from sqlalchemy.orm import sessionmaker as sm

load_dotenv()

DB_URL = os.getenv('DATABASE_URL')

engine = ce(DB_URL)
 
sl = sm(autocommit=False,autoflush=False,bind=engine)

