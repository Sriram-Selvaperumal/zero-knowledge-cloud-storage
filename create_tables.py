 
from app.database.database import engine
from app.models.user import user
from app.models.base import Base

Base.metadata.create_all(bind=engine)
print("Tables Created Successfully!")