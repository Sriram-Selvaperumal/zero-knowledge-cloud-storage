from app.database.database import sl

def get_db():
    db = sl()
    try:
        yield db
    finally:
        db.close()