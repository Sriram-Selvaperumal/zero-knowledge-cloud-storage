from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routes.auth import router as auth_router
from app.routes.files import router as files_router
from app.routes.shares import router as shares_router

app = FastAPI(
    title="Prototype API",
    description="Self-hosted encrypted storage prototype API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(auth_router)
app.include_router(files_router)
app.include_router(shares_router)


@app.get("/")
def root():
    return {"message": "Prototype API"}
