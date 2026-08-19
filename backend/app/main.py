from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.api.routes.targets import router as targets_router
from app.api.routes.projects import router as projects_router
from app.api.routes.scans import router as scans_router


app = FastAPI(
    title="Security SaaS API",
    version="1.0.0",
)


app.include_router(targets_router)
app.include_router(projects_router)
app.include_router(scans_router)


@app.get("/")
async def root():
    return {
        "message": "Security SaaS API is running"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }


@app.get("/health/database")
async def database_health(
    db: Session = Depends(get_db),
):
    db.execute(text("SELECT 1"))

    return {
        "status": "healthy",
        "database": "connected",
    }