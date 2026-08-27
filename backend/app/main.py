from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.database import get_db

from app.api.routes.targets import router as targets_router
from app.api.routes.projects import router as projects_router
from app.api.routes.scans import router as scans_router
from app.api.routes.findings import router as findings_router
from app.api.routes.scanners import router as scanners_router
from app.api.routes.dashboard import router as dashboard_router


app = FastAPI(
    title="Security SaaS API",
    version="1.0.0",
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# API Routes
# ---------------------------------------------------------

app.include_router(targets_router)
app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(scanners_router)
app.include_router(dashboard_router)


# ---------------------------------------------------------
# Root
# ---------------------------------------------------------

@app.get("/")
async def root():
    return {
        "message": "Security SaaS API is running"
    }


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }


# ---------------------------------------------------------
# Database Health
# ---------------------------------------------------------

@app.get("/health/database")
async def database_health(
    db: Session = Depends(get_db),
):
    db.execute(text("SELECT 1"))

    return {
        "status": "healthy",
        "database": "connected",
    }