from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.routes.admin import router as admin_router
from app.api.routes.assets import router as assets_router
from app.api.routes.scanner_admin import router as scanner_admin_router
from app.api.routes.attack_surface import router as attack_surface_router
from app.api.routes.audit_logs import router as audit_logs_router
from app.api.routes.auth import router as auth_router
from app.api.routes.cloud import router as cloud_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.finding_lifecycle import router as finding_lifecycle_router
from app.api.routes.findings import router as findings_router
from app.api.routes.ingestions import router as ingestions_router
from app.api.routes.organization_members import router as organization_members_router
from app.api.routes.project_members import router as project_members_router
from app.api.routes.projects import router as projects_router
from app.api.routes.scanners import router as scanners_router
from app.api.routes.scans import router as scans_router
from app.api.routes.targets import router as targets_router
from app.core.bootstrap import bootstrap_auth_user
from app.core.config import settings
from app.core.request_id import CORRELATION_ID_HEADER, REQUEST_ID_HEADER
from app.db.database import SessionLocal, get_db
from app.middleware.request_id import RequestContextMiddleware


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db = SessionLocal()
    try:
        bootstrap_auth_user(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Security SaaS API",
    version="1.0.0",
    lifespan=lifespan,
)


cors_origins = {
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:3002",
    "http://127.0.0.1:3002",
    "http://localhost:3003",
    "http://127.0.0.1:3003",
}
if settings.FRONTEND_URL:
    cors_origins.add(settings.FRONTEND_URL.rstrip("/"))

app.add_middleware(RequestContextMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[REQUEST_ID_HEADER, CORRELATION_ID_HEADER],
)


protected = [Depends(get_current_user)]

app.include_router(auth_router)
app.include_router(targets_router, dependencies=protected)
app.include_router(projects_router, dependencies=protected)
app.include_router(scans_router, dependencies=protected)
app.include_router(findings_router, dependencies=protected)
app.include_router(finding_lifecycle_router, dependencies=protected)
app.include_router(assets_router, dependencies=protected)
app.include_router(attack_surface_router, dependencies=protected)
app.include_router(scanners_router, dependencies=protected)
app.include_router(dashboard_router, dependencies=protected)
app.include_router(ingestions_router, dependencies=protected)
app.include_router(cloud_router, dependencies=protected)
app.include_router(organization_members_router, dependencies=protected)
app.include_router(project_members_router, dependencies=protected)
app.include_router(audit_logs_router, dependencies=protected)
app.include_router(admin_router)
app.include_router(scanner_admin_router)


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
