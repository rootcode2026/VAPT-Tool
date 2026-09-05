"""P11.1 Ingestion API — project-scoped, safe archive preparation."""

import io
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import (
    _effective_project_role,
    _is_super_admin,
    get_current_user,
    require_project_access,
)
from app.db.database import get_db
from app.models.project import Project
from app.models.user import User
from app.services.audit import (
    EVENT_INGESTION_CREATED,
    EVENT_INGESTION_FAILED,
    RESOURCE_INGESTION,
    RESULT_FAILURE,
    RESULT_SUCCESS,
    AuditService,
)

router = APIRouter(prefix="/api/v1/ingestions", tags=["Ingestions"])

# Reuse worker ingestion logic via import path that works in backend container
# For backend, we duplicate minimal archive validation to avoid cross-service import.
# Keep it deterministic and safe.

# Limits (mirror worker/app/ingestion/limits.py)
MAX_ARCHIVE_SIZE = 100 * 1024 * 1024
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024
MAX_FILE_COUNT = 10000
MAX_FILE_SIZE = 50 * 1024 * 1024

# Lightweight detection (mirror worker)
LANGUAGE_MAP = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java", ".go": "Go", ".rs": "Rust", ".php": "PHP", ".c": "C", ".h": "C", ".cpp": "C++",
    ".hpp": "C++", ".cc": "C++", ".cs": "C#", ".rb": "Ruby",
}
DEPENDENCY_MANIFESTS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod", "go.sum", "pom.xml", "build.gradle", "Cargo.toml", "Gemfile", "composer.json"}


def _validate_entry_name(name: str):
    if not name or name.strip() == "":
        raise HTTPException(status_code=400, detail="Empty archive entry")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        raise HTTPException(status_code=400, detail=f"Absolute path rejected: {name[:50]}")
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha():
        raise HTTPException(status_code=400, detail=f"Windows path rejected: {name[:50]}")
    if normalized.startswith("//"):
        raise HTTPException(status_code=400, detail="UNC path rejected")
    if ".." in normalized.split("/"):
        raise HTTPException(status_code=400, detail=f"Path traversal rejected: {name[:50]}")
    if "\x00" in name:
        raise HTTPException(status_code=400, detail="Null byte in path")


def _detect_archive_type(filename: str, data: bytes) -> str:
    lower = (filename or "").lower()
    if lower.endswith(".zip"):
        return "zip"
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        return "tar.gz"
    if lower.endswith(".tar"):
        return "tar"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "tar.gz"
    raise HTTPException(status_code=400, detail="Unsupported archive format")


@router.post("/prepare")
async def prepare_ingestion(
    project_id: str = Form(..., description="Project ID"),
    file: UploadFile = File(..., description="Archive file (.zip, .tar, .tar.gz)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Project isolation + ingestion.create permission (analyst/project_admin)
    require_project_access(project_id, db, current_user)
    if not _is_super_admin(current_user):
        role = _effective_project_role(current_user, project_id, db)
        if role not in ("analyst", "project_admin"):
            raise HTTPException(status_code=403, detail="Insufficient permissions: requires analyst to create ingestions")

    filename = file.filename or "archive"
    data = await file.read()

    if len(data) > MAX_ARCHIVE_SIZE:
        raise HTTPException(status_code=400, detail=f"Archive size {len(data)} exceeds limit {MAX_ARCHIVE_SIZE}")
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty archive")

    arch_type = _detect_archive_type(filename, data)

    # Create isolated workspace (reuse backend's temp, not worker's workspace.py but similar)
    import tempfile, zipfile, tarfile, os
    from pathlib import Path as PPath

    workspace = Path(tempfile.mkdtemp(prefix="vapt-ingest-", dir=tempfile.gettempdir()))
    try:
        os.chmod(workspace, 0o700)
    except Exception:
        pass

    file_count = 0
    total_size = 0
    # Validate and extract
    try:
        if arch_type == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    name = info.filename
                    if not name or name.strip() == "":
                        continue
                    is_dir = name.endswith("/")
                    _validate_entry_name(name)
                    is_symlink = (info.external_attr >> 16) & 0o120000 == 0o120000
                    if is_symlink:
                        # Read symlink target
                        try:
                            target = zf.read(name).decode("utf-8", errors="ignore").strip()
                        except Exception:
                            target = ""
                        if target.startswith("/") or ".." in target.replace("\\", "/").split("/"):
                            raise HTTPException(status_code=400, detail="Symlink escape rejected")
                        file_count += 1
                        if file_count > MAX_FILE_COUNT:
                            raise HTTPException(status_code=400, detail="Too many files")
                        continue
                    if is_dir:
                        continue
                    if info.file_size > MAX_FILE_SIZE:
                        raise HTTPException(status_code=400, detail=f"File {name[:50]} too large")
                    total_size += info.file_size
                    if total_size > MAX_EXTRACTED_SIZE:
                        raise HTTPException(status_code=400, detail="Extracted size too large")
                    file_count += 1
                    if file_count > MAX_FILE_COUNT:
                        raise HTTPException(status_code=400, detail="Too many files")
                    dest = (workspace / name).resolve()
                    if not str(dest).startswith(str(workspace.resolve())):
                        raise HTTPException(status_code=400, detail="Extraction escapes workspace")
                # Extract
                for info in zf.infolist():
                    name = info.filename
                    if not name or name.strip() == "":
                        continue
                    is_dir = name.endswith("/")
                    is_symlink = (info.external_attr >> 16) & 0o120000 == 0o120000
                    dest = workspace / name
                    if is_dir:
                        dest.mkdir(parents=True, exist_ok=True)
                        continue
                    if is_symlink:
                        target = zf.read(name).decode("utf-8", errors="ignore").strip()
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            if dest.exists() or dest.is_symlink():
                                dest.unlink()
                            dest.symlink_to(target)
                        except Exception:
                            raise HTTPException(status_code=400, detail="Symlink creation failed")
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, open(dest, "wb") as dst:
                        remaining = info.file_size
                        while remaining > 0:
                            chunk = src.read(min(8192, remaining))
                            if not chunk:
                                break
                            dst.write(chunk)
                            remaining -= len(chunk)
        else:  # tar, tar.gz
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                members = tf.getmembers()
                for m in members:
                    name = m.name
                    if not name or name.strip() == "":
                        continue
                    _validate_entry_name(name)
                    if m.issym() or m.islnk():
                        linkname = m.linkname or ""
                        if linkname.startswith("/") or ".." in linkname.replace("\\", "/").split("/"):
                            raise HTTPException(status_code=400, detail="Symlink escape rejected")
                        file_count += 1
                        if file_count > MAX_FILE_COUNT:
                            raise HTTPException(status_code=400, detail="Too many files")
                        continue
                    if m.isdir():
                        continue
                    if m.isreg():
                        if m.size > MAX_FILE_SIZE:
                            raise HTTPException(status_code=400, detail=f"File {name[:50]} too large")
                        total_size += m.size
                        if total_size > MAX_EXTRACTED_SIZE:
                            raise HTTPException(status_code=400, detail="Extracted too large")
                        file_count += 1
                        if file_count > MAX_FILE_COUNT:
                            raise HTTPException(status_code=400, detail="Too many files")
                        dest = (workspace / name).resolve()
                        if not str(dest).startswith(str(workspace.resolve())):
                            raise HTTPException(status_code=400, detail="Extraction escapes workspace")
                    else:
                        raise HTTPException(status_code=400, detail=f"Unsupported entry: {name[:50]}")
                for m in members:
                    name = m.name
                    if not name or name.strip() == "":
                        continue
                    dest = workspace / name
                    if m.isdir():
                        dest.mkdir(parents=True, exist_ok=True)
                        continue
                    if m.issym() or m.islnk():
                        linkname = m.linkname or ""
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            if dest.exists() or dest.is_symlink():
                                dest.unlink()
                            if m.issym():
                                dest.symlink_to(linkname)
                            else:
                                target = workspace / linkname
                                if not target.exists():
                                    raise HTTPException(status_code=400, detail="Hard link target missing")
                                dest.hardlink_to(target)
                        except HTTPException:
                            raise
                        except Exception:
                            raise HTTPException(status_code=400, detail="Link failed")
                        continue
                    if m.isreg():
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        src = tf.extractfile(m)
                        if src is None:
                            raise HTTPException(status_code=400, detail="Failed to extract")
                        with open(dest, "wb") as dst:
                            remaining = m.size
                            while remaining > 0:
                                chunk = src.read(min(8192, remaining))
                                if not chunk:
                                    break
                                dst.write(chunk)
                                remaining -= len(chunk)

        # Lightweight detection
        languages = {}
        manifests = {}
        secrets = {}
        iac = {}
        api = {}
        total_files = 0
        for p in workspace.rglob("*"):
            if not p.is_file():
                continue
            try:
                p.resolve().relative_to(workspace.resolve())
            except ValueError:
                continue
            total_files += 1
            name = p.name
            suffix = p.suffix.lower()
            # Language
            lang = LANGUAGE_MAP.get(suffix)
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
            if name in DEPENDENCY_MANIFESTS:
                manifests[name] = manifests.get(name, 0) + 1
            if name.startswith(".env") or "config" in name.lower():
                secrets[name] = secrets.get(name, 0) + 1
            if suffix == ".tf" or name == "Dockerfile":
                iac[name] = iac.get(name, 0) + 1
            if name.lower() in ("openapi.json", "openapi.yaml", "swagger.json"):
                api[name] = api.get(name, 0) + 1

        # Scanner routing
        recommended = []
        reasons = {}
        if languages:
            recommended.append("sast")
            reasons["sast"] = f"Source files: {', '.join(list(languages.keys())[:3])}"
        if manifests:
            recommended.append("sca")
            reasons["sca"] = f"Manifests: {', '.join(list(manifests.keys())[:3])}"
        if secrets:
            recommended.append("secrets")
            reasons["secrets"] = f"Secrets candidates: {list(secrets.keys())[0]}"
        if iac:
            recommended.append("iac")
            reasons["iac"] = "IaC files detected"
        if api:
            recommended.append("api")
            reasons["api"] = "API specs detected"
        recommended = sorted(set(recommended))

        ingestion_id = str(uuid.uuid4())

        # Audit INGESTION_CREATED — safe metadata only (no file contents)
        try:
            proj = db.query(Project).filter(Project.id == project_id).first()
            org_id = proj.organization_id if proj else current_user.organization_id
            AuditService.record(
                db,
                event_type=EVENT_INGESTION_CREATED,
                action=EVENT_INGESTION_CREATED,
                result=RESULT_SUCCESS,
                actor_user_id=current_user.id,
                organization_id=org_id,
                project_id=project_id,
                resource_type=RESOURCE_INGESTION,
                resource_id=ingestion_id,
                metadata={
                    "source_type": arch_type,
                    "file_count": file_count,
                    "recommended_scanners": recommended,
                },
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        # Cleanup workspace after (for P11.1 foundation, we return metadata and clean up; real scan would keep it)
        # For this API, we clean up immediately to avoid disk leak
        import shutil
        try:
            shutil.rmtree(workspace, ignore_errors=True)
        except Exception:
            pass

        return {
            "ingestion_id": ingestion_id,
            "project_id": project_id,
            "source_type": arch_type,
            "source_name": filename[:100],
            "file_count": file_count,
            "total_size": total_size,
            "detected_languages": languages,
            "detected_artifact_types": sorted(set(list(languages.keys())[:1] + list(manifests.keys())[:1] + (["iac"] if iac else []) + (["api"] if api else []))),
            "artifact_details": {
                "languages": languages,
                "dependency_manifests": manifests,
                "secrets_candidates": secrets,
                "iac_files": iac,
                "api_specs": api,
                "total_files": total_files,
            },
            "recommended_scanners": recommended,
            "scan_reasons": reasons,
            "status": "completed",
            "warnings": [],
        }

    except HTTPException as http_exc:
        # Audit INGESTION_FAILED for validation/terminal failures (sanitized)
        try:
            proj = db.query(Project).filter(Project.id == project_id).first()
            org_id = proj.organization_id if proj else getattr(current_user, "organization_id", None)
            # Only audit if we have a project context
            if project_id:
                AuditService.record(
                    db,
                    event_type=EVENT_INGESTION_FAILED,
                    action=EVENT_INGESTION_FAILED,
                    result=RESULT_FAILURE,
                    actor_user_id=getattr(current_user, "id", None),
                    organization_id=org_id,
                    project_id=project_id,
                    resource_type=RESOURCE_INGESTION,
                    resource_id=str(uuid.uuid4()),
                    metadata={"source_type": filename[:50] if 'filename' in locals() else "unknown", "error": str(http_exc.detail)[:500] if hasattr(http_exc, "detail") else "validation failed"},
                )
                db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        # Cleanup on HTTP error
        import shutil
        try:
            shutil.rmtree(workspace, ignore_errors=True)
        except Exception:
            pass
        raise
    except Exception as e:
        # Audit generic failure
        try:
            proj = db.query(Project).filter(Project.id == project_id).first()
            org_id = proj.organization_id if proj else getattr(current_user, "organization_id", None)
            if project_id:
                AuditService.record(
                    db,
                    event_type=EVENT_INGESTION_FAILED,
                    action=EVENT_INGESTION_FAILED,
                    result=RESULT_FAILURE,
                    actor_user_id=getattr(current_user, "id", None),
                    organization_id=org_id,
                    project_id=project_id,
                    resource_type=RESOURCE_INGESTION,
                    resource_id=str(uuid.uuid4()),
                    metadata={"error": str(e)[:500]},
                )
                db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        import shutil
        try:
            shutil.rmtree(workspace, ignore_errors=True)
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=f"Ingestion failed: {type(e).__name__}")

    finally:
        # Ensure cleanup (idempotent)
        pass
