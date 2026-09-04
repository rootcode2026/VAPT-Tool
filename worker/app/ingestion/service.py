"""Ingestion Service — secure workspace preparation for AppSec scanners."""

import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, Any

from app.scanner.workspace import create_workspace, cleanup_workspace
from .archive import safe_extract_zip, safe_extract_tar, detect_archive_type, IngestionError
from .artifact_detection import detect_artifacts, summarize_artifact_types
from .scanner_routing import recommend_scanners
from app.asset_intel.appsec import (
    create_repository_asset,
    create_source_file_assets,
    build_appsec_relationships,
    normalize_repository_value,
)


@dataclass
class IngestionResult:
    ingestion_id: str
    project_id: str
    source_type: str  # git, zip, tar, tar.gz, directory, etc.
    source_name: str
    workspace_path: str
    file_count: int
    total_size: int
    detected_languages: Dict[str, int] = field(default_factory=dict)
    detected_artifact_types: list = field(default_factory=list)
    artifact_details: Dict[str, Any] = field(default_factory=dict)
    recommended_scanners: list = field(default_factory=list)
    scan_reasons: Dict[str, str] = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    status: str = "completed"  # completed, failed, partial
    duration_ms: int = 0
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    # P11.2 AppSec asset intelligence
    appsec_assets: list = field(default_factory=list)
    appsec_relationships: list = field(default_factory=list)
    repository_asset: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_safe_dict(self) -> dict:
        """Return sanitized dict for API/logs — no secrets, no raw content."""
        d = self.to_dict()
        # Ensure no secret leakage: truncate warnings, sanitize error
        if d.get("error_message"):
            d["error_message"] = d["error_message"][:500]
        if d.get("warnings"):
            d["warnings"] = [str(w)[:200] for w in d["warnings"][:20]]
        # Truncate appsec assets for API
        if d.get("appsec_assets") and len(d["appsec_assets"]) > 100:
            d["appsec_assets"] = d["appsec_assets"][:100]
        if d.get("appsec_relationships") and len(d["appsec_relationships"]) > 100:
            d["appsec_relationships"] = d["appsec_relationships"][:100]
        return d


class IngestionService:
    """Secure ingestion service — prepares isolated workspace for scanners."""

    def prepare_from_archive(
        self,
        archive_bytes: bytes,
        filename: str,
        project_id: str,
        source_type: Optional[str] = None,
        source_name: Optional[str] = None,
    ) -> IngestionResult:
        start = time.monotonic()
        ingestion_id = str(uuid.uuid4())
        workspace = None
        try:
            # Validate project_id
            if not project_id or not isinstance(project_id, str):
                raise IngestionError("Invalid project_id", "invalid_project")

            # Create isolated workspace (reuses existing workspace.py)
            workspace = create_workspace(scan_id=ingestion_id[:8], scanner="ingestion", project_id=project_id)
            ws_path = Path(workspace)

            # Detect archive type and extract safely
            try:
                arch_type = detect_archive_type(archive_bytes, filename)
            except IngestionError as e:
                # Malformed/unsupported
                raise

            source_type = source_type or arch_type
            source_name = source_name or filename or f"archive.{arch_type}"

            # Sanitize source_name for logs (no secrets)
            safe_source_name = source_name[:100]

            # Extract with validation
            if arch_type == "zip":
                file_count, total_size = safe_extract_zip(archive_bytes, ws_path)
            elif arch_type in ("tar", "tar.gz"):
                file_count, total_size = safe_extract_tar(archive_bytes, ws_path)
            else:
                raise IngestionError(f"Unsupported archive type: {arch_type}", "unsupported_format")

            # Verify workspace containment after extraction
            try:
                ws_path.resolve().relative_to(ws_path.resolve())
            except Exception:
                pass
            # Check that all extracted files are within workspace
            for p in ws_path.rglob("*"):
                try:
                    p.resolve().relative_to(ws_path.resolve())
                except ValueError:
                    raise IngestionError(f"Extraction escaped workspace: {p.name[:50]}", "workspace_escape")

            # Artifact detection (deterministic, lightweight)
            detection = detect_artifacts(ws_path)
            artifact_types = summarize_artifact_types(detection)
            routing = recommend_scanners(detection)

            # P11.2 AppSec asset intelligence — repository + source files + relationships
            # Create repository asset deterministically (project-scoped)
            from app.asset_intel.appsec import normalize_repository_value
            repo_value = normalize_repository_value(project_id, safe_source_name, source_type)
            repo_asset = {
                "type": "repository",
                "value": repo_value,
                "metadata": {
                    "source_type": source_type,
                    "source_name": safe_source_name[:200],
                    "ingestion_id": ingestion_id[:100],
                    "project_id": project_id,
                    "sources": ["ingestion"],
                    "languages": list(detection.get("languages", {}).keys())[:5],
                },
            }
            # Create source_file assets from workspace (deterministic, up to 10k)
            source_assets = create_source_file_assets(ws_path, type("obj", (), {"project_id": project_id, "source_name": safe_source_name, "artifact_details": detection, "source_type": source_type, "ingestion_id": ingestion_id})())
            # Build relationships: repository contains source_file
            appsec_rels = build_appsec_relationships(repo_asset, source_assets)

            duration_ms = int((time.monotonic() - start) * 1000)

            return IngestionResult(
                ingestion_id=ingestion_id,
                project_id=project_id,
                source_type=source_type,
                source_name=safe_source_name,
                workspace_path=str(ws_path),
                file_count=file_count,
                total_size=total_size,
                detected_languages=detection.get("languages", {}),
                detected_artifact_types=artifact_types,
                artifact_details=detection,
                recommended_scanners=routing["recommended"],
                scan_reasons=routing["reasons"],
                warnings=[],
                status="completed",
                duration_ms=duration_ms,
                appsec_assets=[repo_asset] + source_assets,
                appsec_relationships=appsec_rels,
                repository_asset=repo_asset,
            )

        except IngestionError as e:
            # Cleanup workspace on failure
            if workspace:
                try:
                    cleanup_workspace(workspace)
                except Exception:
                    pass
            duration_ms = int((time.monotonic() - start) * 1000)
            return IngestionResult(
                ingestion_id=ingestion_id,
                project_id=project_id,
                source_type=source_type or "unknown",
                source_name=(source_name or filename or "unknown")[:100],
                workspace_path="",
                file_count=0,
                total_size=0,
                status="failed",
                error_category=getattr(e, "category", "ingestion_error"),
                error_message=str(e)[:500],
                duration_ms=duration_ms,
            )
        except Exception as e:
            if workspace:
                try:
                    cleanup_workspace(workspace)
                except Exception:
                    pass
            duration_ms = int((time.monotonic() - start) * 1000)
            return IngestionResult(
                ingestion_id=ingestion_id,
                project_id=project_id,
                source_type=source_type or "unknown",
                source_name=(source_name or filename or "unknown")[:100],
                workspace_path="",
                file_count=0,
                total_size=0,
                status="failed",
                error_category="unknown_error",
                error_message=f"Ingestion failed: {type(e).__name__}",
                duration_ms=duration_ms,
            )

    def prepare_from_directory(
        self,
        source_path: str | Path,
        project_id: str,
        source_name: Optional[str] = None,
    ) -> IngestionResult:
        """Prepare workspace from existing local directory (e.g., already cloned repo)."""
        start = time.monotonic()
        ingestion_id = str(uuid.uuid4())
        workspace = None
        try:
            if not project_id or not isinstance(project_id, str):
                raise IngestionError("Invalid project_id", "invalid_project")
            src = Path(source_path)
            if not src.exists() or not src.is_dir():
                raise IngestionError(f"Source directory not found: {str(source_path)[:100]}", "not_found")
            # Prevent path traversal in source_path itself
            try:
                src.resolve()
            except Exception:
                raise IngestionError("Invalid source path", "invalid_path")

            workspace = create_workspace(scan_id=ingestion_id[:8], scanner="ingestion", project_id=project_id)
            ws_path = Path(workspace)

            # Copy files securely (no symlinks outside, no traversal)
            file_count = 0
            total_size = 0
            for p in src.rglob("*"):
                if not p.is_file():
                    continue
                # Skip ignored dirs for counting? For ingestion we copy all
                try:
                    rel = p.relative_to(src)
                except ValueError:
                    continue
                # Validate relative path
                rel_str = str(rel).replace("\\", "/")
                if ".." in rel_str.split("/") or rel_str.startswith("/") or (len(rel_str) >= 2 and rel_str[1] == ":" and rel_str[0].isalpha()):
                    continue
                # Check file size
                try:
                    size = p.stat().st_size
                except Exception:
                    continue
                from .limits import MAX_FILE_SIZE, MAX_FILE_COUNT, MAX_EXTRACTED_SIZE
                if size > MAX_FILE_SIZE:
                    continue
                total_size += size
                if total_size > MAX_EXTRACTED_SIZE:
                    raise IngestionError(f"Extracted size exceeds limit {MAX_EXTRACTED_SIZE}", "extracted_too_large")
                file_count += 1
                if file_count > MAX_FILE_COUNT:
                    raise IngestionError(f"File count exceeds limit {MAX_FILE_COUNT}", "too_many_files")
                dest = ws_path / rel
                # Ensure dest is within workspace
                try:
                    dest.resolve().relative_to(ws_path.resolve())
                except ValueError:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                # Copy file content securely (not symlink)
                if p.is_symlink():
                    # Resolve symlink target and ensure within src
                    try:
                        target = p.readlink()
                        # Check symlink target
                        if target.is_absolute() or ".." in str(target).split("/"):
                            continue
                        resolved = (p.parent / target).resolve()
                        try:
                            resolved.relative_to(src.resolve())
                        except ValueError:
                            continue
                    except Exception:
                        continue
                    # Skip symlink for safety in directory ingestion
                    continue
                dest.write_bytes(p.read_bytes())

            detection = detect_artifacts(ws_path)
            artifact_types = summarize_artifact_types(detection)
            routing = recommend_scanners(detection)

            # P11.2 AppSec
            safe_name_dir = (source_name or src.name)[:100]
            repo_value_dir = normalize_repository_value(project_id, safe_name_dir, "directory")
            repo_asset_dir = {
                "type": "repository",
                "value": repo_value_dir,
                "metadata": {
                    "source_type": "directory",
                    "source_name": safe_name_dir[:200],
                    "ingestion_id": ingestion_id[:100],
                    "project_id": project_id,
                    "sources": ["ingestion"],
                },
            }
            source_assets_dir = create_source_file_assets(ws_path, type("obj", (), {"project_id": project_id, "source_name": safe_name_dir, "artifact_details": detection, "source_type": "directory", "ingestion_id": ingestion_id})())
            appsec_rels_dir = build_appsec_relationships(repo_asset_dir, source_assets_dir)

            duration_ms = int((time.monotonic() - start) * 1000)

            return IngestionResult(
                ingestion_id=ingestion_id,
                project_id=project_id,
                source_type="directory",
                source_name=source_name or src.name,
                workspace_path=str(ws_path),
                file_count=file_count,
                total_size=total_size,
                detected_languages=detection.get("languages", {}),
                detected_artifact_types=artifact_types,
                artifact_details=detection,
                recommended_scanners=routing["recommended"],
                scan_reasons=routing["reasons"],
                status="completed",
                duration_ms=duration_ms,
                appsec_assets=[repo_asset_dir] + source_assets_dir,
                appsec_relationships=appsec_rels_dir,
                repository_asset=repo_asset_dir,
            )
        except IngestionError as e:
            if workspace:
                try:
                    cleanup_workspace(workspace)
                except Exception:
                    pass
            duration_ms = int((time.monotonic() - start) * 1000)
            return IngestionResult(
                ingestion_id=ingestion_id,
                project_id=project_id,
                source_type="directory",
                source_name=(source_name or str(source_path))[:100],
                workspace_path="",
                file_count=0,
                total_size=0,
                status="failed",
                error_category=getattr(e, "category", "ingestion_error"),
                error_message=str(e)[:500],
                duration_ms=duration_ms,
            )
        except Exception as e:
            if workspace:
                try:
                    cleanup_workspace(workspace)
                except Exception:
                    pass
            duration_ms = int((time.monotonic() - start) * 1000)
            return IngestionResult(
                ingestion_id=ingestion_id,
                project_id=project_id,
                source_type="directory",
                source_name=(source_name or str(source_path))[:100],
                workspace_path="",
                file_count=0,
                total_size=0,
                status="failed",
                error_category="unknown_error",
                error_message=f"Ingestion failed: {type(e).__name__}",
                duration_ms=duration_ms,
            )

    def cleanup(self, workspace: str | Path) -> None:
        """Cleanup ingestion workspace via existing lifecycle."""
        cleanup_workspace(str(workspace))
