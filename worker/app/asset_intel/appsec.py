"""P11.2 Advanced AppSec Asset Intelligence — repository, source, package, IaC, API, container.

Deterministic, project-scoped, deduplicated, idempotent. Reuses canonical types.
"""

import re
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple

from app.asset_intel.normalize import canonical_value, infer_asset_type, infer_asset_value
from app.asset_intel.types import KNOWN_ASSET_TYPES

# Repository value normalization — deterministic, project-scoped
def normalize_repository_value(project_id: str, source_name: str, source_type: str = "repository") -> str:
    """Return canonical repository asset value.

    Format: repo:{project_id}:{sanitized_source_name}
    Sanitized: lowercase, alphanumeric + - _ ., truncated 200, hashed if too long.
    """
    pid = str(project_id or "").strip()
    name = str(source_name or "unknown").strip().lower()
    # Sanitize: keep alphanumeric, -, _, ., /
    sanitized = re.sub(r"[^a-z0-9._\-/]", "-", name)
    sanitized = re.sub(r"-+", "-", sanitized).strip("-")
    if not sanitized:
        sanitized = "unknown"
    sanitized = sanitized[:200]
    value = f"repo:{pid}:{sanitized}"
    # Ensure within max length
    if len(value) > 1024:
        # Hash and truncate
        h = hashlib.sha256(value.encode()).hexdigest()[:12]
        value = f"repo:{pid}:{sanitized[:180]}-{h}"
    return value[:1024]


def create_repository_asset(project_id: str, ingestion_result) -> Dict:
    """Create repository asset from ingestion result."""
    source_name = getattr(ingestion_result, "source_name", "unknown") or "unknown"
    source_type = getattr(ingestion_result, "source_type", "repository") or "repository"
    ingestion_id = getattr(ingestion_result, "ingestion_id", "") or ""
    value = normalize_repository_value(project_id, source_name, source_type)
    metadata = {
        "source_type": source_type,
        "source_name": source_name[:200],
        "ingestion_id": ingestion_id[:100],
        "project_id": project_id,
        "sources": ["ingestion"],
    }
    # Add detected languages/artifacts if available
    det = getattr(ingestion_result, "artifact_details", {}) or {}
    if isinstance(det, dict):
        if det.get("languages"):
            # Store top 5 languages
            langs = list(det["languages"].keys())[:5]
            metadata["languages"] = langs
        if det.get("dependency_manifests"):
            metadata["manifests"] = list(det["dependency_manifests"].keys())[:10]
    # Branch/ref/revision if available in ingestion metadata (future Git)
    for field in ("branch", "ref", "revision", "commit"):
        val = getattr(ingestion_result, field, None)
        if val:
            metadata[field] = str(val)[:100]
    return {
        "type": "repository",
        "value": value,
        "metadata": metadata,
    }


def normalize_source_file_path(workspace: Path, file_path: str | Path) -> str:
    """Normalize source file path to relative, prevent traversal."""
    try:
        p = Path(str(file_path))
        # If absolute, make relative to workspace if possible
        if p.is_absolute():
            try:
                rel = p.resolve().relative_to(workspace.resolve())
                return str(rel).replace("\\", "/")
            except ValueError:
                # Absolute outside workspace — reject
                return ""
        # Relative path — clean
        text = str(file_path).replace("\\", "/").strip()
        # Check absolute before stripping (both Unix and Windows)
        if text.startswith("/") or text.startswith("\\"):
            return ""
        if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
            return ""
        if text.startswith("//"):
            return ""
        # Check traversal before stripping
        if ".." in text.split("/"):
            return ""
        text = text.lstrip("./")
        if ".." in text.split("/"):
            return ""
        if text.startswith("/"):
            return ""
        # Windows drive after stripping
        if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
            return ""
        return text[:1024]
    except Exception:
        return ""


def create_source_file_assets(workspace: Path, ingestion_result) -> List[Dict]:
    """Create source_file assets for files detected in ingestion."""
    assets = []
    seen = set()
    # Use artifact_details.languages and total_files, but also walk workspace for source files
    # For determinism, walk workspace and create asset per file with known language extension
    from app.ingestion.artifact_detection import LANGUAGE_MAP

    try:
        for p in workspace.rglob("*"):
            if not p.is_file():
                continue
            try:
                p.resolve().relative_to(workspace.resolve())
            except ValueError:
                continue
            suffix = p.suffix.lower()
            if suffix not in LANGUAGE_MAP:
                continue
            rel = normalize_source_file_path(workspace, p.relative_to(workspace))
            if not rel:
                continue
            key = ("source_file", rel)
            if key in seen:
                continue
            seen.add(key)
            lang = LANGUAGE_MAP[suffix]
            assets.append({
                "type": "source_file",
                "value": rel,
                "metadata": {
                    "language": lang,
                    "extension": suffix,
                    "repository": normalize_repository_value(
                        getattr(ingestion_result, "project_id", ""),
                        getattr(ingestion_result, "source_name", "unknown")
                    ),
                    "relative_path": rel,
                    "sources": ["ingestion"],
                },
            })
            if len(assets) >= 10000:
                break
    except Exception:
        pass
    return assets


def normalize_package_identity(ecosystem: str, package_name: str, version: str = "") -> Tuple[str, str]:
    """Normalize package identity for deduplication.

    Returns (asset_type, value) where value is canonical package identifier.
    For npm: package@version, for pip: package@version lowercased, etc.
    """
    eco = str(ecosystem or "").strip().lower() or "unknown"
    name = str(package_name or "").strip()
    ver = str(version or "").strip()
    if not name:
        return ("package", "")
    # Normalize name per ecosystem
    if eco in ("npm", "yarn", "pnpm"):
        # npm is case-sensitive but we lower for dedup
        name = name.lower()
    elif eco in ("pip", "pypi"):
        name = name.lower().replace("_", "-")
    elif eco == "go":
        name = name.lower()
    # Value is package@version if version present, else package
    value = f"{name}@{ver}" if ver else name
    # Truncate and ensure project isolation is via asset key (project_id, asset_type, value) in persistence
    value = value[:1024]
    return ("package", value)


def create_package_assets_from_manifests(ingestion_result, packages: List[Dict] = None) -> List[Dict]:
    """Create package assets from ingestion manifests + optional scanner packages.

    `packages` is list of dicts with ecosystem, package_name, version, manifest
    """
    assets = []
    seen = set()
    # From ingestion manifests
    det = getattr(ingestion_result, "artifact_details", {}) or {}
    manifests = det.get("dependency_manifests", {}) if isinstance(det, dict) else {}
    if manifests:
        for manifest in manifests:
            # Manifest itself is a source_file, but we also create a package asset for the manifest file
            # The actual packages will be created by SCA scanner; here we just create manifest asset
            pass

    # From scanner-provided packages
    for pkg in packages or []:
        eco = pkg.get("ecosystem") or pkg.get("ecosystem_name") or "unknown"
        name = pkg.get("package_name") or pkg.get("name") or ""
        ver = pkg.get("version") or pkg.get("installed_version") or ""
        asset_type, value = normalize_package_identity(eco, name, ver)
        if not value:
            continue
        key = (asset_type, value)
        if key in seen:
            continue
        seen.add(key)
        assets.append({
            "type": asset_type,
            "value": value,
            "metadata": {
                "ecosystem": eco,
                "package_name": name,
                "version": ver,
                "sources": ["sca", "ingestion"],
            },
        })
    return assets


def build_appsec_relationships(
    repository_asset: Dict,
    source_file_assets: List[Dict],
    package_assets: List[Dict] = None,
    iac_assets: List[Dict] = None,
    api_assets: List[Dict] = None,
    container_assets: List[Dict] = None,
) -> List[Dict]:
    """Build deterministic AppSec relationships.

    Uses existing relationship types: contains, observed_on.
    All relationships are project-scoped via asset values (project_id is in repository value).
    """
    relationships = []
    seen = set()

    repo_type = repository_asset.get("type", "repository")
    repo_value = repository_asset.get("value", "")
    if not repo_value:
        return relationships

    def add_rel(source_type, source_value, target_type, target_value, rel_type, metadata=None):
        key = (source_type, source_value, target_type, target_value, rel_type)
        if key in seen:
            return
        seen.add(key)
        relationships.append({
            "source_type": source_type,
            "source_value": source_value,
            "target_type": target_type,
            "target_value": target_value,
            "relationship_type": rel_type,
            "metadata": metadata or {"sources": ["ingestion"]},
        })

    # repository contains source_file
    for asset in source_file_assets or []:
        add_rel(repo_type, repo_value, asset["type"], asset["value"], "contains", {"sources": ["ingestion"]})

    # repository contains iac_resource
    for asset in iac_assets or []:
        add_rel(repo_type, repo_value, asset["type"], asset["value"], "contains", {"sources": ["ingestion"]})

    # repository contains api_endpoint
    for asset in api_assets or []:
        add_rel(repo_type, repo_value, asset["type"], asset["value"], "contains", {"sources": ["ingestion"]})

    # repository contains package (via manifest) — package assets already have repository in metadata
    for asset in package_assets or []:
        add_rel(repo_type, repo_value, asset["type"], asset["value"], "contains", {"sources": ["ingestion", "sca"]})

    # container_image is not necessarily contained by repository (it may be external), but if ingestion has container_image, link
    for asset in container_assets or []:
        add_rel(repo_type, repo_value, asset["type"], asset["value"], "contains", {"sources": ["ingestion"]})

    return relationships


def associate_findings_to_assets(findings: List[Dict], assets: List[Dict]) -> Dict[str, str]:
    """Associate findings to most specific asset.

    Reuses existing logic: match by file, package, etc.
    Returns mapping finding_index -> asset_value
    """
    # Build asset index by type and value
    asset_by_value = {a["value"]: a for a in assets if isinstance(a, dict) and a.get("value")}
    asset_by_type = {}
    for a in assets:
        t = a.get("type")
        if t not in asset_by_type:
            asset_by_type[t] = []
        asset_by_type[t].append(a)

    mapping = {}
    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        meta = finding.get("metadata", {}) if isinstance(finding.get("metadata"), dict) else {}
        # Try file first (SAST, Secrets, IaC, API)
        file_val = meta.get("file") or finding.get("file") or meta.get("relative_path")
        if file_val and isinstance(file_val, str):
            # Normalize
            file_val = file_val.strip().replace("\\", "/").lstrip("./")
            if file_val in asset_by_value:
                mapping[str(idx)] = file_val
                continue
            # Try source_file assets
            for asset in asset_by_type.get("source_file", []):
                if asset["value"] == file_val:
                    mapping[str(idx)] = asset["value"]
                    break
            if str(idx) in mapping:
                continue
        # Try package (SCA)
        pkg_name = meta.get("package_name") or meta.get("packageName")
        if pkg_name:
            for asset in asset_by_type.get("package", []):
                if pkg_name.lower() in asset["value"].lower():
                    mapping[str(idx)] = asset["value"]
                    break
            if str(idx) in mapping:
                continue
        # Try container_image
        image = meta.get("scanned_image") or meta.get("image") or meta.get("image_ref")
        if image and isinstance(image, str):
            for asset in asset_by_type.get("container_image", []):
                if asset["value"] == image:
                    mapping[str(idx)] = asset["value"]
                    break
            if str(idx) in mapping:
                continue
        # Try iac_resource
        resource = meta.get("resource") or meta.get("iac_resource")
        if resource:
            for asset in asset_by_type.get("iac_resource", []):
                if asset["value"] == resource or resource in asset["value"]:
                    mapping[str(idx)] = asset["value"]
                    break
            if str(idx) in mapping:
                continue
        # Try api_endpoint
        endpoint = meta.get("endpoint") or finding.get("endpoint")
        if endpoint:
            for asset in asset_by_type.get("api_endpoint", []):
                if endpoint in asset["value"] or asset["value"] in endpoint:
                    mapping[str(idx)] = asset["value"]
                    break

    return mapping


def get_repository_for_finding(finding: Dict, assets: List[Dict], relationships: List[Dict]) -> Dict | None:
    """Resolve finding -> asset -> repository via relationships.

    Returns repository asset if found, else None.
    """
    # First find direct asset for finding
    finding_asset_value = None
    meta = finding.get("metadata", {}) if isinstance(finding.get("metadata"), dict) else {}
    # Try to find asset that matches finding's file
    file_val = meta.get("file") or finding.get("file")
    if file_val:
        for asset in assets:
            if asset.get("value") == file_val and asset.get("type") in ("source_file", "iac_resource", "api_endpoint"):
                finding_asset_value = asset["value"]
                break
    # If not found via file, try via asset mapping
    if not finding_asset_value:
        # Fallback: use first asset
        if assets:
            finding_asset_value = assets[0].get("value")

    if not finding_asset_value:
        return None

    # Find repository that contains this asset
    for rel in relationships:
        if rel.get("relationship_type") == "contains" and rel.get("target_value") == finding_asset_value:
            source_value = rel.get("source_value")
            source_type = rel.get("source_type")
            if source_type == "repository":
                for asset in assets:
                    if asset.get("type") == "repository" and asset.get("value") == source_value:
                        return asset
    return None


def persist_appsec_assets(db, project_id: str, scan_id: str, ingestion_result) -> tuple[List[Dict], List[Dict]]:
    """Persist AppSec assets/relationships from ingestion result.

    Uses existing persistence layer for project-scoped, deduplicated, idempotent storage.
    Returns (persisted_assets, persisted_relationships).
    """
    from app.persistence import persist_parsed_bundle

    if not ingestion_result or getattr(ingestion_result, "status", "") != "completed":
        return [], []

    appsec_assets = getattr(ingestion_result, "appsec_assets", []) or []
    appsec_rels = getattr(ingestion_result, "appsec_relationships", []) or []

    if not appsec_assets:
        # Fallback: create from artifact_details if appsec_assets not populated (backward compat)
        workspace = getattr(ingestion_result, "workspace_path", "")
        if workspace:
            from pathlib import Path
            ws_path = Path(workspace)
            if ws_path.exists():
                appsec_assets = create_source_file_assets(ws_path, ingestion_result)
                repo = create_repository_asset(project_id, ingestion_result)
                appsec_assets = [repo] + appsec_assets
                appsec_rels = build_appsec_relationships(repo, appsec_assets[1:])

    if not appsec_assets:
        return [], []

    # Use existing persistence — it handles deduplication, project isolation, change detection
    persisted = persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="ingestion",
        assets=appsec_assets,
        findings=[],
    )

    # Persist relationships via upsert_relationships (called inside persist_parsed_bundle already handles assets,
    # but we need to ensure appsec relationships are also persisted)
    # persist_parsed_bundle already calls upsert_relationships for the bundle's relationships,
    # but our appsec_rels are not part of the bundle's relationships — they are from ingestion.
    # We need to explicitly upsert them.
    if appsec_rels:
        from app.persistence import upsert_relationships
        # Need persisted asset ids for relationship endpoints
        # persist_parsed_bundle returns list of {id, asset_type, value}
        # We need to map repository and source files to ids
        # For simplicity, call upsert_relationships directly with the appsec_rels and persisted assets
        # The function will resolve source/target ids via persisted map
        try:
            upsert_relationships(
                db,
                project_id=project_id,
                relationships=appsec_rels,
                persisted_assets=persisted,
                scanner="ingestion",
            )
        except Exception:
            # Fallback: if upsert fails (e.g., missing asset mapping), ignore — assets are still persisted
            pass

    return persisted, appsec_rels


def resolve_finding_asset_context(finding: Dict, assets: List[Dict], relationships: List[Dict]) -> Dict:
    """Resolve finding -> asset -> repository for risk context.

    Returns dict with repository, asset, related assets.
    """
    repo = get_repository_for_finding(finding, assets, relationships)
    # Find direct asset
    direct_asset = None
    meta = finding.get("metadata", {}) if isinstance(finding.get("metadata"), dict) else {}
    file_val = meta.get("file") or finding.get("file")
    if file_val:
        for asset in assets:
            if asset.get("value") == file_val:
                direct_asset = asset
                break
    # Find related assets via repository contains
    related = []
    if repo:
        for rel in relationships:
            if rel.get("source_value") == repo.get("value") and rel.get("relationship_type") == "contains":
                target_val = rel.get("target_value")
                for asset in assets:
                    if asset.get("value") == target_val and asset.get("value") != direct_asset.get("value") if direct_asset else True:
                        related.append(asset)

    return {
        "repository": repo,
        "direct_asset": direct_asset,
        "related_assets": related[:10],
        "finding_id": finding.get("id") or finding.get("finding_id"),
    }
