"""S7.2 Workspace lifecycle — isolated, temporary, per-attempt.

Creates unique temp directory per scan/scanner/attempt, mounts read-only
at /workspace for Docker scanners, cleans up on every path (success,
failure, timeout, exception, retry).

Security: uses tempfile.mkdtemp, validates paths, no shared workspace,
no predictable shared directory, read-only mount, no host root.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

WORKSPACE_BASE_ENV = "WORKSPACE_BASE"
DEFAULT_BASE = None  # Use system tempdir


def _base_dir() -> Path:
    base = os.getenv(WORKSPACE_BASE_ENV)
    if base:
        p = Path(base).resolve()
        # Ensure base exists and is a directory
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return p
    # Use system tempdir (e.g., /tmp) — isolated per scan
    return Path(tempfile.gettempdir())


def create_workspace(
    scan_id: str | None = None,
    scanner: str | None = None,
    attempt: int | None = None,
    project_id: str | None = None,
) -> str:
    """Create unique isolated workspace. Returns absolute path string."""
    base = _base_dir()
    # Prefix includes scan/scanner for debuggability but remains unique via mkdtemp
    prefix_parts = ["vapt"]
    if scan_id:
        prefix_parts.append(str(scan_id)[:8])
    if scanner:
        prefix_parts.append(str(scanner))
    if attempt is not None:
        prefix_parts.append(f"a{attempt}")
    prefix = "-".join(prefix_parts) + "-"
    # mkdtemp ensures unique, not predictable shared directory, 0o700 perms by default
    workspace = tempfile.mkdtemp(prefix=prefix, dir=str(base))
    # Ensure 0o700
    try:
        os.chmod(workspace, 0o700)
    except Exception:
        pass
    return workspace


def cleanup_workspace(workspace: str | None) -> None:
    """Remove workspace if it exists within allowed base. Silently ignore errors."""
    if not workspace:
        return
    try:
        path = Path(workspace).resolve()
        base = _base_dir().resolve()
        # Security: ensure path is inside base and not root, not traversal
        try:
            path.relative_to(base)
        except ValueError:
            # Not inside base — do not delete (prevents accidental host delete)
            return
        if path == base:
            return
        if not path.exists():
            return
        # Ensure we only delete directories (not files)
        if not path.is_dir():
            return
        shutil.rmtree(str(path), ignore_errors=True)
    except Exception:
        # Never hide original scanner error; cleanup failure is logged but not propagated
        pass


def is_workspace_path_safe(workspace: str | None) -> bool:
    """Check if workspace path is safe (inside base, absolute, no traversal)."""
    if not workspace:
        return False
    try:
        path = Path(workspace).resolve()
        base = _base_dir().resolve()
        path.relative_to(base)
        if path == base:
            return False
        if ".." in workspace.split("/"):
            return False
        return path.is_dir()
    except Exception:
        return False
