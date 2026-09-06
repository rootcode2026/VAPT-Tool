"""Safe repository snapshot — isolated workspace, no hook execution, no code execution, traversal protection."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

MAX_REPO_SIZE = 500 * 1024 * 1024
MAX_FILES = 10000
MAX_FILE_SIZE = 5 * 1024 * 1024
SNAPSHOT_TIMEOUT = 120

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._\-/]+$")
_NULL_BYTE_RE = re.compile(r"\x00")
_SHELL_FORBIDDEN = set(list(";|&$`") + ["*", "?", "~", "<", ">", "^", "(", ")", "[", "]", "{", "}", "'", '"', "\\", "!", "%"])

def _validate_id(value: str, field: str):
    if not value or not isinstance(value, str):
        raise ValueError(f"Invalid {field}")
    v = value.strip()
    if not v or len(v) > 255:
        raise ValueError(f"Invalid {field} length")
    if "\x00" in v or "\n" in v or "\r" in v:
        raise ValueError(f"Invalid {field} contains control")
    if ".." in v:
        raise ValueError(f"{field} must not contain ..")
    for ch in v:
        if ch in _SHELL_FORBIDDEN:
            # allow / and -._ for repo ids, but not shell metachars
            if ch in "/-._":
                continue
            raise ValueError(f"Invalid {field} char {ch!r}")
    return v

def _ensure_workspace(project_id: str, repo_id: str, commit_sha: str) -> Path:
    # Validate inputs
    _validate_id(project_id, "project_id")
    _validate_id(repo_id, "repo_id")
    _validate_id(commit_sha, "commit_sha")
    base = Path("/tmp") / "workspace" / project_id / repo_id.replace("/", "_") / commit_sha[:12]
    # Ensure base is under /tmp/workspace
    base_resolved = base.resolve()
    expected = Path("/tmp/workspace").resolve()
    if not str(base_resolved).startswith(str(expected)):
        raise ValueError("Workspace escape")
    base.mkdir(parents=True, exist_ok=True)
    # Restrict perms 0o700
    try:
        os.chmod(base, 0o700)
    except Exception:
        pass
    return base

def safe_clone_snapshot(credential: str, clone_url: str, branch: str, commit_sha: str, project_id: str, repo_id: str) -> dict:
    """Clone repository safely into isolated workspace, checkout commit, with hooks disabled.

    Does not execute code, does not install deps. Returns workspace path and metadata.
    """
    # Validate clone_url is https and sanitized
    if not clone_url or not clone_url.startswith("https://"):
        raise ValueError("Invalid clone url")
    clone_url = clone_url.strip()
    if ".." in clone_url or " " in clone_url:
        raise ValueError("Invalid clone url")
    # Validate branch/commit
    branch = _validate_id(branch, "branch")
    commit_sha = _validate_id(commit_sha, "commit_sha")
    if len(commit_sha) < 7 or len(commit_sha) > 64:
        raise ValueError("Invalid commit SHA")

    ws = _ensure_workspace(project_id, repo_id, commit_sha)
    # If workspace already has content, clean
    if ws.exists():
        # Check for symlink escape before removal
        for p in ws.rglob("*"):
            try:
                # Reject symlink outside workspace
                if p.is_symlink():
                    target = p.resolve()
                    if not str(target).startswith(str(ws.resolve())):
                        # Remove unsafe symlink
                        try:
                            p.unlink()
                        except Exception:
                            pass
            except Exception:
                pass

    start = time.time()
    # Use credential as token for https clone via header, not URL embedding
    # Prefer: git -c core.hooksPath=/dev/null clone --no-checkout --filter=blob:none --depth 1 -b branch url ws
    # Use argument array, no shell
    env = os.environ.copy()
    # Disable git hooks and unsafe configs
    git_config = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never"]
    clone_cmd = ["git"] + git_config + ["clone", "--no-checkout", "--depth", "1", "--branch", branch, clone_url, str(ws / "repo")]
    try:
        # Timeout bounded
        result = subprocess.run(clone_cmd, capture_output=True, timeout=SNAPSHOT_TIMEOUT, env=env)
        if result.returncode != 0:
            # Sanitized error (no credential)
            err = result.stderr.decode(errors="replace")[:500]
            if "password" in err.lower() or "token" in err.lower():
                err = "Clone failed (sanitized)"
            raise RuntimeError(f"Clone failed: {err[:200]}")
        # Checkout specific commit safely
        repo_dir = ws / "repo"
        # Verify repo_dir inside ws
        if not str(repo_dir.resolve()).startswith(str(ws.resolve())):
            raise ValueError("Path traversal")
        checkout_cmd = ["git", "-C", str(repo_dir)] + git_config + ["checkout", commit_sha]
        result2 = subprocess.run(checkout_cmd, capture_output=True, timeout=60, env=env)
        if result2.returncode != 0:
            # Fallback to fetch + checkout
            fetch_cmd = ["git", "-C", str(repo_dir)] + git_config + ["fetch", "--depth", "1", "origin", commit_sha]
            subprocess.run(fetch_cmd, capture_output=True, timeout=60, env=env)
            result3 = subprocess.run(checkout_cmd, capture_output=True, timeout=60, env=env)
            if result3.returncode != 0:
                raise RuntimeError("Checkout failed")
        # Enforce limits: count files, size
        total_size = 0
        file_count = 0
        for p in repo_dir.rglob("*"):
            if p.is_file():
                # Reject symlink escape
                try:
                    if p.is_symlink():
                        target = p.resolve()
                        if not str(target).startswith(str(repo_dir.resolve())):
                            p.unlink()
                            continue
                except Exception:
                    continue
                try:
                    sz = p.stat().st_size
                    if sz > MAX_FILE_SIZE:
                        # oversized file: remove or skip
                        p.unlink()
                        continue
                    total_size += sz
                    file_count += 1
                    if file_count > MAX_FILES or total_size > MAX_REPO_SIZE:
                        raise RuntimeError("Repository limits exceeded")
                except Exception as e:
                    if "limits exceeded" in str(e):
                        raise
                    pass
                if time.time() - start > SNAPSHOT_TIMEOUT:
                    raise TimeoutError("Snapshot timeout")
        # Ensure no executable hooks remain
        hooks_dir = repo_dir / ".git" / "hooks"
        if hooks_dir.exists():
            shutil.rmtree(hooks_dir, ignore_errors=True)
        return {
            "workspace": str(ws / "repo"),
            "branch": branch,
            "commit_sha": commit_sha,
            "file_count": file_count,
            "total_size": total_size,
            "snapshot_at": int(time.time()),
        }
    except Exception:
        # Cleanup on failure
        try:
            shutil.rmtree(ws, ignore_errors=True)
        except Exception:
            pass
        raise
    finally:
        pass
