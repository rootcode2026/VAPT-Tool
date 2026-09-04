"""Secure archive extraction — ZIP, TAR, TAR.GZ, TGZ with traversal/symlink/bomb protection."""

import io
import os
import tarfile
import zipfile
from pathlib import Path

from .limits import MAX_EXTRACTED_SIZE, MAX_FILE_COUNT, MAX_FILE_SIZE, MAX_ARCHIVE_SIZE

# Reuse workspace containment helper
from app.scanner.workspace import _base_dir


class IngestionError(ValueError):
    """Safe, bounded error for ingestion failures — no secrets, no raw content."""

    def __init__(self, message: str, category: str = "ingestion_error"):
        super().__init__(message)
        self.category = category


def _is_within_workspace(target: Path, workspace: Path) -> bool:
    try:
        target.resolve().relative_to(workspace.resolve())
        return True
    except ValueError:
        return False


def _validate_entry_name(name: str) -> None:
    """Reject absolute, traversal, Windows drive, and unsafe names."""
    if not name or name.strip() == "":
        raise IngestionError("Empty archive entry name", "invalid_path")
    # Normalize separators
    normalized = name.replace("\\", "/")
    # Absolute Unix
    if normalized.startswith("/"):
        raise IngestionError(f"Absolute path rejected: {name[:100]}", "absolute_path")
    # Windows absolute e.g. C:\ or C:/ or \\server
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha():
        raise IngestionError(f"Windows drive path rejected: {name[:100]}", "windows_path")
    if normalized.startswith("//") or normalized.startswith("\\\\"):
        raise IngestionError(f"Windows UNC path rejected: {name[:100]}", "windows_path")
    # Traversal
    parts = normalized.split("/")
    if ".." in parts:
        raise IngestionError(f"Path traversal rejected: {name[:100]}", "traversal")
    if any(p == "" and i != len(parts) - 1 for i, p in enumerate(parts) if p == ""):
        # Empty part (e.g. //) is suspicious but not necessarily fatal — we already handled absolute
        pass
    # Unsafe filenames (null bytes, control)
    if "\x00" in name:
        raise IngestionError("Null byte in path", "invalid_path")


def _ensure_workspace_containment(workspace: Path) -> None:
    base = _base_dir().resolve()
    try:
        workspace.resolve().relative_to(base)
    except ValueError:
        raise IngestionError("Workspace outside allowed base", "workspace_escape")
    if workspace.resolve() == base:
        raise IngestionError("Workspace equals base", "workspace_escape")


def _check_symlink_target(link_target: str, workspace: Path, entry_path: Path) -> None:
    """Reject symlinks whose target escapes workspace or is absolute."""
    if not link_target:
        return
    # Absolute symlink target
    if link_target.startswith("/"):
        raise IngestionError(f"Symlink absolute target rejected: {link_target[:100]}", "symlink_escape")
    if len(link_target) >= 2 and link_target[1] == ":" and link_target[0].isalpha():
        raise IngestionError(f"Symlink Windows target rejected: {link_target[:100]}", "symlink_escape")
    if link_target.replace("\\", "/").startswith("//"):
        raise IngestionError("Symlink UNC target rejected", "symlink_escape")
    # Traversal in link target
    if ".." in link_target.replace("\\", "/").split("/"):
        # Resolve where the symlink would point
        # entry_path is the symlink location; target is relative to its parent
        try:
            resolved = (entry_path.parent / link_target).resolve()
            if not _is_within_workspace(resolved, workspace):
                raise IngestionError(f"Symlink escapes workspace: {link_target[:100]}", "symlink_escape")
        except Exception:
            raise IngestionError(f"Symlink traversal rejected: {link_target[:100]}", "symlink_escape")


def safe_extract_zip(archive_bytes: bytes, workspace: Path) -> tuple[int, int]:
    """Extract ZIP safely into workspace. Returns (file_count, total_size)."""
    _ensure_workspace_containment(workspace)
    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        raise IngestionError(f"Archive size {len(archive_bytes)} exceeds limit {MAX_ARCHIVE_SIZE}", "archive_too_large")

    file_count = 0
    total_size = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            # First pass: validate all entries
            for info in zf.infolist():
                name = info.filename
                # Skip directory entries (ending with /) — they are safe but validate
                if not name or name.strip() == "":
                    continue
                # ZipInfo may have directory flag
                is_dir = name.endswith("/")
                _validate_entry_name(name)
                # Symlink detection in ZIP: check external_attr and file type
                # ZIP stores symlinks as regular files with symlink target as content and specific attr
                is_symlink = (info.external_attr >> 16) & 0o120000 == 0o120000
                if is_symlink:
                    # Read symlink target
                    try:
                        target = zf.read(name).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        target = ""
                    entry_path = workspace / name
                    _check_symlink_target(target, workspace, entry_path)
                    # Symlinks count as file but not size
                    file_count += 1
                    if file_count > MAX_FILE_COUNT:
                        raise IngestionError(f"File count exceeds limit {MAX_FILE_COUNT}", "too_many_files")
                    continue
                if is_dir:
                    continue
                # Regular file checks
                file_size = info.file_size
                if file_size > MAX_FILE_SIZE:
                    raise IngestionError(f"File {name[:100]} size {file_size} exceeds limit {MAX_FILE_SIZE}", "file_too_large")
                total_size += file_size
                if total_size > MAX_EXTRACTED_SIZE:
                    raise IngestionError(f"Extracted size {total_size} exceeds limit {MAX_EXTRACTED_SIZE}", "extracted_too_large")
                file_count += 1
                if file_count > MAX_FILE_COUNT:
                    raise IngestionError(f"File count exceeds limit {MAX_FILE_COUNT}", "too_many_files")
                # Also check workspace containment for the final path
                dest = (workspace / name).resolve()
                if not _is_within_workspace(dest, workspace):
                    raise IngestionError(f"Extraction escapes workspace: {name[:100]}", "workspace_escape")
                # Hard link not applicable to ZIP

            # Second pass: extract
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
                    # Create symlink safely (already validated)
                    target = zf.read(name).decode("utf-8", errors="ignore").strip()
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    # Use symlink, but ensure it stays within workspace (already validated)
                    try:
                        if dest.exists() or dest.is_symlink():
                            dest.unlink()
                        dest.symlink_to(target)
                    except Exception as e:
                        raise IngestionError(f"Symlink creation failed: {str(e)[:100]}", "symlink_error")
                    continue
                # Regular file
                dest.parent.mkdir(parents=True, exist_ok=True)
                # Enforce individual file size during extraction as well
                with zf.open(info) as src, open(dest, "wb") as dst:
                    # Stream with limit
                    remaining = info.file_size
                    while remaining > 0:
                        chunk = src.read(min(8192, remaining))
                        if not chunk:
                            break
                        dst.write(chunk)
                        remaining -= len(chunk)
                # Verify after extraction still within workspace
                if not _is_within_workspace(dest.resolve(), workspace):
                    # Remove the offending file
                    try:
                        dest.unlink()
                    except Exception:
                        pass
                    raise IngestionError(f"Extracted file escapes workspace: {name[:100]}", "workspace_escape")
    except zipfile.BadZipFile as e:
        raise IngestionError(f"Malformed ZIP: {str(e)[:200]}", "malformed_archive") from e
    except IngestionError:
        raise
    except Exception as e:
        # Sanitize error
        raise IngestionError(f"ZIP extraction failed: {type(e).__name__}", "extraction_error") from e

    return file_count, total_size


def safe_extract_tar(archive_bytes: bytes, workspace: Path) -> tuple[int, int]:
    """Extract TAR/TAR.GZ/TGZ safely into workspace. Returns (file_count, total_size)."""
    _ensure_workspace_containment(workspace)
    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        raise IngestionError(f"Archive size {len(archive_bytes)} exceeds limit {MAX_ARCHIVE_SIZE}", "archive_too_large")

    file_count = 0
    total_size = 0
    try:
        # Use mode r:* to handle gz/bz2 transparently
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
            members = tf.getmembers()
            # First pass: validate
            for member in members:
                name = member.name
                if not name or name.strip() == "":
                    continue
                _validate_entry_name(name)
                # Absolute or traversal already checked, but also check member's own checks
                # Symlink / hardlink
                if member.issym() or member.islnk():
                    linkname = member.linkname or ""
                    dest = workspace / name
                    _check_symlink_target(linkname, workspace, dest)
                    # Count symlinks/hardlinks as files for limit
                    file_count += 1
                    if file_count > MAX_FILE_COUNT:
                        raise IngestionError(f"File count exceeds limit {MAX_FILE_COUNT}", "too_many_files")
                    # Also check that link target doesn't escape
                    # Already validated
                    continue
                # Regular file or directory
                if member.isdir():
                    continue
                if member.isreg():
                    file_size = member.size
                    if file_size > MAX_FILE_SIZE:
                        raise IngestionError(f"File {name[:100]} size {file_size} exceeds limit {MAX_FILE_SIZE}", "file_too_large")
                    total_size += file_size
                    if total_size > MAX_EXTRACTED_SIZE:
                        raise IngestionError(f"Extracted size {total_size} exceeds limit {MAX_EXTRACTED_SIZE}", "extracted_too_large")
                    file_count += 1
                    if file_count > MAX_FILE_COUNT:
                        raise IngestionError(f"File count exceeds limit {MAX_FILE_COUNT}", "too_many_files")
                    dest = (workspace / name).resolve()
                    if not _is_within_workspace(dest, workspace):
                        raise IngestionError(f"Extraction escapes workspace: {name[:100]}", "workspace_escape")
                else:
                    # Other types (fifo, etc.) — reject
                    raise IngestionError(f"Unsupported entry type: {name[:100]}", "unsupported_type")

            # Second pass: extract
            for member in members:
                name = member.name
                if not name or name.strip() == "":
                    continue
                dest = workspace / name
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                if member.issym() or member.islnk():
                    # Create symlink/hardlink safely
                    linkname = member.linkname or ""
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        if dest.exists() or dest.is_symlink():
                            # Remove existing
                            if dest.is_dir() and not dest.is_symlink():
                                import shutil
                                shutil.rmtree(dest)
                            else:
                                dest.unlink()
                        if member.issym():
                            dest.symlink_to(linkname)
                        else:
                            # Hard link — only if target exists within workspace
                            target = workspace / linkname
                            if not target.exists():
                                raise IngestionError(f"Hard link target missing: {linkname[:100]}", "hardlink_error")
                            dest.hardlink_to(target)
                    except IngestionError:
                        raise
                    except Exception as e:
                        raise IngestionError(f"Link creation failed: {str(e)[:100]}", "link_error")
                    continue
                if member.isreg():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    # Extract file content with size limit
                    src = tf.extractfile(member)
                    if src is None:
                        raise IngestionError(f"Failed to extract {name[:100]}", "extraction_error")
                    with open(dest, "wb") as dst:
                        remaining = member.size
                        while remaining > 0:
                            chunk = src.read(min(8192, remaining))
                            if not chunk:
                                break
                            dst.write(chunk)
                            remaining -= len(chunk)
                    # Verify containment after
                    if not _is_within_workspace(dest.resolve(), workspace):
                        try:
                            dest.unlink()
                        except Exception:
                            pass
                        raise IngestionError(f"Extracted file escapes workspace: {name[:100]}", "workspace_escape")
    except tarfile.TarError as e:
        raise IngestionError(f"Malformed TAR: {str(e)[:200]}", "malformed_archive") from e
    except IngestionError:
        raise
    except Exception as e:
        raise IngestionError(f"TAR extraction failed: {type(e).__name__}", "extraction_error") from e

    return file_count, total_size


def detect_archive_type(archive_bytes: bytes, filename: str | None = None) -> str:
    """Detect archive type from filename or magic bytes."""
    name_lower = (filename or "").lower()
    if name_lower.endswith(".zip"):
        return "zip"
    if name_lower.endswith(".tar.gz") or name_lower.endswith(".tgz"):
        return "tar.gz"
    if name_lower.endswith(".tar"):
        return "tar"
    # Magic bytes
    if archive_bytes.startswith(b"PK\x03\x04"):
        return "zip"
    if archive_bytes.startswith(b"\x1f\x8b"):
        return "tar.gz"
    # TAR magic at 257: 'ustar'
    if len(archive_bytes) > 262 and archive_bytes[257:262] == b"ustar":
        return "tar"
    # Fallback: try to detect via tarfile
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
            tf.getmembers()
            return "tar"
    except Exception:
        pass
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            zf.infolist()
            return "zip"
    except Exception:
        pass
    raise IngestionError("Unsupported or malformed archive format", "unsupported_format")
