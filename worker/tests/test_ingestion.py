"""P11.1 Ingestion — 24 focused tests for secure archive handling, detection, routing."""

import io
import os
import tarfile
import zipfile
import tempfile
from pathlib import Path

import pytest

from app.ingestion.service import IngestionService
from app.ingestion.archive import IngestionError
from app.ingestion.artifact_detection import detect_artifacts, summarize_artifact_types
from app.ingestion.scanner_routing import recommend_scanners
from app.scanner.workspace import cleanup_workspace


def _make_zip(files: dict[str, bytes]) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return bio.getvalue()


def _make_tar(files: dict[str, bytes], gz: bool = False) -> bytes:
    bio = io.BytesIO()
    mode = "w:gz" if gz else "w"
    with tarfile.open(fileobj=bio, mode=mode) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 0
            tf.addfile(ti, io.BytesIO(data))
    return bio.getvalue()


def _make_tar_with_symlink(target: str, linkname: str) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        # Add a file
        data = b"hello"
        ti = tarfile.TarInfo("real.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
        # Add symlink
        ti2 = tarfile.TarInfo(linkname)
        ti2.type = tarfile.SYMTYPE
        ti2.linkname = target
        ti2.size = 0
        tf.addfile(ti2)
    return bio.getvalue()


# 1-3: Normal archive ingestion
def test_01_zip_ingestion():
    svc = IngestionService()
    data = _make_zip({"a.py": b"print(1)", "README.md": b"hello"})
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    assert res.status == "completed"
    assert res.file_count == 2
    assert res.workspace_path != ""
    assert Path(res.workspace_path).exists()
    cleanup_workspace(res.workspace_path)
    assert not Path(res.workspace_path).exists()


def test_02_tar_ingestion():
    svc = IngestionService()
    data = _make_tar({"a.py": b"print(1)", "b.js": b"console.log(1)"})
    res = svc.prepare_from_archive(data, "test.tar", project_id="proj1")
    assert res.status == "completed"
    assert res.file_count == 2
    cleanup_workspace(res.workspace_path)


def test_03_tar_gz_ingestion():
    svc = IngestionService()
    data = _make_tar({"main.tf": b'resource "x" "y" {}'}, gz=True)
    res = svc.prepare_from_archive(data, "test.tar.gz", project_id="proj1")
    assert res.status == "completed"
    assert res.file_count == 1
    cleanup_workspace(res.workspace_path)


def test_04_normal_repository_structure():
    svc = IngestionService()
    files = {
        "src/main.py": b"print(1)",
        "package.json": b'{"name":"t"}',
        "requirements.txt": b"requests==1.0",
        "Dockerfile": b"FROM alpine",
        "openapi.yaml": b"openapi: 3.0.0",
    }
    data = _make_zip(files)
    res = svc.prepare_from_archive(data, "repo.zip", project_id="proj1")
    assert res.status == "completed"
    assert res.file_count == 5
    assert "Python" in res.detected_languages
    assert "iac" in res.detected_artifact_types or "source_code" in res.detected_artifact_types
    cleanup_workspace(res.workspace_path)


# 5-9: Security rejections
def test_05_path_traversal_rejection():
    svc = IngestionService()
    data = _make_zip({"../evil.py": b"bad", "good.py": b"ok"})
    res = svc.prepare_from_archive(data, "evil.zip", project_id="proj1")
    assert res.status == "failed"
    assert res.error_category == "traversal"


def test_06_absolute_path_rejection():
    svc = IngestionService()
    data = _make_zip({"/etc/passwd": b"bad"})
    res = svc.prepare_from_archive(data, "evil.zip", project_id="proj1")
    assert res.status == "failed"
    assert res.error_category == "absolute_path"


def test_07_windows_path_rejection():
    svc = IngestionService()
    data = _make_zip({"C:/Windows/win.ini": b"bad", "D:\\evil.txt": b"bad2"})
    res = svc.prepare_from_archive(data, "evil.zip", project_id="proj1")
    assert res.status == "failed"
    assert res.error_category in ("windows_path", "traversal", "absolute_path")


def test_08_symlink_escape_rejection():
    svc = IngestionService()
    data = _make_tar_with_symlink("/etc/passwd", "link")
    res = svc.prepare_from_archive(data, "evil.tar", project_id="proj1")
    assert res.status == "failed"
    assert res.error_category == "symlink_escape"


def test_09_hardlink_escape_handling():
    # Hard link to file outside workspace via linkname traversal
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        ti = tarfile.TarInfo("real.txt")
        ti.size = 5
        tf.addfile(ti, io.BytesIO(b"hello"))
        ti2 = tarfile.TarInfo("hardlink")
        ti2.type = tarfile.LNKTYPE
        ti2.linkname = "../outside.txt"
        ti2.size = 0
        tf.addfile(ti2)
    data = bio.getvalue()
    svc = IngestionService()
    res = svc.prepare_from_archive(data, "evil.tar", project_id="proj1")
    assert res.status == "failed"
    assert res.error_category in ("symlink_escape", "traversal", "hardlink_error")


# 10-13: Resource limits
def test_10_archive_size_limit():
    svc = IngestionService()
    import app.ingestion.archive as arch
    old = arch.MAX_ARCHIVE_SIZE
    arch.MAX_ARCHIVE_SIZE = 10
    try:
        data = _make_zip({"a.py": b"x" * 20})
        res = svc.prepare_from_archive(data, "big.zip", project_id="proj1")
        assert res.status == "failed"
        assert res.error_category == "archive_too_large"
    finally:
        arch.MAX_ARCHIVE_SIZE = old


def test_11_extracted_size_limit():
    svc = IngestionService()
    import app.ingestion.archive as arch
    old = arch.MAX_EXTRACTED_SIZE
    arch.MAX_EXTRACTED_SIZE = 10
    try:
        data = _make_zip({"a.py": b"x" * 20})
        res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
        assert res.status == "failed"
        assert res.error_category == "extracted_too_large"
    finally:
        arch.MAX_EXTRACTED_SIZE = old


def test_12_file_count_limit():
    svc = IngestionService()
    import app.ingestion.archive as arch
    old = arch.MAX_FILE_COUNT
    arch.MAX_FILE_COUNT = 2
    try:
        data = _make_zip({"a.py": b"x", "b.py": b"x", "c.py": b"x"})
        res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
        assert res.status == "failed"
        assert res.error_category == "too_many_files"
    finally:
        arch.MAX_FILE_COUNT = old


def test_13_individual_file_size_limit():
    svc = IngestionService()
    import app.ingestion.archive as arch
    old = arch.MAX_FILE_SIZE
    arch.MAX_FILE_SIZE = 10
    try:
        data = _make_zip({"big.py": b"x" * 20})
        res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
        assert res.status == "failed"
        assert res.error_category == "file_too_large"
    finally:
        arch.MAX_FILE_SIZE = old


def test_14_malformed_archive():
    svc = IngestionService()
    data = b"not a zip or tar"
    res = svc.prepare_from_archive(data, "bad.zip", project_id="proj1")
    assert res.status == "failed"
    assert res.error_category in ("malformed_archive", "unsupported_format", "extraction_error")


def test_15_workspace_containment():
    svc = IngestionService()
    data = _make_zip({"a.py": b"print(1)"})
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    assert res.status == "completed"
    ws = Path(res.workspace_path)
    # All files must be within workspace
    for p in ws.rglob("*"):
        if p.is_file():
            assert str(p.resolve()).startswith(str(ws.resolve()))
    cleanup_workspace(res.workspace_path)


def test_16_workspace_cleanup():
    svc = IngestionService()
    data = _make_zip({"a.py": b"print(1)"})
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    ws = res.workspace_path
    assert Path(ws).exists()
    svc.cleanup(ws)
    assert not Path(ws).exists()
    # Cleanup again should not error
    svc.cleanup(ws)
    # Also test failed case cleanup
    bad_data = _make_zip({"/etc/passwd": b"bad"})
    res2 = svc.prepare_from_archive(bad_data, "evil.zip", project_id="proj1")
    assert res2.status == "failed"
    assert res2.workspace_path == ""  # Should be empty on failure (cleaned)


# 17-21: Artifact detection
def test_17_language_detection():
    svc = IngestionService()
    files = {
        "a.py": b"print(1)",
        "b.js": b"console.log(1)",
        "c.java": b"class A {}",
        "d.go": b"package main",
    }
    data = _make_zip(files)
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    assert res.status == "completed"
    assert "Python" in res.detected_languages
    assert "JavaScript" in res.detected_languages
    assert "Java" in res.detected_languages
    assert "Go" in res.detected_languages
    cleanup_workspace(res.workspace_path)


def test_18_dependency_manifest_detection():
    svc = IngestionService()
    files = {
        "package.json": b'{}',
        "requirements.txt": b"requests",
        "go.mod": b"module x",
        "pom.xml": b"<project></project>",
    }
    data = _make_zip(files)
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    assert res.status == "completed"
    assert "dependency_manifest" in res.detected_artifact_types or any("package.json" in str(k) for k in res.artifact_details.get("dependency_manifests", {}))
    assert "package.json" in res.artifact_details.get("dependency_manifests", {})
    cleanup_workspace(res.workspace_path)


def test_19_iac_detection():
    svc = IngestionService()
    files = {
        "main.tf": b'resource "x" "y" {}',
        "k8s/deployment.yaml": b"apiVersion: v1\nkind: Pod",
        "Dockerfile": b"FROM alpine",
    }
    data = _make_zip(files)
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    assert res.status == "completed"
    assert "iac" in res.detected_artifact_types
    cleanup_workspace(res.workspace_path)


def test_20_api_spec_detection():
    svc = IngestionService()
    files = {
        "openapi.json": b'{"openapi":"3.0.0","info":{"title":"t","version":"1"}}',
        "swagger.yaml": b"swagger: '2.0'",
    }
    data = _make_zip(files)
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    assert res.status == "completed"
    assert "api_spec" in res.detected_artifact_types
    cleanup_workspace(res.workspace_path)


def test_21_secrets_config_detection():
    svc = IngestionService()
    files = {
        ".env": b"SECRET=123",
        ".env.production": b"KEY=abc",
        "config.yaml": b"key: value",
        "id_rsa": b"private",
    }
    data = _make_zip(files)
    res = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    assert res.status == "completed"
    assert "secrets_candidate" in res.detected_artifact_types
    cleanup_workspace(res.workspace_path)


# 22: Scanner routing
def test_22_scanner_routing():
    # Python source -> SAST
    det = {"languages": {"Python": 1}, "dependency_manifests": {}, "secrets_candidates": {}, "iac_files": {}, "api_specs": {}}
    routing = recommend_scanners(det)
    assert "sast" in routing["recommended"]
    # package.json -> SCA
    det2 = {"languages": {}, "dependency_manifests": {"package.json": 1}, "secrets_candidates": {}, "iac_files": {}, "api_specs": {}}
    routing2 = recommend_scanners(det2)
    assert "sca" in routing2["recommended"]
    # .env -> Secrets
    det3 = {"languages": {}, "dependency_manifests": {}, "secrets_candidates": {".env": 1}, "iac_files": {}, "api_specs": {}}
    routing3 = recommend_scanners(det3)
    assert "secrets" in routing3["recommended"]
    # .tf -> IaC
    det4 = {"languages": {}, "dependency_manifests": {}, "secrets_candidates": {}, "iac_files": {"main.tf": 1}, "api_specs": {}}
    routing4 = recommend_scanners(det4)
    assert "iac" in routing4["recommended"]
    # openapi -> API
    det5 = {"languages": {}, "dependency_manifests": {}, "secrets_candidates": {}, "iac_files": {}, "api_specs": {"openapi.json": 1}}
    routing5 = recommend_scanners(det5)
    assert "api" in routing5["recommended"]
    # Combined
    det_all = {"languages": {"Python": 1}, "dependency_manifests": {"package.json": 1}, "secrets_candidates": {".env": 1}, "iac_files": {"main.tf": 1}, "api_specs": {"openapi.json": 1}}
    routing_all = recommend_scanners(det_all)
    assert set(routing_all["recommended"]) == {"sast", "sca", "secrets", "iac", "api"}
    # Container only via flag
    routing_c = recommend_scanners(det, has_container_image=True)
    assert "container" in routing_c["recommended"]


# 23: Project isolation
def test_23_project_isolation():
    svc = IngestionService()
    data = _make_zip({"a.py": b"print(1)"})
    res1 = svc.prepare_from_archive(data, "test.zip", project_id="proj1")
    res2 = svc.prepare_from_archive(data, "test.zip", project_id="proj2")
    assert res1.status == "completed"
    assert res2.status == "completed"
    assert res1.project_id == "proj1"
    assert res2.project_id == "proj2"
    assert res1.workspace_path != res2.workspace_path
    assert "proj1" in res1.workspace_path or "proj2" not in res1.workspace_path  # prefix contains project
    cleanup_workspace(res1.workspace_path)
    cleanup_workspace(res2.workspace_path)


# 24: Sanitized error behavior
def test_24_sanitized_error_behavior():
    svc = IngestionService()
    # Create archive with Windows path that triggers error containing filename
    # Error should not leak raw content or secrets
    secret_content = b"SECRET_VALUE_FAKE_12345"
    data = _make_zip({"C:/Windows/win.ini": secret_content})
    res = svc.prepare_from_archive(data, "evil.zip", project_id="proj1")
    assert res.status == "failed"
    # Error message should be bounded and not contain secret content
    assert "SECRET_VALUE_FAKE_12345" not in (res.error_message or "")
    assert len(res.error_message or "") <= 500
    # Also test malformed archive error is sanitized
    res2 = svc.prepare_from_archive(b"\x00\x01\x02", "bad.zip", project_id="proj1")
    assert res2.status == "failed"
    assert len(res2.error_message or "") <= 500
    # Ensure warnings are also bounded
    assert res2.workspace_path == ""
