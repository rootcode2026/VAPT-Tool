import json, tempfile
from pathlib import Path
from app.scanner.scanners.sast import SASTScanner

def test_metadata():
    s = SASTScanner()
    m = s.metadata()
    assert m["name"] == "sast"
    assert "repository" in m["target_types"]
    assert m["input_type"] == "source_code"
    assert m["output_format"] == "sarif"

def test_target_type_validation():
    from app.scanner.manager import ScannerManager
    m = ScannerManager()
    # sast supports repository
    m.run("sast", "/tmp", target_type="repository")
    try:
        m.run("sast", "/tmp", target_type="domain")
        assert False
    except ValueError as e:
        assert "does not support" in str(e)

def test_directory_scanning(tmp_path):
    (tmp_path / "a.py").write_text('password = "secret123"\n')
    s = SASTScanner()
    raw = s.scan(str(tmp_path))
    data = json.loads(raw)
    assert data["scanner"] == "sast"
    assert len(data["findings"]) == 1

def test_json_output(tmp_path):
    (tmp_path / "a.py").write_text('x=1\n')
    s = SASTScanner()
    raw = s.scan(str(tmp_path))
    data = json.loads(raw)
    assert "findings" in data
    assert "metadata" in data

def test_findings_included(tmp_path):
    (tmp_path / "a.py").write_text('eval(x)\n')
    s = SASTScanner()
    data = json.loads(s.scan(str(tmp_path)))
    assert any(f["rule_id"] == "SAST002" for f in data["findings"])

def test_errors_included(tmp_path):
    (tmp_path / "bad.py").write_text("def foo(\n")
    s = SASTScanner()
    data = json.loads(s.scan(str(tmp_path)))
    assert len(data["errors"]) == 1

def test_deterministic_ordering(tmp_path):
    (tmp_path / "a.py").write_text('password = "a12345"\n')
    (tmp_path / "b.py").write_text('password = "b12345"\n')
    s = SASTScanner()
    d1 = json.loads(s.scan(str(tmp_path)))
    d2 = json.loads(s.scan(str(tmp_path)))
    assert d1["findings"] == d2["findings"]
