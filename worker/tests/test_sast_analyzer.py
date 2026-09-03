import tempfile
import os
from pathlib import Path
from app.services.sast.analyzer import SASTAnalyzer

def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def test_hardcoded_password_detection(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "app.py"
    _write(f, 'password = "secret123"\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(r["rule_id"] == "SAST001" for r in result["findings"])

def test_hardcoded_api_key_detection(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "config.py"
    _write(f, 'api_key = "abcdef12345"\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(r["rule_id"] == "SAST001" for r in result["findings"])

def test_eval_detection(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'x = eval(user_input)\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(r["rule_id"] == "SAST002" for r in result["findings"])

def test_exec_detection(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'exec(user_input)\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(r["rule_id"] == "SAST002" for r in result["findings"])

def test_subprocess_shell_detection(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'import subprocess\nsubprocess.run(command, shell=True)\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(r["rule_id"] == "SAST003" for r in result["findings"])

def test_unsafe_sql_construction_detection(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'query = "SELECT * FROM users WHERE id=" + user_id\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(r["rule_id"] == "SAST004" for r in result["findings"])

def test_pickle_loads_detection(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'import pickle\npickle.loads(data)\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(r["rule_id"] == "SAST005" for r in result["findings"])

def test_comments_do_not_trigger(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, '# password = "secret123"\n# eval(user_input)\n')
    result = analyzer.analyze(str(tmp_path))
    assert len(result["findings"]) == 0

def test_safe_code_no_findings(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'x = 1\ny = x + 2\nprint(y)\n')
    result = analyzer.analyze(str(tmp_path))
    assert len(result["findings"]) == 0

def test_correct_file_path(tmp_path):
    analyzer = SASTAnalyzer()
    sub = tmp_path / "sub"
    f = sub / "app.py"
    _write(f, 'password = "secret123"\n')
    result = analyzer.analyze(str(tmp_path))
    assert any("sub/app.py" in r["file"] or "app.py" in r["file"] for r in result["findings"])

def test_correct_line_number(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'x=1\npassword = "secret123"\n')
    result = analyzer.analyze(str(tmp_path))
    r = next(r for r in result["findings"] if r["rule_id"] == "SAST001")
    assert r["line"] == 2

def test_bounded_evidence(tmp_path):
    analyzer = SASTAnalyzer()
    f = tmp_path / "a.py"
    _write(f, 'password = "secret123"\n')
    result = analyzer.analyze(str(tmp_path))
    for r in result["findings"]:
        assert len(r["evidence"]) <= 500

def test_deterministic_ordering(tmp_path):
    analyzer = SASTAnalyzer()
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    _write(f1, 'password = "secret123"\n')
    _write(f2, 'eval(x)\n')
    r1 = analyzer.analyze(str(tmp_path))
    r2 = analyzer.analyze(str(tmp_path))
    assert r1["findings"] == r2["findings"]

def test_syntax_error_does_not_crash(tmp_path):
    analyzer = SASTAnalyzer()
    f1 = tmp_path / "bad.py"
    f2 = tmp_path / "good.py"
    _write(f1, 'def foo(\n')
    _write(f2, 'password = "secret123"\n')
    result = analyzer.analyze(str(tmp_path))
    assert any(e["file"].endswith("bad.py") for e in result["errors"])
    assert any(r["rule_id"] == "SAST001" for r in result["findings"])

def test_multiple_files(tmp_path):
    analyzer = SASTAnalyzer()
    _write(tmp_path / "a.py", 'password = "secret123"\n')
    _write(tmp_path / "b.py", 'eval(x)\n')
    result = analyzer.analyze(str(tmp_path))
    assert len(result["findings"]) == 2

def test_ignored_directories(tmp_path):
    analyzer = SASTAnalyzer()
    _write(tmp_path / ".git" / "a.py", 'password = "secret123"\n')
    _write(tmp_path / "venv" / "a.py", 'password = "secret123"\n')
    _write(tmp_path / "node_modules" / "a.py", 'password = "secret123"\n')
    _write(tmp_path / "good.py", 'password = "secret123"\n')
    result = analyzer.analyze(str(tmp_path))
    assert len(result["findings"]) == 1
    assert result["metadata"]["files_skipped"] >= 3

def test_max_file_size(tmp_path):
    analyzer = SASTAnalyzer()
    big = "x=1\n" * 300000  # ~1.2MB
    # Create file larger than 1MB
    p = tmp_path / "big.py"
    _write(p, "a" * (2 * 1024 * 1024))
    result = analyzer.analyze(str(tmp_path))
    assert result["metadata"]["files_skipped"] >= 1

def test_max_file_count(tmp_path):
    analyzer = SASTAnalyzer()
    for i in range(600):
        _write(tmp_path / f"f{i}.py", 'x=1\n')
    result = analyzer.analyze(str(tmp_path))
    assert result["metadata"]["files_scanned"] <= 500

def test_max_total_bytes(tmp_path):
    analyzer = SASTAnalyzer()
    for i in range(30):
        _write(tmp_path / f"f{i}.py", "x=1\n" * 200000)
    result = analyzer.analyze(str(tmp_path))
    # Should skip due to total bytes
    assert result["metadata"]["files_skipped"] >= 1
