import tempfile
from pathlib import Path
from app.services.sast.analyzer import SASTAnalyzer

def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def test_js001_eval(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'eval(userInput)\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS001" for f in r["findings"])

def test_js001_comment_ignored(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, '// eval(userInput)\n')
    r = a.analyze(str(tmp_path))
    assert not any(f["rule_id"] == "JS001" for f in r["findings"])

def test_js001_string_ignored(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'const message = "eval(userInput)";\n')
    r = a.analyze(str(tmp_path))
    assert not any(f["rule_id"] == "JS001" for f in r["findings"])

def test_js002_function_constructor(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'new Function(userInput)\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS002" for f in r["findings"])
    p2 = tmp_path / "b.js"
    _write(p2, 'Function(userInput)\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS002" for f in r["findings"])

def test_js003_password(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'const password = "secret123";\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS003" for f in r["findings"])

def test_js003_apikey(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'const apiKey = "abc12345";\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS003" for f in r["findings"])

def test_js003_token(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'let token = "abc12345";\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS003" for f in r["findings"])

def test_js003_ordinary_ignored(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'const username = "admin";\n')
    r = a.analyze(str(tmp_path))
    assert not any(f["rule_id"] == "JS003" for f in r["findings"])

def test_js004_exec(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'const cp = require("child_process");\nchild_process.exec(command)\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS004" for f in r["findings"])

def test_js004_execSync(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'child_process.execSync(command)\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS004" for f in r["findings"])

def test_js004_comment_ignored(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, '// child_process.exec(command)\n')
    r = a.analyze(str(tmp_path))
    assert not any(f["rule_id"] == "JS004" for f in r["findings"])

def test_js005_concat(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'let query = "SELECT * FROM users WHERE id=" + user_id;\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS005" for f in r["findings"])

def test_js005_template(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'let query = `SELECT * FROM users WHERE id=${user_id}`;\n')
    r = a.analyze(str(tmp_path))
    assert any(f["rule_id"] == "JS005" for f in r["findings"])

def test_safe_js(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'const x = 1;\nconsole.log(x);\n')
    r = a.analyze(str(tmp_path))
    assert len([f for f in r["findings"] if f["file"].endswith("a.js")]) == 0

def test_typescript_detection(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.ts"
    _write(p, 'eval(userInput)\n')
    r = a.analyze(str(tmp_path))
    f = next(f for f in r["findings"] if f["rule_id"] == "JS001")
    assert f["metadata"]["language"] == "typescript"

def test_jsx_detection(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.jsx"
    _write(p, 'eval(userInput)\n')
    r = a.analyze(str(tmp_path))
    assert any(f["metadata"]["language"] == "javascript" for f in r["findings"])

def test_tsx_detection(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.tsx"
    _write(p, 'eval(userInput)\n')
    r = a.analyze(str(tmp_path))
    assert any(f["metadata"]["language"] == "typescript" for f in r["findings"])

def test_correct_file_path_js(tmp_path):
    a = SASTAnalyzer()
    sub = tmp_path / "src"
    p = sub / "app.js"
    _write(p, 'eval(x)\n')
    r = a.analyze(str(tmp_path))
    assert any("src/app.js" in f["file"] for f in r["findings"])

def test_correct_line_js(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'const a=1;\neval(x)\n')
    r = a.analyze(str(tmp_path))
    f = next(f for f in r["findings"] if f["rule_id"] == "JS001")
    assert f["line"] == 2

def test_bounded_evidence_js(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'eval(x)\n')
    r = a.analyze(str(tmp_path))
    for f in r["findings"]:
        assert len(f["evidence"]) <= 500

def test_deterministic_js(tmp_path):
    a = SASTAnalyzer()
    p = tmp_path / "a.js"
    _write(p, 'eval(x)\n')
    r1 = a.analyze(str(tmp_path))
    r2 = a.analyze(str(tmp_path))
    assert r1["findings"] == r2["findings"]

def test_multiple_js_files(tmp_path):
    a = SASTAnalyzer()
    _write(tmp_path / "a.js", 'eval(x)\n')
    _write(tmp_path / "b.js", 'eval(y)\n')
    r = a.analyze(str(tmp_path))
    assert len([f for f in r["findings"] if f["rule_id"] == "JS001"]) == 2

def test_ignored_node_modules_js(tmp_path):
    a = SASTAnalyzer()
    _write(tmp_path / "node_modules" / "a.js", 'eval(x)\n')
    _write(tmp_path / "good.js", 'eval(x)\n')
    r = a.analyze(str(tmp_path))
    assert len([f for f in r["findings"] if "good.js" in f["file"]]) == 1
    assert not any("node_modules" in f["file"] for f in r["findings"])

def test_file_size_limit_js(tmp_path):
    a = SASTAnalyzer()
    big = tmp_path / "big.js"
    big.write_text("a" * (2 * 1024 * 1024), encoding="utf-8")
    r = a.analyze(str(tmp_path))
    assert r["metadata"]["files_skipped"] >= 1
