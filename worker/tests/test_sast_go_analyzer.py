import tempfile
from pathlib import Path
from app.services.sast.analyzer import SASTAnalyzer

def _write(p,c):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(c, encoding="utf-8")

def test_go_exec_command(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'package main\nimport "os/exec"\nfunc f(){ exec.Command("ls") }\n')
    assert any(f["rule_id"]=="GO001" for f in a.analyze(str(tmp_path))["findings"])

def test_go_os_exec(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'package main\nimport "os/exec"\nfunc f(){ exec.Command(userInput) }\n')
    assert any(f["rule_id"]=="GO001" for f in a.analyze(str(tmp_path))["findings"])

def test_go_sql_concat(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'query := "SELECT * FROM users WHERE id=" + userId\n')
    assert any(f["rule_id"]=="GO002" for f in a.analyze(str(tmp_path))["findings"])

def test_go_hardcoded_secret(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'password := "secret123"\n')
    assert any(f["rule_id"]=="GO003" for f in a.analyze(str(tmp_path))["findings"])

def test_go_weak_crypto(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'import "crypto/md5"\nfunc f(){ md5.New() }\n')
    assert any(f["rule_id"]=="GO004" for f in a.analyze(str(tmp_path))["findings"])

def test_go_insecure_skip_verify(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'cfg := &tls.Config{InsecureSkipVerify: true}\n')
    assert any(f["rule_id"]=="GO005" for f in a.analyze(str(tmp_path))["findings"])

def test_go_comments_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'// exec.Command("ls")\n/* InsecureSkipVerify: true */')
    assert not any(f["rule_id"] in ("GO001","GO005") for f in a.analyze(str(tmp_path))["findings"])

def test_go_strings_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'var s = "exec.Command(\\"ls\\")"\n')
    assert not any(f["rule_id"]=="GO001" for f in a.analyze(str(tmp_path))["findings"])

def test_go_safe(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'package main\nfunc main(){ println("hi") }\n')
    assert len(a.analyze(str(tmp_path))["findings"])==0

def test_go_language_metadata(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'exec.Command("ls")\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="GO001")
    assert f["metadata"]["language"]=="go"

def test_go_file_path(tmp_path):
    a=SASTAnalyzer()
    sub=tmp_path/"src"
    p=sub/"main.go"
    _write(p,'exec.Command("ls")\n')
    assert any("src/main.go" in f["file"] for f in a.analyze(str(tmp_path))["findings"])

def test_go_line(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'package main\nfunc f(){\nexec.Command("ls")\n}\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="GO001")
    assert f["line"]==3

def test_go_bounded_evidence(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'exec.Command("ls")\n')
    for f in a.analyze(str(tmp_path))["findings"]:
        assert len(f["evidence"])<=500

def test_go_deterministic(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'exec.Command("ls")\n')
    assert a.analyze(str(tmp_path))["findings"]==a.analyze(str(tmp_path))["findings"]
