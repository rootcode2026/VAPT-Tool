import tempfile
from pathlib import Path
from app.services.sast.analyzer import SASTAnalyzer

def _write(p, c):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(c, encoding="utf-8")

def test_java_runtime_exec(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'public class Test { void f(){ Runtime.getRuntime().exec("ls"); } }')
    assert any(f["rule_id"]=="JAVA001" for f in a.analyze(str(tmp_path))["findings"])

def test_java_processbuilder(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'ProcessBuilder pb = new ProcessBuilder("ls");')
    assert any(f["rule_id"]=="JAVA001" for f in a.analyze(str(tmp_path))["findings"])

def test_java_deserialization(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'ObjectInputStream ois = new ObjectInputStream(in);\n ois.readObject();')
    assert any(f["rule_id"]=="JAVA002" for f in a.analyze(str(tmp_path))["findings"])

def test_java_sql_concat(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'String query = "SELECT * FROM users WHERE id=" + userId;')
    assert any(f["rule_id"]=="JAVA003" for f in a.analyze(str(tmp_path))["findings"])

def test_java_hardcoded_secret(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'String password = "secret123";')
    assert any(f["rule_id"]=="JAVA004" for f in a.analyze(str(tmp_path))["findings"])

def test_java_weak_crypto(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'MessageDigest md = MessageDigest.getInstance("MD5");')
    assert any(f["rule_id"]=="JAVA005" for f in a.analyze(str(tmp_path))["findings"])

def test_java_comments_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'// Runtime.getRuntime().exec("ls");\n/* ObjectInputStream */')
    assert not any(f["rule_id"] in ("JAVA001","JAVA002") for f in a.analyze(str(tmp_path))["findings"])

def test_java_strings_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'String s = "Runtime.getRuntime().exec(\\"ls\\")";')
    assert not any(f["rule_id"]=="JAVA001" for f in a.analyze(str(tmp_path))["findings"])

def test_java_safe(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'public class Test { int x=1; }')
    assert len(a.analyze(str(tmp_path))["findings"])==0

def test_java_language_metadata(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'Runtime.getRuntime().exec("ls");')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JAVA001")
    assert f["metadata"]["language"]=="java"

def test_java_file_path(tmp_path):
    a=SASTAnalyzer()
    sub=tmp_path/"src"
    p=sub/"Test.java"
    _write(p,'Runtime.getRuntime().exec("ls");')
    assert any("src/Test.java" in f["file"] for f in a.analyze(str(tmp_path))["findings"])

def test_java_line(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'public class Test {\n void f(){\nRuntime.getRuntime().exec("ls");\n}\n}')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JAVA001")
    assert f["line"]==3

def test_java_bounded_evidence(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'Runtime.getRuntime().exec("ls");')
    for f in a.analyze(str(tmp_path))["findings"]:
        assert len(f["evidence"])<=500

def test_java_deterministic(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'Runtime.getRuntime().exec("ls");')
    assert a.analyze(str(tmp_path))["findings"]==a.analyze(str(tmp_path))["findings"]
