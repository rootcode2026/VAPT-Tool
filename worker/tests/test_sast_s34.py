import tempfile
from pathlib import Path
from app.services.sast.analyzer import SASTAnalyzer

def _write(p, c):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(c, encoding="utf-8")

def test_py009_markup_args(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'from markupsafe import Markup\nMarkup(request.args.get("name"))\n')
    assert any(f["rule_id"]=="PY009" for f in a.analyze(str(tmp_path))["findings"])

def test_py009_markup_form(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'Markup(request.form.get("html"))\n')
    assert any(f["rule_id"]=="PY009" for f in a.analyze(str(tmp_path))["findings"])

def test_py009_static_no_finding(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'Markup("<html>hello</html>")\n')
    assert not any(f["rule_id"]=="PY009" for f in a.analyze(str(tmp_path))["findings"])

def test_py010_os_system(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'import os\nos.system(request.args.get("cmd"))\n')
    assert any(f["rule_id"]=="PY010" for f in a.analyze(str(tmp_path))["findings"])

def test_py010_subprocess_shell(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'import subprocess\nsubprocess.run(request.args.get("cmd"), shell=True)\n')
    assert any(f["rule_id"]=="PY010" for f in a.analyze(str(tmp_path))["findings"])

def test_py010_static_no_finding(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'import os\nos.system("whoami")\n')
    assert not any(f["rule_id"]=="PY010" for f in a.analyze(str(tmp_path))["findings"])

def test_py010_subprocess_no_shell_no_finding(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'import subprocess\nsubprocess.run(["ls", "-la"])\n')
    assert not any(f["rule_id"]=="PY010" for f in a.analyze(str(tmp_path))["findings"])

def test_js009_write_req_query(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p, 'document.write(req.query.name)\n')
    assert any(f["rule_id"]=="JS009" for f in a.analyze(str(tmp_path))["findings"])

def test_js009_writeln_location_search(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p, 'document.writeln(location.search)\n')
    assert any(f["rule_id"]=="JS009" for f in a.analyze(str(tmp_path))["findings"])

def test_js009_static_no_finding(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p, 'document.write("hello")\n')
    assert not any(f["rule_id"]=="JS009" for f in a.analyze(str(tmp_path))["findings"])

def test_java009_runtime(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p, 'Runtime.getRuntime().exec(request.getParameter("cmd"));\n')
    assert any(f["rule_id"]=="JAVA009" for f in a.analyze(str(tmp_path))["findings"])

def test_java009_processbuilder(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p, 'new ProcessBuilder(request.getParameter("cmd"));\n')
    assert any(f["rule_id"]=="JAVA009" for f in a.analyze(str(tmp_path))["findings"])

def test_java009_static_no_finding(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p, 'Runtime.getRuntime().exec("whoami");\n')
    assert not any(f["rule_id"]=="JAVA009" for f in a.analyze(str(tmp_path))["findings"])

def test_go009_exec_formvalue(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p, 'exec.Command("sh", r.FormValue("cmd"))\n')
    assert any(f["rule_id"]=="GO009" for f in a.analyze(str(tmp_path))["findings"])

def test_go009_curl_query(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p, 'exec.Command("curl", r.URL.Query().Get("url"))\n')
    assert any(f["rule_id"]=="GO009" for f in a.analyze(str(tmp_path))["findings"])

def test_go009_static_no_finding(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p, 'exec.Command("ls", "-la")\n')
    assert not any(f["rule_id"]=="GO009" for f in a.analyze(str(tmp_path))["findings"])

def test_severity_score_rule_id(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'Markup(request.args.get("x"))\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="PY009")
    assert f["severity"]=="high" and f["score"]==75
    p2=tmp_path/"Test.java"
    _write(p2, 'Runtime.getRuntime().exec(request.getParameter("cmd"));\n')
    f2=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JAVA009")
    assert f2["severity"]=="high"
    p3=tmp_path/"a.js"
    _write(p3, 'document.write(req.query.x)\n')
    f3=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JS009")
    assert f3["severity"]=="high"

def test_language_metadata(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'Markup(request.args.get("x"))\n')
    assert a.analyze(str(tmp_path))["findings"][0]["metadata"]["language"]=="python"
    p2=tmp_path/"a.js"
    _write(p2, 'document.write(req.query.x)\n')
    assert any(f["metadata"]["language"]=="javascript" for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JS009")

def test_evidence_bounded(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'Markup(request.args.get("x"))\n')
    for f in a.analyze(str(tmp_path))["findings"]:
        assert len(f["evidence"]) <= 500

def test_comments_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, '# Markup(request.args.get("x"))\n')
    assert not any(f["rule_id"]=="PY009" for f in a.analyze(str(tmp_path))["findings"])
    p2=tmp_path/"a.js"
    _write(p2, '// document.write(req.query.x)\n')
    assert not any(f["rule_id"]=="JS009" for f in a.analyze(str(tmp_path))["findings"])

def test_deterministic(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'Markup(request.args.get("x"))\n')
    assert a.analyze(str(tmp_path))["findings"] == a.analyze(str(tmp_path))["findings"]

def test_js006_still_works(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p, 'fetch(req.query.url)\n')
    assert any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_existing_aws_still_works(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p, 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"\n')
    assert any(f["rule_id"]=="PY008" for f in a.analyze(str(tmp_path))["findings"])
