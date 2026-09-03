import tempfile
from pathlib import Path
from app.services.sast.analyzer import SASTAnalyzer

def _write(p, c):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(c, encoding="utf-8")

# PY006
def test_py006_requests_get(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'import requests\nrequests.get(request.args.get("url"))\n')
    assert any(f["rule_id"]=="PY006" for f in a.analyze(str(tmp_path))["findings"])

def test_py006_post(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'requests.post(request.form.get("target"))\n')
    assert any(f["rule_id"]=="PY006" for f in a.analyze(str(tmp_path))["findings"])

def test_py006_urllib(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'import urllib.request\nurllib.request.urlopen(request.args.get("url"))\n')
    assert any(f["rule_id"]=="PY006" for f in a.analyze(str(tmp_path))["findings"])

def test_py006_static_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'requests.get("https://example.com")\n')
    assert not any(f["rule_id"]=="PY006" for f in a.analyze(str(tmp_path))["findings"])

def test_py007_render_template_string(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'render_template_string(user_input)\n')
    assert any(f["rule_id"]=="PY007" for f in a.analyze(str(tmp_path))["findings"])

def test_py007_safe_render_template_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'render_template("index.html")\n')
    assert not any(f["rule_id"]=="PY007" for f in a.analyze(str(tmp_path))["findings"])

def test_py008_akia(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="PY008")
    assert f["severity"]=="critical" and f["score"]==90

def test_py008_invalid_short_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"app.py"
    _write(p,'x = "AKIA123"\n')
    assert not any(f["rule_id"]=="PY008" for f in a.analyze(str(tmp_path))["findings"])

# JAVA006
def test_java006_ssrf(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'URL url = new URL(request.getParameter("url"));\n')
    assert any(f["rule_id"]=="JAVA006" for f in a.analyze(str(tmp_path))["findings"])

def test_java006_static_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'URL url = new URL("https://example.com");\n')
    assert not any(f["rule_id"]=="JAVA006" for f in a.analyze(str(tmp_path))["findings"])

def test_java007_xss(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'response.getWriter().write(request.getParameter("name"));\n')
    assert any(f["rule_id"]=="JAVA007" for f in a.analyze(str(tmp_path))["findings"])

def test_java007_safe_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'response.getWriter().write("hello");\n')
    assert not any(f["rule_id"]=="JAVA007" for f in a.analyze(str(tmp_path))["findings"])

def test_java008_akia(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"Test.java"
    _write(p,'String AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JAVA008")
    assert f["severity"]=="critical"

# GO006
def test_go006_http_get(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'http.Get(r.URL.Query().Get("url"))\n')
    assert any(f["rule_id"]=="GO006" for f in a.analyze(str(tmp_path))["findings"])

def test_go006_newrequest(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'http.NewRequest("GET", r.FormValue("target"), nil)\n')
    assert any(f["rule_id"]=="GO006" for f in a.analyze(str(tmp_path))["findings"])

def test_go006_static_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'http.Get("https://example.com")\n')
    assert not any(f["rule_id"]=="GO006" for f in a.analyze(str(tmp_path))["findings"])

# GO007
def test_go007_template_html(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'template.HTML(userInput)\n')
    assert any(f["rule_id"]=="GO007" for f in a.analyze(str(tmp_path))["findings"])

def test_go007_safe_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'html.EscapeString(userInput)\n')
    assert not any(f["rule_id"]=="GO007" for f in a.analyze(str(tmp_path))["findings"])

# GO008
def test_go008_akia(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'awsKey := "AKIA1234567890ABCDEF"\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="GO008")
    assert f["severity"]=="critical"

def test_go008_invalid_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"main.go"
    _write(p,'x := "AKIA123"\n')
    assert not any(f["rule_id"]=="GO008" for f in a.analyze(str(tmp_path))["findings"])

# JS already exists - ensure still passes
def test_js006_still_works(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'fetch(req.query.url)\n')
    assert any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])
