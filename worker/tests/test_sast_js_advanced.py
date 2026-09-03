import tempfile
from pathlib import Path
from app.services.sast.analyzer import SASTAnalyzer

def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

# SSRF
def test_js006_fetch_req_query(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'fetch(req.query.url)\n')
    assert any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_axios_get(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'axios.get(req.query.url)\n')
    assert any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_axios_post_body(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'axios(req.body.target)\n')
    assert any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_https_get(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'https.get(req.params.url)\n')
    assert any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_static_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'fetch("https://example.com")\n')
    assert not any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_env_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'fetch(process.env.API_URL)\n')
    assert not any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_comment_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'// fetch(req.query.url)\n')
    assert not any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_string_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const docs = "fetch(req.query.url)";\n')
    assert not any(f["rule_id"]=="JS006" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_correct_rule(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'fetch(req.query.url)\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JS006")
    assert f["severity"]=="high" and f["score"]==75

# XSS
def test_js007_innerhtml(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'element.innerHTML = req.query.name;\n')
    assert any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])

def test_js007_outerhtml(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'element.outerHTML = userInput;\n')
    assert any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])

def test_js007_insertadjacent(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'element.insertAdjacentHTML("beforeend", req.body.html);\n')
    assert any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])

def test_js007_dangerously(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'<div dangerouslySetInnerHTML={{ __html: userInput }} />\n')
    assert any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])

def test_js007_static_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'element.innerHTML = "<p>Hello</p>";\n')
    assert not any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])

def test_js007_textcontent_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'element.textContent = userInput;\n')
    assert not any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])
    p2=tmp_path/"b.js"
    _write(p2,'element.innerText = userInput;\n')
    # Need to re-analyze whole dir, but previous file still there, so check not JS007 for those
    r=a.analyze(str(tmp_path))
    # textContent/innerText should not trigger, but other files might, so ensure no JS007 for those lines
    # Actually we have two files now, but we can just check that textContent file not flagged
    # Simpler: create fresh tmp
    import tempfile
    from pathlib import Path as P
    with tempfile.TemporaryDirectory() as td:
        pp=P(td)/"c.js"
        pp.write_text('element.textContent = userInput;\n')
        assert not any(f["rule_id"]=="JS007" for f in a.analyze(td)["findings"])

def test_js007_comment_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'// element.innerHTML = userInput\n')
    assert not any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])

def test_js007_string_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const docs = "element.innerHTML = userInput";\n')
    assert not any(f["rule_id"]=="JS007" for f in a.analyze(str(tmp_path))["findings"])

# AWS
def test_js008_assignment(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";\n')
    assert any(f["rule_id"]=="JS008" for f in a.analyze(str(tmp_path))["findings"])

def test_js008_accesskeyid(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const config = { accessKeyId: "AKIA1234567890ABCDEF" };\n')
    assert any(f["rule_id"]=="JS008" for f in a.analyze(str(tmp_path))["findings"])

def test_js008_aws_access_key_id(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\n')
    assert any(f["rule_id"]=="JS008" for f in a.analyze(str(tmp_path))["findings"])

def test_js008_invalid_short_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const key = "AKIA123";\n')
    assert not any(f["rule_id"]=="JS008" for f in a.analyze(str(tmp_path))["findings"])

def test_js008_random_ignored(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const x = "hello world";\n')
    assert not any(f["rule_id"]=="JS008" for f in a.analyze(str(tmp_path))["findings"])

def test_js006_line_number(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const a=1;\nfetch(req.query.url)\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JS006")
    assert f["line"]==2
    assert f["severity"]=="high" and f["score"]==75

def test_js007_line_and_severity(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const a=1;\nelement.innerHTML = userInput;\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JS007")
    assert f["line"]==2
    assert f["severity"]=="high"

def test_js008_critical(tmp_path):
    a=SASTAnalyzer()
    p=tmp_path/"a.js"
    _write(p,'const AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";\n')
    f=next(f for f in a.analyze(str(tmp_path))["findings"] if f["rule_id"]=="JS008")
    assert f["severity"]=="critical" and f["score"]==90
    assert f["line"]==1
