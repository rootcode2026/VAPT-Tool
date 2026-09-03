import json
from app.scanner.parsers.sast_parser import SASTParser

def test_parser_registry_contains_sast():
    from app.scanner.parsers.registry import ParserRegistry
    assert "sast" in ParserRegistry().list()

def test_parser_converts_json():
    p = SASTParser()
    raw = json.dumps({"scanner":"sast","findings":[{"rule_id":"SAST001","title":"t","severity":"high","file":"a.py","line":1}],"assets":[]})
    res = p.parse(raw)
    assert res["scanner"] == "sast"
    assert len(res["findings"]) == 1

def test_finding_fields_preserved():
    p = SASTParser()
    raw = json.dumps({"scanner":"sast","findings":[{"rule_id":"SAST001","title":"Hardcoded secret","severity":"high","file":"a.py","line":2,"column":0,"evidence":"x","metadata":{"file":"a.py"}}]})
    res = p.parse(raw)
    f = res["findings"][0]
    assert f["title"] == "Hardcoded secret"
    assert f["metadata"]["file"] == "a.py"

def test_scanner_name_is_sast():
    p = SASTParser()
    assert p.scanner_name == "sast"

def test_assets_remains_empty():
    p = SASTParser()
    res = p.parse(json.dumps({"scanner":"sast","findings":[],"assets":[]}))
    assert res["assets"] == []
