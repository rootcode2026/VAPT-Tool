#!/usr/bin/env python3
"""API spec security scanner — static OpenAPI/Swagger analysis, SARIF output.

Checks:
- API001: Server URL uses HTTP (should be HTTPS)
- API002: Operation missing security (no auth)
- API003: Path missing responses
- API004: OpenAPI version missing
- API005: Info missing title/version
- API006: Operation missing operationId
- API007: Parameter without schema
- API008: Response without description
"""

import json
import sys
import pathlib
import yaml

def load_spec(path: pathlib.Path):
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(text), None
        else:
            return json.loads(text), None
    except Exception as e:
        return None, str(e)

def check_spec(spec, file_path):
    findings = []
    if not isinstance(spec, dict):
        findings.append(("API004", "error", f"Invalid spec structure in {file_path}", file_path, 1, "OpenAPI version missing or invalid"))
        return findings
    # API004: version
    if "openapi" not in spec and "swagger" not in spec:
        findings.append(("API004", "error", "Missing openapi/swagger version", file_path, 1, "Add openapi: 3.0.x"))
    # API005: info
    info = spec.get("info", {})
    if not isinstance(info, dict) or not info.get("title") or not info.get("version"):
        findings.append(("API005", "warning", "Info missing title/version", file_path, 1, "Add info.title and version"))
    # API001: servers http
    servers = spec.get("servers", [])
    if isinstance(servers, list):
        for srv in servers:
            url = srv.get("url", "") if isinstance(srv, dict) else ""
            if isinstance(url, str) and url.startswith("http://"):
                findings.append(("API001", "error", f"Server URL uses HTTP (should be HTTPS): {url}", file_path, 1, "Use https://"))
    # Paths
    paths = spec.get("paths", {})
    if not isinstance(paths, dict) or not paths:
        findings.append(("API003", "warning", "No paths defined", file_path, 1, "Define at least one path"))
    else:
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.startswith("x-"):
                    continue
                if not isinstance(op, dict):
                    continue
                # API002: missing security
                if "security" not in op:
                    # Check global security
                    if "security" not in spec:
                        findings.append(("API002", "warning", f"Operation {method.upper()} {path} missing security (no auth)", file_path, 1, "Add security scheme"))
                # API003: responses
                if "responses" not in op or not op["responses"]:
                    findings.append(("API003", "error", f"Operation {method.upper()} {path} missing responses", file_path, 1, "Add responses"))
                # API006: operationId
                if "operationId" not in op:
                    findings.append(("API006", "note", f"Operation {method.upper()} {path} missing operationId", file_path, 1, "Add operationId"))
                # API007: params
                for param in op.get("parameters", []):
                    if isinstance(param, dict) and "schema" not in param and "content" not in param:
                        findings.append(("API007", "warning", f"Parameter {param.get('name','')} in {method.upper()} {path} missing schema", file_path, 1, "Add schema"))
                # API008: responses without description
                for code, resp in (op.get("responses") or {}).items():
                    if isinstance(resp, dict) and not resp.get("description"):
                        findings.append(("API008", "note", f"Response {code} in {method.upper()} {path} missing description", file_path, 1, "Add description"))
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", help="Workspace directory to scan")
    parser.add_argument("--output", required=True, help="SARIF output file")
    args = parser.parse_args()
    ws = pathlib.Path(args.workspace)
    # Find spec files
    spec_files = []
    patterns = ["openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml", "api.json", "api.yaml", "api.yml"]
    for p in ws.rglob("*"):
        if p.is_file():
            if p.name in patterns or p.suffix.lower() in (".json", ".yaml", ".yml") and "openapi" in p.name.lower() or "swagger" in p.name.lower():
                # Also check content: if file contains openapi/swagger
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                    if "openapi" in text.lower() or "swagger" in text.lower():
                        spec_files.append(p)
                except:
                    pass
            # Also check any .json/.yaml that looks like spec
            if p.suffix.lower() in (".json", ".yaml", ".yml"):
                if p not in spec_files:
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")[:2000]
                        if '"openapi"' in text or '"swagger"' in text or "openapi:" in text:
                            spec_files.append(p)
                    except:
                        pass
    # Deduplicate
    spec_files = list(dict.fromkeys(spec_files))
    # Also check for generic API spec files in workspace root
    for pat in patterns:
        for f in ws.glob(pat):
            if f not in spec_files:
                spec_files.append(f)
        for f in ws.rglob(pat):
            if f not in spec_files:
                spec_files.append(f)

    all_results = []
    for spec_path in spec_files:
        # Ensure path is inside workspace
        try:
            spec_path.resolve().relative_to(ws.resolve())
        except ValueError:
            continue
        spec, err = load_spec(spec_path)
        rel_path = str(spec_path.relative_to(ws))
        if err:
            all_results.append({
                "ruleId": "API999",
                "level": "error",
                "message": {"text": f"Failed to parse {rel_path}: {err}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": rel_path}, "region": {"startLine": 1}}}]
            })
            continue
        findings = check_spec(spec, rel_path)
        for rule_id, level, msg, file_uri, line, remediation in findings:
            all_results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": msg},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": file_uri}, "region": {"startLine": line}}}],
                "properties": {"remediation": remediation}
            })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vapt-api",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/vapt/api",
                    "rules": [
                        {"id": "API001", "shortDescription": {"text": "Server URL uses HTTP"}, "fullDescription": {"text": "Server URL should use HTTPS"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "API002", "shortDescription": {"text": "Operation missing security"}, "fullDescription": {"text": "Operation should have security defined"}, "defaultConfiguration": {"level": "warning"}},
                        {"id": "API003", "shortDescription": {"text": "Path missing responses"}, "fullDescription": {"text": "Operation should have responses"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "API004", "shortDescription": {"text": "OpenAPI version missing"}, "fullDescription": {"text": "Spec should have openapi/swagger version"}, "defaultConfiguration": {"level": "error"}},
                        {"id": "API005", "shortDescription": {"text": "Info missing"}, "fullDescription": {"text": "Info should have title/version"}, "defaultConfiguration": {"level": "warning"}},
                        {"id": "API006", "shortDescription": {"text": "Operation missing operationId"}, "fullDescription": {"text": "Add operationId"}, "defaultConfiguration": {"level": "note"}},
                        {"id": "API007", "shortDescription": {"text": "Parameter missing schema"}, "fullDescription": {"text": "Parameter should have schema"}, "defaultConfiguration": {"level": "warning"}},
                        {"id": "API008", "shortDescription": {"text": "Response missing description"}, "fullDescription": {"text": "Add description"}, "defaultConfiguration": {"level": "note"}},
                        {"id": "API999", "shortDescription": {"text": "Parse error"}, "fullDescription": {"text": "Failed to parse spec"}, "defaultConfiguration": {"level": "error"}},
                    ]
                }
            },
            "results": all_results
        }]
    }
    pathlib.Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.output).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    # Also print summary to stderr for debugging
    print(f"API scan: {len(spec_files)} spec(s), {len(all_results)} findings", file=sys.stderr)

if __name__ == "__main__":
    main()
