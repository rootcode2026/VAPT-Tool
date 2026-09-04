"""S7.7 IaC Parser — Checkov SARIF, iac_resource assets.

Parses Checkov SARIF 2.1.0 into normalized findings. Preserves check ID,
file, line, resource, framework, severity, and vulnerability metadata
without fabrication. Ensures iac_resource asset and evidence handling
via existing SarifParser and project isolation layer.
"""

import json

from app.scanner.parsers.base import BaseParser


class IacParser(BaseParser):
    scanner_name = "iac"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {"scanner": "iac", "assets": [], "findings": [], "metadata": {"reason": "empty output"}}

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid iac output JSON: {e}") from e
        if not isinstance(data, dict):
            raise ValueError("Iac output must be a JSON object")

        # Checkov JSON format (preferred for this scanner — avoids SARIF file ro issue)
        if "results" in data and isinstance(data.get("results"), dict):
            # Checkov JSON has results.failed_checks
            if "failed_checks" in data["results"] or "passed_checks" in data["results"]:
                return self._parse_checkov_json(data)
        if "runs" in data or "version" in data:
            if "runs" not in data or not isinstance(data.get("runs"), list):
                if "version" in data and "runs" not in data:
                    raise ValueError("SARIF output missing runs array")
            return self._parse_sarif(data, raw_output)

        return self._parse_legacy(data)

    def _parse_checkov_json(self, data: dict) -> dict:
        """Parse Checkov JSON output (results.failed_checks) into normalized findings."""
        results = data.get("results", {}) if isinstance(data.get("results"), dict) else {}
        failed = results.get("failed_checks", []) if isinstance(results.get("failed_checks"), list) else []
        findings: list[dict] = []
        assets: list[dict] = []
        seen_assets: set[tuple[str, str]] = set()
        for check in failed:
            if not isinstance(check, dict):
                continue
            check_id = str(check.get("check_id") or check.get("id") or "").strip() or "unknown"
            file_path = str(check.get("file_path") or "").strip()
            # Normalize file path: remove /workspace prefix if present
            if file_path.startswith("/workspace"):
                file_path = file_path[len("/workspace"):].lstrip("/")
                if not file_path:
                    file_path = "unknown"
            elif file_path.startswith("workspace"):
                file_path = file_path.lstrip("/")
            line = None
            file_line = check.get("file_line_range")
            if isinstance(file_line, list) and len(file_line) >= 1 and isinstance(file_line[0], int):
                line = int(file_line[0])
            # Severity mapping — Checkov JSON often has severity null; default to medium
            severity = str(check.get("severity") or "medium").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"
            # Title and description
            check_name = str(check.get("check_name") or check_id).strip()
            resource = str(check.get("resource") or "").strip()
            title = f"{check_id}: {check_name}"[:500]
            description = str(check.get("guideline") or check_name)[:2000]
            if not description:
                description = check_name
            finding: dict = {
                "scanner": "iac",
                "title": title,
                "description": description,
                "severity": severity,
                "score": None,
                "status": "open",
                "evidence": f"{check_id} on {file_path}:{line or 1} resource {resource}"[:500] if file_path else check_id,
                "remediation": str(check.get("guideline") or "")[:2000],
                "cve": None,
                "cwe": None,
                "metadata": {
                    "rule_id": check_id,
                    "check_id": check_id,
                    "file": file_path,
                    "line": line,
                    "resource": resource,
                    "framework": str(check.get("check_type") or check.get("framework") or "terraform").lower(),
                    "severity": severity,
                    "guideline": str(check.get("guideline") or "")[:500],
                    "execution_engine": "checkov",
                    "execution_mode": "docker",
                },
                "evidence_type": "iac_resource",
            }
            if file_path:
                finding["file"] = file_path
            if line is not None:
                finding["line"] = line
            if check_id:
                finding["rule_id"] = check_id
            findings.append(finding)
            # Asset for file
            if file_path and file_path != "unknown":
                key = ("iac_resource", file_path)
                if key not in seen_assets:
                    seen_assets.add(key)
                    assets.append({"type": "iac_resource", "value": file_path, "metadata": {"source": "checkov"}})
                # Also source_file for compatibility
                key2 = ("source_file", file_path)
                if key2 not in seen_assets:
                    seen_assets.add(key2)
                    assets.append({"type": "source_file", "value": file_path, "metadata": {"source": "checkov"}})

        # Handle case where failed_checks is empty (clean scan)
        return {"scanner": "iac", "assets": assets, "findings": findings, "metadata": {"checkov_version": str(data.get("summary", {}).get("checkov_version") or "") if isinstance(data.get("summary"), dict) else ""}}

    def _parse_sarif(self, data: dict, raw_output: str) -> dict:
        from app.scanner.parsers.sarif_parser import SarifParser

        sarif = SarifParser()
        try:
            result = sarif.parse(raw_output)
        except Exception:
            result = sarif.parse(json.dumps(data))

        result["scanner"] = "iac"

        # Post-process findings for IaC specifics
        runs = data.get("runs", [])
        raw_results = []
        for run in runs:
            if isinstance(run, dict) and isinstance(run.get("results"), list):
                raw_results.extend(run["results"])

        for idx, f in enumerate(result.get("findings", [])):
            if not isinstance(f, dict):
                continue
            f["scanner"] = "iac"
            if not f.get("evidence_type"):
                f["evidence_type"] = "iac_resource"
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            if not isinstance(meta, dict):
                meta = {}
            # Enrich with checkov-specific fields where present
            if idx < len(raw_results):
                raw_res = raw_results[idx]
                if isinstance(raw_res, dict):
                    props = raw_res.get("properties", {}) if isinstance(raw_res.get("properties"), dict) else {}
                    for key in ("resource", "checkId", "check_id", "framework", "severity", "guideline", "checkClass"):
                        if key in props and props[key] not in (None, ""):
                            norm_key = {
                                "checkId": "check_id",
                                "check_id": "check_id",
                                "checkClass": "check_class",
                            }.get(key, key.lower())
                            if norm_key not in meta:
                                meta[norm_key] = str(props[key])[:500]
                    # Also pull tool properties
                    tool_props = {}
                    for run in runs:
                        tool = run.get("tool", {}) if isinstance(run.get("tool"), dict) else {}
                        driver = tool.get("driver", {}) if isinstance(tool.get("driver"), dict) else {}
                        tool_props = driver.get("properties", {}) if isinstance(driver.get("properties"), dict) else {}
                    for k in ("framework",):
                        if k in tool_props and tool_props[k] not in (None, ""):
                            if k not in meta:
                                meta[k] = str(tool_props[k])[:500]

            if "execution_engine" not in meta:
                meta["execution_engine"] = "checkov"
                meta["execution_mode"] = "docker"
            # Ensure check_id alias for correlation
            if meta.get("check_id") and not meta.get("rule_id"):
                meta["rule_id"] = meta["check_id"]
            if f.get("rule_id") and not meta.get("check_id"):
                meta["check_id"] = f.get("rule_id")
            f["metadata"] = meta

        # Assets: SarifParser creates source_file for file_path; for IaC we want iac_resource
        # Convert source_file assets for IaC files to iac_resource where appropriate,
        # but keep both for compatibility — add iac_resource alias
        assets = result.get("assets", [])
        seen = set((a.get("type"), a.get("value")) for a in assets if isinstance(a, dict))
        for a in list(assets):
            if isinstance(a, dict) and a.get("type") == "source_file":
                val = a.get("value")
                # Heuristic: IaC files are .tf, .yaml/.yml, Dockerfile, .json (CFN)
                if isinstance(val, str) and (val.endswith(".tf") or val.endswith(".yaml") or val.endswith(".yml") or val.endswith(".json") or "Dockerfile" in val or val.endswith("/Dockerfile")):
                    key = ("iac_resource", val)
                    if key not in seen:
                        seen.add(key)
                        assets.append({"type": "iac_resource", "value": val, "metadata": {"source": "checkov", "execution_engine": "checkov"}})

        for a in assets:
            if isinstance(a.get("metadata"), dict):
                a["metadata"]["asset_type"] = a.get("type", "iac_resource")
            else:
                a["metadata"] = {"asset_type": a.get("type", "iac_resource")}

        result["assets"] = assets
        result.setdefault("metadata", {})["scanner"] = "iac"
        return result

    def _parse_legacy(self, data: dict) -> dict:
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        for f in findings:
            if isinstance(f, dict):
                f["scanner"] = "iac"
                if not f.get("evidence_type"):
                    f["evidence_type"] = "iac_resource"
                meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                if not isinstance(meta, dict):
                    meta = {}
                if "execution_engine" not in meta:
                    meta["execution_engine"] = "checkov"
                f["metadata"] = meta
        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []
        return {
            "scanner": "iac",
            "assets": assets,
            "findings": findings,
            "metadata": data.get("metadata", {}),
        }
