"""Generic SARIF parser — AppSec-ready, no new dependencies.

Converts SARIF 2.1.0 (JSON) into normalized {scanner, assets, findings}.
Usable by SAST/SCA/secrets/IaC scanners that emit SARIF without modifying
FindingEngine. Handles malformed output safely, preserves provenance.
"""

import json
from app.scanner.parsers.base import BaseParser

LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _level_to_severity(level: str | None, rule_level: str | None = None) -> str:
    key = str(level or rule_level or "").strip().lower()
    return LEVEL_TO_SEVERITY.get(key, "medium")


class SarifParser(BaseParser):
    scanner_name = "sarif"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {"scanner": "sarif", "assets": [], "findings": []}

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid SARIF JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("SARIF output must be a JSON object")

        # Quick validation: must have runs
        runs = data.get("runs")
        if not isinstance(runs, list) or not runs:
            # Allow empty SARIF (no findings)
            if "runs" in data and runs == []:
                return {"scanner": "sarif", "assets": [], "findings": []}
            raise ValueError("SARIF missing runs array")

        assets: list[dict] = []
        findings: list[dict] = []
        seen_assets: set[tuple[str, str]] = set()

        for run in runs:
            if not isinstance(run, dict):
                continue
            tool = run.get("tool", {}) if isinstance(run.get("tool"), dict) else {}
            driver = tool.get("driver", {}) if isinstance(tool.get("driver"), dict) else {}
            scanner_name = str(driver.get("name") or "sarif").strip().lower() or "sarif"
            rules = {}
            # Build rule map for severity lookup
            rules_list = driver.get("rules") if isinstance(driver.get("rules"), list) else []
            for rule in rules_list:
                if isinstance(rule, dict) and rule.get("id"):
                    rules[str(rule["id"])] = rule

            results = run.get("results") if isinstance(run.get("results"), list) else []
            for result in results:
                if not isinstance(result, dict):
                    continue
                rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "").strip() or None
                rule = rules.get(rule_id, {}) if rule_id else {}
                # Level: result level overrides rule default
                level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
                severity = _level_to_severity(level, rule.get("level") if isinstance(rule.get("level"), str) else None)

                message = ""
                msg_obj = result.get("message", {})
                if isinstance(msg_obj, dict):
                    message = str(msg_obj.get("text") or msg_obj.get("markdown") or "").strip()
                elif isinstance(msg_obj, str):
                    message = str(msg_obj).strip()
                if not message and rule_id:
                    message = str(rule.get("shortDescription", {}).get("text") or rule.get("fullDescription", {}).get("text") or rule_id).strip()

                title = rule_id or message[:120] or "SARIF finding"
                # Location
                file_path = None
                line = None
                # SARIF locations: result.locations[0].physicalLocation.artifactLocation.uri, region.startLine
                locations = result.get("locations") if isinstance(result.get("locations"), list) else []
                for loc in locations:
                    if not isinstance(loc, dict):
                        continue
                    phys = loc.get("physicalLocation") if isinstance(loc.get("physicalLocation"), dict) else None
                    if not phys:
                        continue
                    art = phys.get("artifactLocation") if isinstance(phys.get("artifactLocation"), dict) else None
                    if art and art.get("uri"):
                        file_path = str(art["uri"]).strip()
                        # Normalize: remove file:// prefix if present
                        if file_path.startswith("file://"):
                            file_path = file_path[7:]
                        break
                    # Also handle region
                if locations:
                    try:
                        first_loc = locations[0]
                        region = first_loc.get("physicalLocation", {}).get("region", {}) if isinstance(first_loc, dict) else {}
                        if isinstance(region, dict) and region.get("startLine") is not None:
                            line = int(region["startLine"])
                    except Exception:
                        line = None

                # CWE/CVE from properties or rule
                cwe = None
                cve = None
                props = result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
                # Check rule properties
                rule_props = rule.get("properties", {}) if isinstance(rule.get("properties"), dict) else {}
                for src in (props, rule_props):
                    for k in ("cwe", "CWE"):
                        if src.get(k):
                            cwe = str(src[k]).strip()
                            break
                    for k in ("cve", "CVE"):
                        if src.get(k):
                            cve = str(src[k]).strip()
                            break
                    if cww := src.get("cwe"):
                        cwe = str(cww).strip()
                    if cvv := src.get("cve"):
                        cve = str(cvv).strip()

                # Also check tags
                tags = rule.get("properties", {}).get("tags") if isinstance(rule.get("properties"), dict) else None
                if isinstance(tags, list):
                    for tag in tags:
                        tag_s = str(tag).strip()
                        if tag_s.upper().startswith("CWE-") and not cwe:
                            cwe = tag_s
                        if tag_s.upper().startswith("CVE-") and not cve:
                            cve = tag_s

                finding: dict = {
                    "scanner": scanner_name,
                    "title": title[:500],
                    "description": message[:2000] if message else title,
                    "severity": severity,
                    "score": None,
                    "status": "open",
                    "evidence": message[:500] if message else "",
                    "remediation": str(rule.get("help", {}).get("text") or "").strip()[:2000] if isinstance(rule.get("help"), dict) else "",
                    "cve": cve,
                    "cwe": cwe,
                    "metadata": {
                        "rule_id": rule_id,
                        "level": level,
                        "file": file_path,
                        "line": line,
                    },
                }
                # Add file/line to top-level for normalizer
                if file_path:
                    finding["file"] = file_path
                if line is not None:
                    finding["line"] = line
                if rule_id:
                    finding["rule_id"] = rule_id
                # Preserve fingerprint-relevant fields
                findings.append(finding)

                # Asset: source_file for each unique file
                if file_path:
                    key = ("source_file", file_path)
                    if key not in seen_assets:
                        seen_assets.add(key)
                        assets.append({"type": "source_file", "value": file_path, "metadata": {"source": "sarif"}})

        return {"scanner": "sarif", "assets": assets, "findings": findings}
