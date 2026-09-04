"""S7.8 API Parser — OpenAPI/Swagger SARIF, api_endpoint assets.

Parses API scanner SARIF (vapt-api) into normalized findings. Preserves
endpoint, method, and API metadata without fabrication.
"""

import json

from app.scanner.parsers.base import BaseParser


class ApiParser(BaseParser):
    scanner_name = "api"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {"scanner": "api", "assets": [], "findings": [], "metadata": {"reason": "empty output"}}

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid api output JSON: {e}") from e
        if not isinstance(data, dict):
            raise ValueError("Api output must be a JSON object")

        if "runs" in data or "version" in data:
            if "runs" not in data or not isinstance(data.get("runs"), list):
                if "version" in data and "runs" not in data:
                    raise ValueError("SARIF output missing runs array")
            return self._parse_sarif(data, raw_output)

        return self._parse_legacy(data)

    def _parse_sarif(self, data: dict, raw_output: str) -> dict:
        from app.scanner.parsers.sarif_parser import SarifParser

        sarif = SarifParser()
        try:
            result = sarif.parse(raw_output)
        except Exception:
            result = sarif.parse(json.dumps(data))

        result["scanner"] = "api"

        # Enrich findings for API specifics
        runs = data.get("runs", [])
        raw_results = []
        for run in runs:
            if isinstance(run, dict) and isinstance(run.get("results"), list):
                raw_results.extend(run["results"])

        for idx, f in enumerate(result.get("findings", [])):
            if not isinstance(f, dict):
                continue
            f["scanner"] = "api"
            if not f.get("evidence_type"):
                # API findings are api_endpoint if they have endpoint/method
                meta = f.get("metadata", {}) if isinstance(f.get("metadata"), dict) else {}
                if meta.get("file") and ("openapi" in str(meta.get("file")).lower() or "swagger" in str(meta.get("file")).lower()):
                    f["evidence_type"] = "api_endpoint"
                else:
                    f["evidence_type"] = "api_endpoint"
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            if not isinstance(meta, dict):
                meta = {}
            # Preserve endpoint/method if in raw
            if idx < len(raw_results):
                raw_res = raw_results[idx]
                if isinstance(raw_res, dict):
                    props = raw_res.get("properties", {}) if isinstance(raw_res.get("properties"), dict) else {}
                    for key in ("endpoint", "method", "parameter", "path", "http_method"):
                        if key in props and props[key] not in (None, ""):
                            if key not in meta:
                                meta[key] = str(props[key])[:500]
            if "execution_engine" not in meta:
                meta["execution_engine"] = "vapt-api"
                meta["execution_mode"] = "docker"
            # Ensure endpoint/method top-level for normalizer if possible
            if meta.get("endpoint") and not f.get("endpoint"):
                f["endpoint"] = meta["endpoint"]
            if meta.get("method") and not f.get("method"):
                f["method"] = meta["method"]
            # Also try to extract endpoint from title/message
            if not f.get("endpoint") and f.get("title"):
                title = f.get("title", "")
                # Title often contains "GET /users" etc.
                if "/" in title:
                    f["endpoint"] = title.split()[-1] if "/" in title else title
            f["metadata"] = meta

        # Assets: SarifParser creates source_file for file_path; for API we want api_endpoint
        assets = result.get("assets", [])
        seen = set((a.get("type"), a.get("value")) for a in assets if isinstance(a, dict))
        for a in list(assets):
            if isinstance(a, dict) and a.get("type") == "source_file":
                val = a.get("value")
                if isinstance(val, str) and ("openapi" in val.lower() or "swagger" in val.lower() or val.endswith(".json") or val.endswith(".yaml")):
                    key = ("api_endpoint", val)
                    if key not in seen:
                        seen.add(key)
                        assets.append({"type": "api_endpoint", "value": val, "metadata": {"source": "vapt-api"}})

        for a in assets:
            if isinstance(a.get("metadata"), dict):
                a["metadata"]["asset_type"] = a.get("type", "api_endpoint")
            else:
                a["metadata"] = {"asset_type": a.get("type", "api_endpoint")}

        result["assets"] = assets
        result.setdefault("metadata", {})["scanner"] = "api"
        return result

    def _parse_legacy(self, data: dict) -> dict:
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        for f in findings:
            if isinstance(f, dict):
                f["scanner"] = "api"
                if not f.get("evidence_type"):
                    f["evidence_type"] = "api_endpoint"
                meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                if not isinstance(meta, dict):
                    meta = {}
                if "execution_engine" not in meta:
                    meta["execution_engine"] = "vapt-api"
                f["metadata"] = meta
        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []
        return {
            "scanner": "api",
            "assets": assets,
            "findings": findings,
            "metadata": data.get("metadata", {}),
        }
