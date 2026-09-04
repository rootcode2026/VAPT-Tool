import json
from app.scanner.parsers.base import BaseParser


class SCAParser(BaseParser):
    scanner_name = "sca"

    def parse(self, raw_output: str) -> dict:
        """
        Parse SCA scanner raw output. Supports both legacy analyzer JSON
        and SARIF 2.1.0 from OSV-Scanner (via Docker).
        """
        if not raw_output or not raw_output.strip():
            return {"scanner": "sca", "assets": [], "findings": []}

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid SCA output JSON: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("SCA output must be a JSON object")

        # If SARIF (has runs), delegate to generic SarifParser
        if "runs" in data:
            from app.scanner.parsers.sarif_parser import SarifParser

            sarif = SarifParser()
            result = sarif.parse(raw_output)
            result["scanner"] = "sca"
            for f in result.get("findings", []):
                if isinstance(f, dict):
                    f["scanner"] = "sca"
                    meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                    if not isinstance(meta, dict):
                        meta = {}
                    if "execution_engine" not in meta:
                        meta["execution_engine"] = "osv-scanner"
                        meta["execution_mode"] = "docker"
                        meta["engine_version"] = "1.9.2"
                    # Preserve package/version if present in original SARIF message
                    # SarifParser already extracts file/line; SCA package is in message/rule
                    f["metadata"] = meta
            if result.get("findings"):
                # Ensure assets include package assets if not already
                pass
            result.setdefault("metadata", {})["execution_engine"] = result["metadata"].get("execution_engine", "osv-scanner")
            result["metadata"].setdefault("execution_mode", "docker")
            result["metadata"].setdefault("engine_version", "1.9.2")
            return result

        # Legacy analyzer JSON with dependencies/vulnerabilities/findings
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        for f in findings:
            if isinstance(f, dict):
                if not f.get("scanner"):
                    f["scanner"] = "sca"
                f["scanner"] = "sca"
                # Ensure provenance for legacy path
                meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                if not isinstance(meta, dict):
                    meta = {}
                meta.setdefault("execution_engine", "sca_analyzer")
                meta.setdefault("execution_mode", "legacy")
                f["metadata"] = meta

        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []

        # Preserve metadata execution_engine if present
        meta = data.get("metadata", {})
        if isinstance(meta, dict):
            meta.setdefault("execution_engine", "sca_analyzer")
            meta.setdefault("execution_mode", "legacy")
            data["metadata"] = meta

        return {
            "scanner": "sca",
            "assets": assets,
            "findings": findings,
            "metadata": data.get("metadata", {}),
        }
