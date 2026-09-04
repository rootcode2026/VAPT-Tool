import json
from app.scanner.parsers.base import BaseParser


class SASTParser(BaseParser):
    scanner_name = "sast"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {"scanner": "sast", "assets": [], "findings": []}
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid SAST output JSON: {e}") from e
        if not isinstance(data, dict):
            raise ValueError("SAST output must be a JSON object")

        # If SARIF (has runs), delegate to generic SarifParser for production SAST
        if "runs" in data:
            from app.scanner.parsers.sarif_parser import SarifParser

            sarif = SarifParser()
            result = sarif.parse(raw_output)
            # Preserve scanner identity as sast and inject production provenance
            result["scanner"] = "sast"
            for f in result.get("findings", []):
                if isinstance(f, dict):
                    f["scanner"] = "sast"
                    meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                    if not isinstance(meta, dict):
                        meta = {}
                    # Do not overwrite if already set (e.g., scanner already injected provenance)
                    if "execution_engine" not in meta:
                        meta["execution_engine"] = "semgrep"
                        meta["execution_mode"] = "docker"
                        meta["engine_version"] = "1.75.0"
                    f["metadata"] = meta
            # Preserve or inject result-level provenance
            meta = result.get("metadata")
            if not isinstance(meta, dict):
                meta = {}
                result["metadata"] = meta
            meta.setdefault("execution_engine", "semgrep")
            meta.setdefault("execution_mode", "docker")
            meta.setdefault("engine_version", "1.75.0")
            return result

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        # Ensure scanner field
        for f in findings:
            if isinstance(f, dict) and not f.get("scanner"):
                f["scanner"] = "sast"
            if isinstance(f, dict):
                f["scanner"] = "sast"
        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []
        # Handle legacy analyzer output that may have errors/metadata
        return {"scanner": "sast", "assets": assets, "findings": findings}
