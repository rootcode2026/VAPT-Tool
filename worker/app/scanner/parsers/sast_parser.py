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
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        # Ensure scanner field
        for f in findings:
            if isinstance(f, dict) and not f.get("scanner"):
                f["scanner"] = "sast"
        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []
        return {"scanner": "sast", "assets": assets, "findings": findings}
