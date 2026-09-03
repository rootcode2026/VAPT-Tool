import json
from app.scanner.parsers.base import BaseParser


class SCAParser(BaseParser):
    scanner_name = "sca"

    def parse(self, raw_output: str) -> dict:
        """
        Parse SCA scanner raw output (JSON string from SCAScanner).
        Expected raw_output is JSON with scanner, dependencies, vulnerabilities, findings.
        Returns normalized result for FindingEngine.
        """
        if not raw_output or not raw_output.strip():
            return {"scanner": "sca", "assets": [], "findings": []}

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid SCA output JSON: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("SCA output must be a JSON object")

        # Support both direct findings and raw analyzer output
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        # Ensure each finding has scanner = sca
        for f in findings:
            if isinstance(f, dict) and not f.get("scanner"):
                f["scanner"] = "sca"

        # SCA does not create new asset types currently; assets remain empty
        # Asset correlation will handle linking to existing assets when evidence matches
        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []

        # Also handle case where raw_output is from legacy analyzer with dependencies/vulnerabilities but no findings key?
        # Already covered.

        return {
            "scanner": "sca",
            "assets": assets,
            "findings": findings,
        }
