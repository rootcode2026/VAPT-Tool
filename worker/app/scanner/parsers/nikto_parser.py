import re

from app.scanner.parsers.base import BaseParser
from app.scanner.parsers.json_extract import extract_json_document


class NiktoParser(BaseParser):
    scanner_name = "nikto"

    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {
                "scanner": self.scanner_name,
                "assets": [],
                "findings": [],
            }

        try:
            document = extract_json_document(raw_output)
        except ValueError as exc:
            if self._is_connection_failure(raw_output):
                return {
                    "scanner": self.scanner_name,
                    "assets": [],
                    "findings": [],
                }

            raise ValueError(
                f"Invalid Nikto JSON output: {exc}"
            ) from exc

        assets = []
        findings = []

        for host in self._iter_hosts(document):
            asset = self._parse_asset(host)

            if asset:
                assets.append(asset)

            for vulnerability in host.get("vulnerabilities", []):
                finding = self._parse_vulnerability(
                    vulnerability=vulnerability,
                    host=host,
                )

                if finding:
                    findings.append(finding)

        return {
            "scanner": self.scanner_name,
            "assets": assets,
            "findings": findings,
        }

    def _is_connection_failure(self, raw_output: str) -> bool:
        lowered = raw_output.lower()
        return (
            "unable to connect" in lowered
            or "[fail]" in lowered
        )

    def _iter_hosts(self, document) -> list[dict]:
        if isinstance(document, list):
            return [
                item
                for item in document
                if isinstance(item, dict)
            ]

        if isinstance(document, dict):
            return [document]

        raise ValueError("Invalid Nikto JSON output.")

    def _parse_asset(self, host: dict) -> dict:
        port = host.get("port")

        return {
            "type": "web_host",
            "host": host.get("host", ""),
            "ip": host.get("ip", ""),
            "port": int(port) if str(port).isdigit() else port,
            "banner": host.get("banner", ""),
        }

    def _parse_vulnerability(
        self,
        vulnerability: dict,
        host: dict,
    ) -> dict | None:
        if not isinstance(vulnerability, dict):
            return None

        message = str(
            vulnerability.get("msg")
            or vulnerability.get("message")
            or ""
        ).strip()

        title = message or "Nikto finding"
        osvdb = str(vulnerability.get("OSVDB") or vulnerability.get("osvdb") or "")
        references = str(vulnerability.get("references") or "")
        combined = " ".join(
            [
                message,
                references,
                str(vulnerability.get("id") or ""),
            ]
        )

        cve = self._first_match(self.CVE_PATTERN, combined)
        cwe = self._first_match(self.CWE_PATTERN, combined)
        severity, score = self._severity_for(
            cve=cve,
            osvdb=osvdb,
            message=message,
        )

        return {
            "title": title,
            "description": message,
            "severity": severity,
            "score": score,
            "status": "open",
            "evidence": self._build_evidence(
                vulnerability=vulnerability,
                host=host,
            ),
            "remediation": (
                "Review the Nikto finding, confirm the affected "
                "endpoint, and apply the recommended configuration "
                "or patch."
            ),
            "cve": cve,
            "cwe": cwe,
            "metadata": {
                "nikto_id": str(vulnerability.get("id") or ""),
                "osvdb": osvdb,
                "method": vulnerability.get("method", ""),
                "url": vulnerability.get("url", ""),
                "host": host.get("host", ""),
                "ip": host.get("ip", ""),
                "port": host.get("port", ""),
                "banner": host.get("banner", ""),
                "references": references,
            },
        }

    def _build_evidence(
        self,
        vulnerability: dict,
        host: dict,
    ) -> str:
        method = vulnerability.get("method") or "GET"
        url = vulnerability.get("url") or "/"
        host_name = host.get("host") or host.get("ip") or "unknown"
        message = vulnerability.get("msg") or ""

        return (
            f"{method} {host_name}{url}: {message}"
        ).strip()

    def _severity_for(
        self,
        cve: str | None,
        osvdb: str,
        message: str,
    ) -> tuple[str, int]:
        if cve:
            return "high", 75

        lowered = message.lower()

        if osvdb and osvdb not in {"0", "00"}:
            return "medium", 50

        if any(
            token in lowered
            for token in (
                "vulnerable",
                "outdated",
                "overflow",
                "injection",
                "directory indexing",
            )
        ):
            return "medium", 50

        if any(
            token in lowered
            for token in (
                "header",
                "retrieved",
                "allowed",
                "banner",
            )
        ):
            return "info", 5

        return "low", 25

    def _first_match(
        self,
        pattern: re.Pattern,
        text: str,
    ) -> str | None:
        match = pattern.search(text)

        if not match:
            return None

        return match.group(0).upper().replace("CWE-", "CWE-")
