from app.scanner.parsers.base import BaseParser
from app.scanner.parsers.json_extract import extract_json_document


class TLSParser(BaseParser):
    scanner_name = "tls"

    SKIP_SEVERITIES = {
        "ok",
        "debug",
        "fatal",
    }

    SEVERITY_MAP = {
        "critical": ("critical", 90),
        "high": ("high", 75),
        "medium": ("medium", 50),
        "low": ("low", 25),
        "warn": ("low", 25),
        "warning": ("low", 25),
        "info": ("info", 5),
    }

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
            raise ValueError(
                f"Invalid TLS JSON output: {exc}"
            ) from exc

        assets = self._parse_assets(document)
        findings = []

        for item in self._iter_finding_items(document):
            finding = self._parse_finding(item)

            if finding:
                findings.append(finding)

        return {
            "scanner": self.scanner_name,
            "assets": assets,
            "findings": findings,
        }

    def _iter_finding_items(self, document):
        if isinstance(document, list):
            for item in document:
                yield from self._iter_finding_items(item)
            return

        if not isinstance(document, dict):
            return

        if "id" in document and "severity" in document:
            yield document
            return

        for value in document.values():
            yield from self._iter_finding_items(value)

    def _parse_assets(self, document) -> list[dict]:
        assets = []
        seen = set()

        if isinstance(document, dict):
            scan_results = document.get("scanResult")

            if isinstance(scan_results, list):
                for result in scan_results:
                    if not isinstance(result, dict):
                        continue

                    asset = {
                        "type": "tls_endpoint",
                        "host": result.get("targetHost", ""),
                        "ip": result.get("ip", ""),
                        "port": result.get("port", ""),
                    }
                    key = (
                        asset["host"],
                        asset["ip"],
                        str(asset["port"]),
                    )

                    if key not in seen:
                        seen.add(key)
                        assets.append(asset)

        if assets:
            return assets

        for item in self._iter_finding_items(document):
            ip = str(item.get("ip") or "")
            port = str(item.get("port") or "")
            host = ip.split("/")[-1] if "/" in ip else ip
            key = (host, ip, port)

            if key in seen or not (ip or port):
                continue

            seen.add(key)
            assets.append(
                {
                    "type": "tls_endpoint",
                    "host": host,
                    "ip": ip,
                    "port": int(port) if port.isdigit() else port,
                }
            )

        return assets

    def _parse_finding(self, item: dict) -> dict | None:
        finding_id = str(item.get("id") or "")

        if self._is_http_header_finding(finding_id):
            return None

        raw_severity = str(item.get("severity") or "info").lower()

        if raw_severity in self.SKIP_SEVERITIES:
            return None

        severity, score = self.SEVERITY_MAP.get(
            raw_severity,
            ("info", 5),
        )

        description = str(item.get("finding") or "").strip()
        title = self._title_for(finding_id, description)

        cve = item.get("cve") or None
        cwe = item.get("cwe") or None

        if isinstance(cve, list):
            cve = cve[0] if cve else None

        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None

        return {
            "title": title,
            "description": description or title,
            "severity": severity,
            "score": score,
            "status": "open",
            "evidence": description,
            "remediation": (
                "Review the TLS configuration, disable insecure "
                "protocols and ciphers, and ensure the certificate "
                "is valid for the hostname."
            ),
            "cve": cve,
            "cwe": self._normalize_cwe(cwe),
            "metadata": {
                "id": finding_id,
                "ip": item.get("ip", ""),
                "port": item.get("port", ""),
                "severity_raw": item.get("severity", ""),
                "cve": cve,
                "cwe": cwe,
            },
        }

    def _is_http_header_finding(self, finding_id: str) -> bool:
        fid = finding_id.lower()

        if fid.startswith("http_"):
            return True

        if fid in {
            "hsts",
            "hsts_time",
            "security_headers",
            "banner_http",
        }:
            return True

        if "cookie" in fid:
            return True

        return False

    def _title_for(self, finding_id: str, description: str) -> str:
        if finding_id:
            readable = finding_id.replace("_", " ").replace("-", " ")
            return readable.strip()

        if description:
            return description.split(".")[0][:120]

        return "TLS finding"

    def _normalize_cwe(self, value) -> str | None:
        if not value:
            return None

        text = str(value).strip()

        if text.upper().startswith("CWE-"):
            return text.upper()

        if text.isdigit():
            return f"CWE-{text}"

        return text
