import html
import xml.etree.ElementTree as ET

from app.scanner.parsers.base import BaseParser


class ZAPParser(BaseParser):
    scanner_name = "zap"

    RISK_MAP = {
        "3": ("high", 75),
        "2": ("medium", 50),
        "1": ("low", 25),
        "0": ("info", 5),
    }

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {
                "scanner": self.scanner_name,
                "assets": [],
                "findings": [],
            }

        xml_output = self._extract_xml_report(raw_output)

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as exc:
            raise ValueError(
                f"Invalid ZAP XML output: {exc}"
            ) from exc

        assets = []
        findings = []

        for site in root.findall(".//site"):
            site_asset = self._parse_site(site)

            if site_asset:
                assets.append(site_asset)

            for alert in site.findall("./alerts/alertitem"):
                findings.extend(
                    self._parse_alert(
                        alert=alert,
                        site=site,
                    )
                )

        return {
            "scanner": self.scanner_name,
            "assets": assets,
            "findings": findings,
        }

    def _extract_xml_report(self, raw_output: str) -> str:
        """
        ZAP writes startup/progress messages before the XML report.

        Example:

            Found Java version...
            Accessing URL
            Active scanning
            Attack complete
            <?xml version="1.0"?>
            <OWASPZAPReport ...>

        Extract only the XML portion before parsing.
        """

        xml_start = raw_output.find("<?xml")

        if xml_start == -1:
            xml_start = raw_output.find("<OWASPZAPReport")

        if xml_start == -1:
            raise ValueError(
                "ZAP XML report was not found in scanner output."
            )

        return raw_output[xml_start:].strip()

    def _parse_site(self, site: ET.Element) -> dict:
        name = site.get("name", "")
        host = site.get("host", "")
        port = site.get("port", "")
        ssl = site.get("ssl", "false").lower() == "true"

        return {
            "type": "web_site",
            "name": name,
            "host": host,
            "port": int(port) if port.isdigit() else port,
            "ssl": ssl,
        }

    def _parse_alert(
        self,
        alert: ET.Element,
        site: ET.Element,
    ) -> list[dict]:
        plugin_id = self._text(
            alert,
            "pluginid",
        )

        alert_ref = self._text(
            alert,
            "alertRef",
        )

        title = (
            self._text(alert, "alert")
            or self._text(alert, "name")
        )

        risk_code = self._text(
            alert,
            "riskcode",
        )

        severity, score = self.RISK_MAP.get(
            risk_code,
            ("info", 5),
        )

        confidence = self._text(
            alert,
            "confidence",
        )

        description = self._clean_html(
            self._text(alert, "desc")
        )

        remediation = self._clean_html(
            self._text(alert, "solution")
        )

        reference = self._clean_html(
            self._text(alert, "reference")
        )

        cwe = self._text(
            alert,
            "cweid",
        )

        wasc = self._text(
            alert,
            "wascid",
        )

        findings = []

        instances = alert.findall(
            "./instances/instance"
        )

        if not instances:
            instances = [None]

        for instance in instances:
            uri = ""
            method = ""
            parameter = ""
            evidence = ""

            if instance is not None:
                uri = self._text(
                    instance,
                    "uri",
                )

                method = self._text(
                    instance,
                    "method",
                )

                parameter = self._text(
                    instance,
                    "param",
                )

                evidence = self._text(
                    instance,
                    "evidence",
                )

            finding = {
                "title": title,
                "description": description,
                "severity": severity,
                "score": score,
                "status": "open",
                "evidence": evidence,
                "remediation": remediation,
                "cve": None,
                "cwe": self._normalize_identifier(
                    cwe,
                    "CWE",
                ),
                "metadata": {
                    "plugin_id": plugin_id,
                    "alert_ref": alert_ref,
                    "confidence": confidence,
                    "risk_code": risk_code,
                    "wasc_id": wasc,
                    "site": site.get(
                        "name",
                        "",
                    ),
                    "host": site.get(
                        "host",
                        "",
                    ),
                    "port": site.get(
                        "port",
                        "",
                    ),
                    "ssl": (
                        site.get(
                            "ssl",
                            "false",
                        ).lower()
                        == "true"
                    ),
                    "uri": uri,
                    "method": method,
                    "parameter": parameter,
                    "reference": reference,
                },
            }

            findings.append(finding)

        return findings

    def _text(
        self,
        element: ET.Element,
        tag: str,
    ) -> str:
        child = element.find(tag)

        if child is None or child.text is None:
            return ""

        return child.text.strip()

    def _clean_html(self, value: str) -> str:
        if not value:
            return ""

        value = html.unescape(value)

        value = value.replace(
            "<p>",
            "",
        )

        value = value.replace(
            "</p>",
            "\n",
        )

        value = value.replace(
            "<br>",
            "\n",
        )

        value = value.replace(
            "<br/>",
            "\n",
        )

        value = value.replace(
            "<br />",
            "\n",
        )

        return value.strip()

    def _normalize_identifier(
        self,
        value: str,
        prefix: str,
    ) -> str | None:
        if not value or value in {
            "-1",
            "0",
        }:
            return None

        if value.upper().startswith(
            prefix.upper()
        ):
            return value.upper()

        return f"{prefix}-{value}"