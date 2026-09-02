from app.scanner.parsers.base import BaseParser


class HTTPFingerprintParser(BaseParser):

    scanner_name = "http_fingerprint"

    def parse(self, raw_output: str) -> dict:
        import json

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "Invalid HTTP fingerprint scanner output."
            ) from exc

        if data.get("error"):
            return {
                "scanner": "http_fingerprint",
                "assets": [],
                "findings": [],
                "error": data["error"],
            }

        target = data.get("target")
        final_url = data.get("final_url")
        status_code = data.get("status_code")
        headers = data.get("headers", {})
        history = data.get("history", [])
        cookies = data.get("cookies", [])
        tls = data.get("tls", {})
        technologies = data.get(
            "technology",
            [],
        )

        asset = {
            "target": target,
            "url": final_url,
            "status_code": status_code,
            "technologies": technologies,
            "tls": tls,
            "headers": headers,
            "cookies": cookies,
            "redirects": history,
        }

        findings = []

        findings.extend(
            self._analyze_security_headers(
                headers
            )
        )

        findings.extend(
            self._analyze_server_header(
                headers
            )
        )

        findings.extend(
            self._analyze_tls(
                final_url,
                tls,
            )
        )

        findings.extend(
            self._analyze_redirects(
                target,
                final_url,
                history,
            )
        )

        for finding in findings:
            finding["metadata"] = {
                "url": final_url,
                "target": target,
                "status_code": status_code,
            }

        return {
            "scanner": "http_fingerprint",
            "assets": [asset],
            "findings": findings,
        }

    # ---------------------------------------------------------
    # SECURITY HEADERS
    # ---------------------------------------------------------

    def _analyze_security_headers(
        self,
        headers: dict,
    ) -> list[dict]:

        normalized_headers = {
            key.lower(): value
            for key, value in headers.items()
        }

        findings = []

        security_headers = {
            "strict-transport-security": (
                "Missing HSTS header",
                "low",
                25,
                "CWE-319",
                (
                    "Add a Strict-Transport-Security header "
                    "when the application is served over HTTPS."
                ),
            ),
            "content-security-policy": (
                "Missing Content-Security-Policy header",
                "low",
                25,
                "CWE-693",
                (
                    "Define a Content-Security-Policy appropriate "
                    "for the application."
                ),
            ),
            "x-content-type-options": (
                "Missing X-Content-Type-Options header",
                "low",
                25,
                "CWE-693",
                (
                    "Set X-Content-Type-Options to nosniff."
                ),
            ),
            "x-frame-options": (
                "Missing X-Frame-Options header",
                "low",
                25,
                "CWE-1021",
                (
                    "Set X-Frame-Options or use an appropriate "
                    "frame-ancestors CSP directive."
                ),
            ),
            "referrer-policy": (
                "Missing Referrer-Policy header",
                "info",
                5,
                None,
                (
                    "Configure an appropriate Referrer-Policy "
                    "for the application."
                ),
            ),
        }

        for header, details in security_headers.items():

            if header in normalized_headers:
                continue

            (
                title,
                severity,
                score,
                cwe,
                remediation,
            ) = details

            findings.append(
                self._finding(
                    title=title,
                    description=(
                        f"The HTTP response does not include "
                        f"the {header} security header."
                    ),
                    severity=severity,
                    score=score,
                    evidence=(
                        f"Response header '{header}' "
                        "was not present."
                    ),
                    remediation=remediation,
                    cwe=cwe,
                )
            )

        return findings

    # ---------------------------------------------------------
    # SERVER HEADER
    # ---------------------------------------------------------

    def _analyze_server_header(
        self,
        headers: dict,
    ) -> list[dict]:

        normalized_headers = {
            key.lower(): value
            for key, value in headers.items()
        }

        server = normalized_headers.get("server")

        if not server:
            return []

        return [
            self._finding(
                title="Server header disclosed",
                description=(
                    "The HTTP response exposes server "
                    "software information through the "
                    "Server response header."
                ),
                severity="info",
                score=5,
                evidence=(
                    f"Server: {server}"
                ),
                remediation=(
                    "Consider minimizing unnecessary "
                    "server software disclosure."
                ),
            )
        ]

    # ---------------------------------------------------------
    # TLS
    # ---------------------------------------------------------

    def _analyze_tls(
        self,
        final_url: str | None,
        tls: dict,
    ) -> list[dict]:

        if not final_url:
            return []

        if final_url.lower().startswith(
            "https://"
        ):
            return []

        return [
            self._finding(
                title="HTTPS is not enforced",
                description=(
                    "The final URL is served over "
                    "unencrypted HTTP."
                ),
                severity="medium",
                score=45,
                evidence=(
                    f"Final URL: {final_url}"
                ),
                remediation=(
                    "Serve the application over HTTPS "
                    "and redirect HTTP requests to HTTPS."
                ),
                cwe="CWE-319",
            )
        ]

    # ---------------------------------------------------------
    # REDIRECTS
    # ---------------------------------------------------------

    def _analyze_redirects(
        self,
        target: str,
        final_url: str | None,
        history: list,
    ) -> list[dict]:

        if not history:
            return []

        findings = []

        if final_url:
            target_is_http = target.lower().startswith(
                "http://"
            )

            final_is_https = final_url.lower().startswith(
                "https://"
            )

            if target_is_http and final_is_https:

                findings.append(
                    self._finding(
                        title="HTTP redirects to HTTPS",
                        description=(
                            "The target redirects from HTTP "
                            "to HTTPS."
                        ),
                        severity="info",
                        score=5,
                        evidence=(
                            f"Final URL: {final_url}"
                        ),
                        remediation=(
                            "Continue enforcing HTTPS across "
                            "all application endpoints."
                        ),
                    )
                )

        return findings

    # ---------------------------------------------------------
    # FINDING BUILDER
    # ---------------------------------------------------------

    def _finding(
        self,
        title: str,
        description: str,
        severity: str,
        score: int,
        evidence: str,
        remediation: str,
        cve: str | None = None,
        cwe: str | None = None,
    ) -> dict:

        return {
            "scanner": self.scanner_name,
            "title": title,
            "description": description,
            "severity": severity,
            "score": score,
            "status": "open",
            "evidence": evidence,
            "remediation": remediation,
            "cve": cve,
            "cwe": cwe,
        }