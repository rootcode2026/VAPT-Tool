from urllib.parse import urljoin, urlparse
import urllib3
import requests

from app.scanner.base import BaseScanner
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

class HTTPFingerprintScanner(BaseScanner):

    # ---------------------------------------------------------
    # Identity
    # ---------------------------------------------------------

    name = "http_fingerprint"
    category = "web_recon"

    description = (
        "HTTP and HTTPS web service fingerprinting "
        "and security header analysis"
    )

    # ---------------------------------------------------------
    # Target / Input
    # ---------------------------------------------------------

    target_types = {
        "url",
        "domain",
    }

    input_type = "target"

    # ---------------------------------------------------------
    # Output
    # ---------------------------------------------------------

    output_format = "json"

    # ---------------------------------------------------------
    # Capabilities
    # ---------------------------------------------------------

    capabilities = {
        "http_fingerprinting",
        "https_detection",
        "header_analysis",
        "redirect_detection",
        "technology_detection",
    }

    # ---------------------------------------------------------
    # Requirements
    # ---------------------------------------------------------

    requirements = [
        "network_access",
    ]

    # ---------------------------------------------------------
    # Execution
    # ---------------------------------------------------------

    timeout = 30

    def scan(self, target: str) -> str:
        """
        Perform HTTP fingerprinting.

        The scanner returns JSON text so that it can be
        processed by HTTPFingerprintParser.
        """

        normalized_target = self._normalize_target(target)

        try:
            response = requests.get(
                normalized_target,
                timeout=self.timeout,
                allow_redirects=True,
                headers={
                    "User-Agent": (
                        "VAPT-Security-Scanner/1.0"
                    )
                },
                verify=False,
            )

            result = {
                "scanner": self.name,
                "target": target,
                "final_url": response.url,
                "status_code": response.status_code,
                "history": [
                    {
                        "status_code": redirect.status_code,
                        "url": redirect.url,
                        "location": redirect.headers.get(
                            "Location"
                        ),
                    }
                    for redirect in response.history
                ],
                "headers": dict(response.headers),
                "cookies": [
                    cookie.name
                    for cookie in response.cookies
                ],
                "tls": {
                    "https": response.url.startswith(
                        "https://"
                    ),
                },
                "technology": self._detect_technology(
                    response
                ),
            }

            return self._to_json(result)

        except requests.RequestException as exc:
            error_result = {
                "scanner": self.name,
                "target": target,
                "error": str(exc),
            }

            return self._to_json(error_result)

    def _normalize_target(self, target: str) -> str:
        target = target.strip()

        if not target:
            raise ValueError(
                "HTTP fingerprint target cannot be empty."
            )

        parsed = urlparse(target)

        if parsed.scheme:
            if parsed.scheme not in {
                "http",
                "https",
            }:
                raise ValueError(
                    "HTTP fingerprint scanner only supports "
                    "http:// and https:// targets."
                )

            return target

        return f"https://{target}"

    def _detect_technology(
        self,
        response: requests.Response,
    ) -> list[str]:

        technologies = []

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        server = headers.get("server", "").lower()
        powered_by = headers.get(
            "x-powered-by",
            "",
        ).lower()

        if "nginx" in server:
            technologies.append("nginx")

        if "apache" in server:
            technologies.append("apache")

        if "iis" in server:
            technologies.append("iis")

        if "cloudflare" in server:
            technologies.append("cloudflare")

        if "php" in powered_by:
            technologies.append("PHP")

        if "asp.net" in powered_by:
            technologies.append("ASP.NET")

        return sorted(set(technologies))

    def _to_json(self, data: dict) -> str:
        import json

        return json.dumps(
            data,
            ensure_ascii=False,
        )