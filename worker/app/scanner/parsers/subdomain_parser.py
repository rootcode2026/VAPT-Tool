import json

from app.asset_intel.normalize import normalize_hostname
from app.scanner.parsers.base import BaseParser


class SubdomainParser(BaseParser):
    scanner_name = "subdomain"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {
                "scanner": self.scanner_name,
                "assets": [],
                "findings": [],
            }

        assets = []
        seen = set()
        parsed_any = False

        for line in raw_output.splitlines():
            line = line.strip()

            if not line:
                continue

            if line[0] not in {"{", "["}:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid subdomain JSON output: {exc}"
                ) from exc

            parsed_any = True

            if isinstance(data, list):
                items = data
            else:
                items = [data]

            for item in items:
                if not isinstance(item, dict):
                    continue

                host = self._normalize_name(
                    item.get("host")
                    or item.get("subdomain")
                    or item.get("name")
                )

                if not host:
                    continue

                key = ("subdomain", host)

                if key in seen:
                    continue

                seen.add(key)

                metadata = {
                    "source": item.get("source"),
                    "input": self._normalize_name(
                        item.get("input")
                    ),
                }

                resolved_ip = item.get("ip") or item.get("a")

                if resolved_ip:
                    metadata["resolved_ip"] = resolved_ip

                if item.get("cname"):
                    metadata["cname"] = item.get("cname")

                assets.append(
                    {
                        "type": "subdomain",
                        "value": host,
                        "metadata": {
                            key: value
                            for key, value in metadata.items()
                            if value
                        },
                    }
                )

        if not parsed_any:
            raise ValueError(
                "Invalid subdomain JSON output: "
                "JSON document was not found."
            )

        return {
            "scanner": self.scanner_name,
            "assets": assets,
            "findings": [],
        }

    def _normalize_name(self, value) -> str:
        return normalize_hostname(value)
