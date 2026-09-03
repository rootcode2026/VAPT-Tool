import json
import re

from app.asset_intel.normalize import normalize_hostname
from app.scanner.parsers.base import BaseParser


class DNSParser(BaseParser):
    scanner_name = "dns"

    MX_PATTERN = re.compile(
        r"^(?:(\d+)\s+)?(.+)$"
    )

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {
                "scanner": self.scanner_name,
                "assets": [],
                "findings": [],
            }

        records = self._parse_records(raw_output)
        assets = []
        seen = set()

        for record in records:
            host = self._normalize_name(
                record.get("host")
            )

            if host:
                self._add_asset(
                    assets,
                    seen,
                    {
                        "type": "domain",
                        "value": host,
                        "metadata": {
                            "resolver": record.get("resolver"),
                            "status_code": record.get(
                                "status_code"
                            ),
                        },
                    },
                )

            for address in self._as_list(record.get("a")):
                self._add_asset(
                    assets,
                    seen,
                    {
                        "type": "ip",
                        "value": address,
                        "metadata": {
                            "record": "A",
                            "host": host,
                        },
                    },
                )

            for address in self._as_list(record.get("aaaa")):
                self._add_asset(
                    assets,
                    seen,
                    {
                        "type": "ipv6",
                        "value": address,
                        "metadata": {
                            "record": "AAAA",
                            "host": host,
                        },
                    },
                )

            for cname in self._as_list(record.get("cname")):
                target = self._normalize_name(cname)
                owner = host or target

                self._add_asset(
                    assets,
                    seen,
                    {
                        "type": "dns_cname",
                        "value": owner,
                        "metadata": {
                            "target": target,
                            "record": "CNAME",
                        },
                    },
                )
                self._add_hostname_asset(
                    assets,
                    seen,
                    name=owner,
                    zone=host,
                    source="cname",
                )
                self._add_hostname_asset(
                    assets,
                    seen,
                    name=target,
                    zone=host,
                    source="cname_target",
                )

            for mx in self._as_list(record.get("mx")):
                priority, mail_host = self._parse_mx(mx)

                self._add_asset(
                    assets,
                    seen,
                    {
                        "type": "dns_mx",
                        "value": mail_host,
                        "metadata": {
                            "priority": priority,
                            "host": host,
                            "record": "MX",
                        },
                    },
                )
                self._add_hostname_asset(
                    assets,
                    seen,
                    name=mail_host,
                    zone=host,
                    source="mx",
                )

            for nameserver in self._as_list(record.get("ns")):
                ns_host = self._normalize_name(nameserver)

                self._add_asset(
                    assets,
                    seen,
                    {
                        "type": "dns_ns",
                        "value": ns_host,
                        "metadata": {
                            "host": host,
                            "record": "NS",
                        },
                    },
                )
                self._add_hostname_asset(
                    assets,
                    seen,
                    name=ns_host,
                    zone=host,
                    source="ns",
                )

            for txt in self._as_list(record.get("txt")):
                txt_value = str(txt).strip()

                if not txt_value:
                    continue

                self._add_asset(
                    assets,
                    seen,
                    {
                        "type": "dns_txt",
                        "value": txt_value,
                        "metadata": {
                            "host": host,
                            "record": "TXT",
                        },
                    },
                )

            for soa in self._as_list(record.get("soa")):
                soa_asset = self._parse_soa(soa, host)

                if soa_asset:
                    self._add_asset(assets, seen, soa_asset)

        return {
            "scanner": self.scanner_name,
            "assets": assets,
            "findings": [],
        }

    def _parse_records(self, raw_output: str) -> list[dict]:
        records = []
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
                    f"Invalid DNS JSON output: {exc}"
                ) from exc

            parsed_any = True

            if isinstance(data, list):
                records.extend(
                    item
                    for item in data
                    if isinstance(item, dict)
                )
            elif isinstance(data, dict):
                records.append(data)

        if not parsed_any:
            raise ValueError(
                "Invalid DNS JSON output: JSON document was not found."
            )

        return records

    def _add_hostname_asset(
        self,
        assets: list,
        seen: set,
        name: str | None,
        zone: str | None,
        source: str,
    ) -> None:
        name = self._normalize_name(name)

        if not name or not zone:
            return

        if name == zone:
            return

        if not self._is_under_zone(name, zone):
            return

        self._add_asset(
            assets,
            seen,
            {
                "type": "subdomain",
                "value": name,
                "metadata": {
                    "parent": zone,
                    "source": source,
                },
            },
        )

    def _parse_mx(self, value: str) -> tuple[int | None, str]:
        text = str(value).strip()
        match = self.MX_PATTERN.match(text)

        if not match:
            return None, self._normalize_name(text)

        priority_text, host = match.groups()
        priority = int(priority_text) if priority_text else None

        return priority, self._normalize_name(host)

    def _parse_soa(self, value: str, host: str | None) -> dict | None:
        parts = str(value).split()

        if not parts:
            return None

        mname = self._normalize_name(parts[0])
        metadata = {
            "host": host,
            "record": "SOA",
            "raw": str(value).strip(),
        }

        if len(parts) >= 2:
            metadata["rname"] = self._normalize_name(parts[1])

        if len(parts) >= 3 and parts[2].isdigit():
            metadata["serial"] = int(parts[2])

        return {
            "type": "dns_soa",
            "value": mname,
            "metadata": metadata,
        }

    def _add_asset(
        self,
        assets: list,
        seen: set,
        asset: dict,
    ) -> None:
        value = str(asset.get("value") or "").strip()

        if not value:
            return

        asset["value"] = value
        key = (asset["type"], value.lower())

        if key in seen:
            return

        seen.add(key)
        assets.append(asset)

    def _as_list(self, value) -> list:
        if value is None:
            return []

        if isinstance(value, list):
            return value

        return [value]

    def _normalize_name(self, value) -> str:
        return normalize_hostname(value)

    def _is_under_zone(self, name: str, zone: str) -> bool:
        return name.endswith("." + zone)
