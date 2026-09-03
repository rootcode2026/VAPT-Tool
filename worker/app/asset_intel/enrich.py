"""Centralized asset expansion and relationship extraction.

Parsers keep their existing output contract. This layer runs after
parsing and before persistence.
"""

from app.asset_intel.normalize import (
    canonical_value,
    infer_asset_type,
    infer_asset_value,
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_service,
    normalize_technology,
    normalize_url,
)
from app.asset_intel.types import RELATIONSHIP_TYPES


def enrich_parsed_output(
    scanner: str,
    assets: list,
    findings: list | None = None,
) -> dict:
    collected: dict[tuple[str, str], dict] = {}
    relationships: list[dict] = []

    for asset in assets or []:
        if not isinstance(asset, dict):
            continue

        _ingest_parsed_asset(collected, asset, scanner)

    name = str(scanner or "").strip().lower()

    if name == "dns":
        _enrich_dns(collected, relationships, assets or [])
    elif name == "subdomain":
        _enrich_subdomain(collected, relationships, assets or [])
    elif name == "nmap":
        _enrich_nmap(collected, relationships, assets or [])
    elif name == "http_fingerprint":
        _enrich_http_fingerprint(collected, relationships, assets or [])
    elif name == "tls":
        _enrich_tls(collected, relationships, assets or [])
    elif name == "zap":
        _enrich_zap(collected, relationships, assets or [])
    elif name == "nikto":
        _enrich_nikto(collected, relationships, assets or [])
    elif name == "nuclei":
        _enrich_nuclei(collected, relationships, findings or [])

    return {
        "assets": list(collected.values()),
        "relationships": relationships,
    }


def _ingest_parsed_asset(collected: dict, asset: dict, scanner: str) -> dict | None:
    asset_type = infer_asset_type(asset)
    value = infer_asset_value(asset)

    if not value:
        return None

    metadata = asset.get("metadata")
    if not isinstance(metadata, dict):
        metadata = _fallback_metadata(asset)

    return _put(
        collected,
        asset_type,
        value,
        metadata,
        scanner=scanner,
    )


def _fallback_metadata(asset: dict) -> dict:
    ignored = {
        "type",
        "value",
        "name",
        "url",
        "final_url",
        "host",
        "ip",
        "headers",
        "cookies",
        "redirects",
        "addresses",
        "ports",
        "hostnames",
        "technologies",
    }

    return {
        key: item
        for key, item in asset.items()
        if key not in ignored
    }


def _put(
    collected: dict,
    asset_type: str,
    value,
    metadata: dict | None = None,
    *,
    scanner: str | None = None,
) -> dict | None:
    canonical = canonical_value(asset_type, value)

    if not canonical:
        return None

    key = (asset_type, canonical)
    extra = dict(metadata or {})

    if scanner:
        extra.setdefault("sources", [])
        if scanner not in extra["sources"]:
            extra["sources"] = list(extra["sources"]) + [scanner]

    existing = collected.get(key)

    if existing is None:
        collected[key] = {
            "type": asset_type,
            "value": canonical,
            "metadata": extra,
        }
        return collected[key]

    merged = dict(existing.get("metadata") or {})
    for field, item in extra.items():
        if field == "sources":
            continue
        if field not in merged or merged[field] in (None, "", [], {}):
            merged[field] = item
        elif isinstance(merged[field], dict) and isinstance(item, dict):
            merged[field] = {**merged[field], **item}
        else:
            merged[field] = item

    sources = list(merged.get("sources") or [])
    for source in extra.get("sources") or []:
        if source not in sources:
            sources.append(source)
    merged["sources"] = sources
    existing["metadata"] = merged
    return existing


def _relate(
    relationships: list,
    source: dict | None,
    target: dict | None,
    relationship_type: str,
    metadata: dict | None = None,
) -> None:
    if not source or not target:
        return

    if relationship_type not in RELATIONSHIP_TYPES:
        return

    if (
        source["type"] == target["type"]
        and source["value"] == target["value"]
    ):
        return

    item = {
        "source_type": source["type"],
        "source_value": source["value"],
        "target_type": target["type"],
        "target_value": target["value"],
        "relationship_type": relationship_type,
        "metadata": dict(metadata or {}),
    }

    key = (
        item["source_type"],
        item["source_value"],
        item["target_type"],
        item["target_value"],
        item["relationship_type"],
    )

    existing_keys = {
        (
            rel["source_type"],
            rel["source_value"],
            rel["target_type"],
            rel["target_value"],
            rel["relationship_type"],
        )
        for rel in relationships
    }

    if key in existing_keys:
        return

    relationships.append(item)


def _lookup(collected: dict, asset_type: str, value) -> dict | None:
    canonical = canonical_value(asset_type, value)
    if not canonical:
        return None
    return collected.get((asset_type, canonical))


def _hostname_asset(collected: dict, name: str, scanner: str) -> dict | None:
    host = normalize_hostname(name)
    if not host:
        return None

    for kind in ("domain", "subdomain", "hostname"):
        found = collected.get((kind, host))
        if found:
            return found

    return _put(collected, "hostname", host, scanner=scanner)


def _enrich_dns(collected: dict, relationships: list, assets: list) -> None:
    for asset in assets:
        if not isinstance(asset, dict):
            continue

        kind = str(asset.get("type") or "")
        metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
        host = normalize_hostname(metadata.get("host") or metadata.get("parent"))

        if kind == "subdomain":
            parent = normalize_hostname(metadata.get("parent") or host)
            _maybe_contains(
                collected,
                relationships,
                parent,
                asset.get("value"),
                "dns",
            )
            continue

        if kind == "ip":
            target = _lookup(collected, "ip", asset.get("value"))
            if not target:
                continue
            owner = _hostname_asset(collected, host, "dns") if host else None
            _relate(relationships, owner, target, "resolves_to", {"record": "A"})

        elif kind == "ipv6":
            target = _lookup(collected, "ipv6", asset.get("value"))
            if not target:
                continue
            owner = _hostname_asset(collected, host, "dns") if host else None
            _relate(relationships, owner, target, "resolves_to", {"record": "AAAA"})

        elif kind == "dns_cname":
            source = _hostname_asset(collected, asset.get("value"), "dns")
            target_name = normalize_hostname(metadata.get("target"))
            target = _hostname_asset(collected, target_name, "dns") if target_name else None
            _relate(
                relationships,
                source,
                target,
                "points_to",
                {"record": "CNAME"},
            )
            _maybe_contains(collected, relationships, host, target_name, "dns")

        elif kind == "dns_mx":
            owner = _hostname_asset(collected, host, "dns") if host else None
            mail_host = normalize_hostname(asset.get("value"))
            target = _hostname_asset(collected, mail_host, "dns") if mail_host else None
            _relate(
                relationships,
                owner,
                target,
                "points_to",
                {
                    "record": "MX",
                    "priority": metadata.get("priority"),
                },
            )
            _maybe_contains(collected, relationships, host, mail_host, "dns")

        elif kind == "dns_ns":
            owner = _hostname_asset(collected, host, "dns") if host else None
            ns_host = normalize_hostname(asset.get("value"))
            target = _hostname_asset(collected, ns_host, "dns") if ns_host else None
            _relate(
                relationships,
                owner,
                target,
                "points_to",
                {"record": "NS"},
            )
            _maybe_contains(collected, relationships, host, ns_host, "dns")

        elif kind == "dns_soa":
            owner = _hostname_asset(collected, host, "dns") if host else None
            soa = _lookup(collected, "dns_soa", asset.get("value"))
            _relate(
                relationships,
                owner,
                soa,
                "observed_on",
                {"record": "SOA"},
            )


def _maybe_contains(
    collected: dict,
    relationships: list,
    parent: str | None,
    child: str | None,
    scanner: str,
) -> None:
    parent_name = normalize_hostname(parent)
    child_name = normalize_hostname(child)

    if not parent_name or not child_name:
        return

    if child_name == parent_name:
        return

    if not _is_immediate_child(child_name, parent_name):
        return

    parent_asset = _hostname_asset(collected, parent_name, scanner)
    child_asset = _hostname_asset(collected, child_name, scanner)

    if child_asset and child_asset["type"] == "hostname":
        subdomain = _put(
            collected,
            "subdomain",
            child_name,
            {"parent": parent_name},
            scanner=scanner,
        )
        child_asset = subdomain or child_asset

    _relate(relationships, parent_asset, child_asset, "contains")


def _enrich_subdomain(collected: dict, relationships: list, assets: list) -> None:
    observed = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        host = normalize_hostname(asset.get("value"))
        metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
        zone = normalize_hostname(metadata.get("input") or metadata.get("parent"))
        resolved = metadata.get("resolved_ip")

        if not host:
            continue

        child = _lookup(collected, "subdomain", host) or _hostname_asset(
            collected,
            host,
            "subdomain",
        )
        observed.append((host, zone, child, resolved))

        if zone:
            parent = _put(collected, "domain", zone, scanner="subdomain")
            if _is_immediate_child(host, zone):
                _relate(relationships, parent, child, "contains")

        if resolved:
            ip_type, ip_value = normalize_ip(resolved)
            if ip_value:
                address = _put(collected, ip_type, ip_value, scanner="subdomain")
                _relate(
                    relationships,
                    child,
                    address,
                    "resolves_to",
                    {"evidence": "resolved_ip"},
                )

    for host, zone, child, _resolved in observed:
        immediate = _immediate_parent(host)
        if not immediate or immediate == zone:
            continue
        if zone and not immediate.endswith("." + zone) and immediate != zone:
            continue
        sibling = _lookup(collected, "subdomain", immediate)
        if sibling:
            _relate(relationships, sibling, child, "contains")


def _immediate_parent(hostname: str) -> str | None:
    labels = hostname.split(".")
    if len(labels) < 3:
        return None
    return ".".join(labels[1:])


def _is_immediate_child(child: str, parent: str) -> bool:
    if not child or not parent or child == parent:
        return False

    suffix = "." + parent
    if not child.endswith(suffix):
        return False

    extra = child[: -len(suffix)]
    return extra != "" and "." not in extra


def _enrich_nmap(collected: dict, relationships: list, assets: list) -> None:
    for asset in assets:
        if not isinstance(asset, dict):
            continue

        addresses = []
        for item in asset.get("addresses") or []:
            if isinstance(item, dict):
                raw = item.get("address")
            else:
                raw = item
            ip_type, ip_value = normalize_ip(raw)
            if not ip_value:
                continue
            address = _put(
                collected,
                ip_type,
                ip_value,
                {"source": "nmap"},
                scanner="nmap",
            )
            addresses.append(address)

        for name in asset.get("hostnames") or []:
            host = normalize_hostname(name)
            if host:
                _hostname_asset(collected, host, "nmap")

        for port in asset.get("ports") or []:
            if not isinstance(port, dict):
                continue

            if port.get("state") and port.get("state") != "open":
                continue

            port_value = normalize_port(port.get("port"))
            if not port_value:
                continue

            port_asset = _put(
                collected,
                "port",
                port_value,
                {
                    "protocol": port.get("protocol"),
                    "state": port.get("state"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                },
                scanner="nmap",
            )

            for address in addresses:
                _relate(
                    relationships,
                    address,
                    port_asset,
                    "exposes",
                    {"protocol": port.get("protocol")},
                )

            service_name = normalize_service(port.get("service"))
            if service_name:
                service = _put(
                    collected,
                    "service",
                    service_name,
                    {
                        "product": port.get("product"),
                        "version": port.get("version"),
                    },
                    scanner="nmap",
                )
                _relate(relationships, port_asset, service, "runs")


def _enrich_http_fingerprint(
    collected: dict,
    relationships: list,
    assets: list,
) -> None:
    for asset in assets:
        if not isinstance(asset, dict):
            continue

        url_value = normalize_url(asset.get("url") or asset.get("final_url"))
        if not url_value:
            continue

        url_asset = _put(
            collected,
            "url",
            url_value,
            {
                "target": asset.get("target"),
                "status_code": asset.get("status_code"),
                "tls": asset.get("tls"),
            },
            scanner="http_fingerprint",
        )

        host = normalize_hostname(url_value)
        if host:
            hostname = _hostname_asset(collected, host, "http_fingerprint")
            _relate(relationships, url_asset, hostname, "observed_on")

        technologies = asset.get("technologies") or []
        if not isinstance(technologies, list):
            technologies = [technologies]

        for item in technologies:
            name = normalize_technology(item)
            if not name:
                continue
            technology = _put(
                collected,
                "technology",
                name,
                {"raw": item} if str(item).strip() != name else {},
                scanner="http_fingerprint",
            )
            _relate(relationships, url_asset, technology, "serves")


def _enrich_tls(collected: dict, relationships: list, assets: list) -> None:
    for asset in assets:
        if not isinstance(asset, dict):
            continue

        raw_ip = str(asset.get("ip") or "")
        host = normalize_hostname(asset.get("host"))
        ip_value = raw_ip

        if "/" in raw_ip:
            address_part, _, host_part = raw_ip.partition("/")
            ip_value = address_part
            host = host or normalize_hostname(host_part)

        ip_type, canonical_ip = normalize_ip(ip_value)
        port_value = normalize_port(asset.get("port"))

        endpoint = _lookup(collected, "tls_endpoint", infer_asset_value(asset))
        if endpoint:
            metadata = dict(endpoint.get("metadata") or {})
            if host:
                metadata["host"] = host
            if canonical_ip:
                metadata["ip"] = canonical_ip
            if port_value:
                metadata["port"] = port_value
            metadata["certificate"] = {
                "note": (
                    "Certificate identity is not a first-class asset yet. "
                    "Preserve subject, issuer, SANs, expiry, protocol, and "
                    "cipher data here when the TLS parser exposes them."
                ),
            }
            endpoint["metadata"] = metadata

        hostname = _hostname_asset(collected, host, "tls") if host else None
        if hostname and endpoint:
            _relate(relationships, hostname, endpoint, "uses")

        if canonical_ip:
            address = _put(collected, ip_type, canonical_ip, scanner="tls")
            if port_value:
                port_asset = _put(collected, "port", port_value, scanner="tls")
                _relate(relationships, address, port_asset, "exposes")


def _enrich_zap(collected: dict, relationships: list, assets: list) -> None:
    for asset in assets:
        if not isinstance(asset, dict):
            continue

        name = asset.get("name") or asset.get("value")
        url_value = normalize_url(name) if name and "://" in str(name) else ""
        host = normalize_hostname(asset.get("host") or name)
        port_value = normalize_port(asset.get("port"))

        site = _lookup(collected, "web_site", infer_asset_value(asset))

        if url_value:
            url_asset = _put(collected, "url", url_value, scanner="zap")
            _relate(relationships, site, url_asset, "observed_on")

        if host:
            hostname = _hostname_asset(collected, host, "zap")
            _relate(relationships, site, hostname, "observed_on")

        if port_value:
            port_asset = _put(collected, "port", port_value, scanner="zap")
            _relate(relationships, site, port_asset, "exposes")


def _enrich_nikto(collected: dict, relationships: list, assets: list) -> None:
    for asset in assets:
        if not isinstance(asset, dict):
            continue

        host = normalize_hostname(asset.get("host"))
        port_value = normalize_port(asset.get("port"))
        web_host = _lookup(collected, "web_host", infer_asset_value(asset))

        if host:
            hostname = _hostname_asset(collected, host, "nikto")
            _relate(relationships, web_host, hostname, "observed_on")

        ip_type, ip_value = normalize_ip(asset.get("ip"))
        if ip_value:
            address = _put(collected, ip_type, ip_value, scanner="nikto")
            _relate(relationships, web_host, address, "resolves_to")
            if port_value:
                port_asset = _put(collected, "port", port_value, scanner="nikto")
                _relate(relationships, address, port_asset, "exposes")


def _enrich_nuclei(collected: dict, relationships: list, findings: list) -> None:
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        matched = metadata.get("matched_at") or metadata.get("url")

        if not matched:
            continue

        text = str(matched)
        if "://" in text:
            url_value = normalize_url(text)
            if url_value:
                url_asset = _put(collected, "url", url_value, scanner="nuclei")
                host = normalize_hostname(url_value)
                if host and url_asset:
                    hostname = _hostname_asset(collected, host, "nuclei")
                    _relate(relationships, url_asset, hostname, "observed_on")
            continue

        ip_type, ip_value = normalize_ip(text)
        if ip_value:
            _put(collected, ip_type, ip_value, scanner="nuclei")
            continue

        host = normalize_hostname(text)
        if host:
            _hostname_asset(collected, host, "nuclei")
