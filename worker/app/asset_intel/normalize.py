"""Canonical asset value normalization."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse, urlunparse

from app.asset_intel.types import HOSTNAME_TYPES, TECHNOLOGY_SKIP

MAX_ASSET_VALUE_LENGTH = 1024
DEFAULT_TLS_PORT = 443
DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}
ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

LABEL_RE = re.compile(
    r"^(?:[*]|xn--[a-z0-9-]{1,59}|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$"
)


class AssetNormalizationError(ValueError):
    """Raised when a value cannot be canonicalized for its asset type."""


def canonical_asset_identity(asset_type: str, value) -> str:
    """Return the canonical identity string for (asset_type, value).

    Suitable for the unique key (project_id, asset_type, value).
    Raises AssetNormalizationError when the value is missing or invalid.
    """
    kind = _asset_kind(asset_type)

    if value is None:
        raise AssetNormalizationError(
            f"Asset value is required for type '{kind}'."
        )

    try:
        result = _normalize_typed(kind, value)
    except AssetNormalizationError:
        raise
    except ValueError as exc:
        raise AssetNormalizationError(str(exc)) from exc

    if not result:
        raise AssetNormalizationError(
            f"Asset value is invalid for type '{kind}'."
        )

    return result[:MAX_ASSET_VALUE_LENGTH]


def canonical_value(asset_type: str, value) -> str | None:
    try:
        return canonical_asset_identity(asset_type, value)
    except AssetNormalizationError:
        return None


def normalize_hostname(value, *, extract_url: bool = True) -> str:
    try:
        return _normalize_hostname(value, extract_url=extract_url)
    except AssetNormalizationError:
        return ""


def normalize_ipv4(value) -> str:
    return _normalize_ipv4(value)


def normalize_ipv6(value) -> str:
    return _normalize_ipv6(value)


def normalize_ip(value) -> tuple[str, str] | tuple[None, None]:
    text = str(value or "").strip()

    if not text:
        return None, None

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None, None

    if address.version == 4:
        return "ip", str(address)

    return "ipv6", address.compressed


def normalize_url(value) -> str:
    try:
        return _normalize_url(value)
    except AssetNormalizationError:
        return ""


def normalize_port(value) -> str:
    try:
        return _normalize_port(value)
    except AssetNormalizationError:
        return ""


def normalize_service(value) -> str:
    try:
        return _normalize_service(value)
    except AssetNormalizationError:
        return ""


def normalize_technology(value) -> str:
    try:
        return _normalize_technology(value)
    except AssetNormalizationError:
        return ""


def normalize_tls_endpoint(value) -> str:
    try:
        return _normalize_tls_endpoint(value)
    except AssetNormalizationError:
        return ""


def normalize_dns_txt(value) -> str:
    try:
        return _normalize_dns_txt(value)
    except AssetNormalizationError:
        return ""


def _asset_kind(asset_type: str) -> str:
    return str(asset_type or "").strip().lower() or "unknown"


def _normalize_typed(kind: str, value) -> str:
    if kind in HOSTNAME_TYPES:
        return _normalize_hostname(value, extract_url=True)
    if kind == "ip":
        return _normalize_ipv4(value)
    if kind == "ipv6":
        return _normalize_ipv6(value)
    if kind in {"url", "web_site"}:
        return _normalize_url(value)
    if kind == "port":
        return _normalize_port(value)
    if kind == "service":
        return _normalize_service(value)
    if kind == "technology":
        return _normalize_technology(value)
    if kind == "dns_txt":
        return _normalize_dns_txt(value)
    if kind == "tls_endpoint":
        return _normalize_tls_endpoint(value)
    if kind == "web_host":
        return _normalize_web_host(value)
    if kind == "host":
        return _normalize_host_blob_value(value)
    return _normalize_generic(value)


def _normalize_hostname(value, *, extract_url: bool = True) -> str:
    text = _require_text(value, "hostname")

    if extract_url and "://" in text:
        parsed = urlparse(text)
        if not parsed.hostname:
            raise AssetNormalizationError("Hostname is missing from URL.")
        text = parsed.hostname

    text = text.strip().rstrip(".")

    if not text:
        raise AssetNormalizationError("Hostname cannot be empty.")

    if any(char in text for char in "/?#@ "):
        raise AssetNormalizationError("Hostname must not include scheme, path, or port.")

    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None

    if address is not None:
        if address.version == 4:
            return str(address)
        return address.compressed

    if ":" in text:
        raise AssetNormalizationError("Hostname must not include a port.")

    try:
        ascii_name = _idna_hostname(text)
    except UnicodeError as exc:
        raise AssetNormalizationError("Hostname is not a valid IDN.") from exc

    ascii_name = ascii_name.rstrip(".")

    if len(ascii_name) > 253:
        raise AssetNormalizationError("Hostname exceeds 253 characters.")

    labels = ascii_name.split(".")

    if any(not label or not LABEL_RE.match(label) for label in labels):
        raise AssetNormalizationError("Hostname contains an invalid DNS label.")

    return ascii_name[:MAX_ASSET_VALUE_LENGTH]


def _idna_hostname(text: str) -> str:
    labels = text.split(".")
    encoded = []

    for label in labels:
        if label == "*":
            encoded.append("*")
            continue

        encoded.append(label.encode("idna").decode("ascii").lower())

    return ".".join(encoded)


def _normalize_ipv4(value) -> str:
    text = _require_text(value, "IPv4 address")

    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise AssetNormalizationError("Value is not a valid IPv4 address.") from exc

    if address.version != 4:
        raise AssetNormalizationError("Value is not a valid IPv4 address.")

    return str(address)


def _normalize_ipv6(value) -> str:
    text = _require_text(value, "IPv6 address")

    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise AssetNormalizationError("Value is not a valid IPv6 address.") from exc

    if address.version != 6:
        raise AssetNormalizationError("Value is not a valid IPv6 address.")

    return address.compressed


def _normalize_url(value) -> str:
    text = _require_text(value, "URL")
    parsed = urlparse(text)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise AssetNormalizationError("URL scheme must be http or https.")

    if not parsed.hostname:
        raise AssetNormalizationError("URL hostname is missing.")

    try:
        host_part = _url_host(parsed.hostname)
    except AssetNormalizationError as exc:
        raise AssetNormalizationError("URL hostname is invalid.") from exc

    port = parsed.port
    default_port = DEFAULT_PORTS[scheme]
    if port is None or port == default_port:
        netloc = host_part
    else:
        netloc = f"{host_part}:{port}"

    path = parsed.path or "/"
    query = parsed.query

    canonical = urlunparse((scheme, netloc, path, "", query, ""))
    return canonical[:MAX_ASSET_VALUE_LENGTH]


def _url_host(hostname: str) -> str:
    host = _normalize_hostname(hostname, extract_url=False)

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host

    if address.version == 6:
        return f"[{address.compressed}]"

    return str(address)


def _normalize_port(value) -> str:
    if value is None or value == "":
        raise AssetNormalizationError("Port cannot be empty.")

    text = str(value).strip()

    if "/" in text:
        text = text.split("/", 1)[0].strip()

    try:
        port = int(text)
    except (TypeError, ValueError) as exc:
        raise AssetNormalizationError("Port must be an integer.") from exc

    if port < 1 or port > 65535:
        raise AssetNormalizationError("Port must be between 1 and 65535.")

    return str(port)


def _normalize_service(value) -> str:
    text = _collapse_whitespace(value)
    if not text:
        raise AssetNormalizationError("Service name cannot be empty.")
    return text.lower()[:MAX_ASSET_VALUE_LENGTH]


def _normalize_technology(value) -> str:
    text = _collapse_whitespace(value)
    if not text:
        raise AssetNormalizationError("Technology name cannot be empty.")

    lowered = text.lower()
    if lowered in TECHNOLOGY_SKIP:
        raise AssetNormalizationError("Technology name is not meaningful.")

    return lowered[:MAX_ASSET_VALUE_LENGTH]


def _normalize_dns_txt(value) -> str:
    text = _require_text(value, "TXT record")
    if (text.startswith('"') and text.endswith('"')) or (
        text.startswith("'") and text.endswith("'")
    ):
        text = text[1:-1].strip()

    text = unquote(text) if "%" in text[:3] else text

    if not text:
        raise AssetNormalizationError("TXT record cannot be empty.")

    return text[:MAX_ASSET_VALUE_LENGTH]


def _normalize_tls_endpoint(value) -> str:
    text = _require_text(value, "TLS endpoint")

    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname
        port = parsed.port or DEFAULT_TLS_PORT
    elif text.startswith("["):
        closing = text.find("]")
        if closing == -1:
            raise AssetNormalizationError("TLS endpoint IPv6 host is malformed.")
        host = text[1:closing]
        remainder = text[closing + 1 :]
        if remainder.startswith(":"):
            port = remainder[1:]
        elif remainder:
            raise AssetNormalizationError("TLS endpoint is malformed.")
        else:
            port = DEFAULT_TLS_PORT
    else:
        host, separator, port_text = text.rpartition(":")
        if separator and port_text.isdigit() and host:
            port = port_text
        else:
            host = text
            port = DEFAULT_TLS_PORT

    hostname = _normalize_hostname(host, extract_url=False)
    port_value = _normalize_port(port)

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        host_part = hostname
    else:
        if address.version == 6:
            host_part = f"[{address.compressed}]"
        else:
            host_part = str(address)

    return f"{host_part}:{port_value}"[:MAX_ASSET_VALUE_LENGTH]


def _normalize_web_host(value) -> str:
    text = _require_text(value, "web host")

    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname
        port = parsed.port
        if host is None:
            raise AssetNormalizationError("Web host is missing.")
        if port is None:
            return _normalize_hostname(host, extract_url=False)
        return f"{_normalize_hostname(host, extract_url=False)}:{_normalize_port(port)}"

    if ":" in text and not text.startswith("["):
        host, _, port = text.rpartition(":")
        if port.isdigit() and host:
            return f"{_normalize_hostname(host, extract_url=False)}:{_normalize_port(port)}"

    return _normalize_hostname(text, extract_url=False)


def _normalize_host_blob_value(value) -> str:
    text = _require_text(value, "host")
    ip_type, ip_value = normalize_ip(text)
    if ip_value:
        return ip_value
    return _normalize_hostname(text, extract_url=True)


def _normalize_generic(value) -> str:
    text = _require_text(value, "asset")
    return text.lower()[:MAX_ASSET_VALUE_LENGTH]


def _require_text(value, label: str) -> str:
    if value is None:
        raise AssetNormalizationError(f"{label} cannot be empty.")

    text = str(value).strip()
    if not text:
        raise AssetNormalizationError(f"{label} cannot be empty.")

    return text


def _collapse_whitespace(value) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def infer_asset_type(asset: dict) -> str:
    declared = asset.get("type")

    if declared:
        return str(declared).strip().lower() or "unknown"

    if asset.get("url") or asset.get("final_url"):
        return "url"

    if asset.get("addresses") or asset.get("ports"):
        return "host"

    if asset.get("host"):
        return "host"

    return "unknown"


def infer_asset_value(asset: dict) -> str | None:
    kind = infer_asset_type(asset)

    candidates = [
        asset.get("value"),
        asset.get("name"),
        asset.get("url"),
        asset.get("final_url"),
    ]

    host = asset.get("host")
    port = asset.get("port")

    if kind == "tls_endpoint":
        if host:
            port_value = port if port not in (None, "") else DEFAULT_TLS_PORT
            candidates.insert(0, f"{host}:{port_value}")
        candidates.append(host)
    elif kind == "web_host" and host:
        if port not in (None, ""):
            candidates.append(f"{host}:{port}")
        else:
            candidates.append(host)
    elif host and port not in (None, ""):
        candidates.append(f"{host}:{port}")
    else:
        candidates.append(host)

    candidates.append(asset.get("ip"))

    addresses = asset.get("addresses")

    if isinstance(addresses, list) and addresses:
        first = addresses[0]

        if isinstance(first, dict):
            candidates.append(first.get("address"))
        else:
            candidates.append(first)

    for candidate in candidates:
        if candidate is None:
            continue

        canonical = canonical_value(kind, candidate)

        if canonical:
            return canonical

    return None
