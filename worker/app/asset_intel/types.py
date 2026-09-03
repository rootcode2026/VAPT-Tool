"""
Asset type contract.

Canonical types
---------------
domain       Apex or scanned zone hostname.
subdomain    Hostname strictly under a known parent zone.
ip           IPv4 address.
ipv6         IPv6 address (canonical compressed form).
url          HTTP(S) endpoint (scheme, host, port, path, query).
port         Transport port number as a decimal string.
service      Network service name (for example http, https).
technology   Application/server technology name (for example nginx).
hostname     Generic hostname when domain vs subdomain is not known.
dns_cname    DNS CNAME owner hostname.
dns_mx       MX mail hostname.
dns_ns       Nameserver hostname.
dns_txt      TXT record payload.
dns_soa      SOA primary nameserver (MNAME).

Compatibility types (preserved so existing rows stay valid)
------------------------------------------------------------
host           Nmap host blob (addresses/ports) persisted as a unit.
web_site       ZAP site record.
web_host       Nikto host record.
tls_endpoint   testssl.sh endpoint (host:port identity).

Relationship types
------------------
contains     Parent hostname contains a child hostname.
resolves_to  Hostname/domain resolves to an IP address.
points_to    DNS hostname points to another hostname (CNAME, MX, NS).
exposes      Host/IP exposes a network port.
runs         Port runs a service.
serves       URL serves a technology.
uses         Hostname uses a TLS endpoint.
observed_on  Asset/evidence was observed on a host or URL.

Relationship metadata (JSONB)
-----------------------------
sources      Scanner names that observed the edge (unique, ordered).
confidence   Discrete high | medium | low. Does not affect risk scoring.
evidence     Bounded facts (record_type, observed_value, protocol, ...).
"""

CANONICAL_ASSET_TYPES = frozenset(
    {
        "domain",
        "subdomain",
        "ip",
        "ipv6",
        "url",
        "port",
        "service",
        "technology",
        "hostname",
        "dns_cname",
        "dns_mx",
        "dns_ns",
        "dns_txt",
        "dns_soa",
    }
)

COMPAT_ASSET_TYPES = frozenset(
    {
        "host",
        "web_site",
        "web_host",
        "tls_endpoint",
        "unknown",
    }
)

KNOWN_ASSET_TYPES = CANONICAL_ASSET_TYPES | COMPAT_ASSET_TYPES

HOSTNAME_TYPES = frozenset(
    {
        "domain",
        "subdomain",
        "hostname",
        "dns_cname",
        "dns_mx",
        "dns_ns",
        "dns_soa",
    }
)

RELATIONSHIP_TYPES = frozenset(
    {
        "contains",
        "resolves_to",
        "points_to",
        "exposes",
        "runs",
        "serves",
        "uses",
        "observed_on",
    }
)

TECHNOLOGY_SKIP = frozenset(
    {
        "",
        "*",
        "unknown",
        "other",
        "n/a",
        "none",
    }
)
