import pytest

from app.asset_intel.normalize import (
    AssetNormalizationError,
    canonical_asset_identity,
    canonical_value,
    normalize_dns_txt,
    normalize_hostname,
    normalize_ipv4,
    normalize_ipv6,
    normalize_port,
    normalize_service,
    normalize_technology,
    normalize_tls_endpoint,
    normalize_url,
)


def test_domain_case_normalization():
    assert canonical_asset_identity("domain", "Example.COM") == "example.com"


def test_domain_trailing_dot_removal():
    assert canonical_asset_identity("domain", "example.com.") == "example.com"


def test_domain_whitespace_and_idn_are_deterministic():
    assert canonical_asset_identity("domain", "  Example.COM.  ") == "example.com"
    punycode = canonical_asset_identity("domain", "münchen.example")
    assert punycode == "xn--mnchen-3ya.example"
    assert canonical_asset_identity("domain", punycode) == punycode


def test_malformed_domain_rejection():
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("domain", "not a domain")
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("domain", "example..com")
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("domain", "-example.com")
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("domain", "example.com:443")
    assert canonical_value("domain", "example..com") is None
    assert normalize_hostname("not a domain") == ""


def test_subdomain_normalizes_like_domain():
    assert canonical_asset_identity(
        "subdomain",
        "API.Example.COM.",
    ) == canonical_asset_identity("domain", "api.example.com")


def test_ipv4_normalization():
    assert normalize_ipv4("  192.0.2.10  ") == "192.0.2.10"
    assert canonical_asset_identity("ip", "192.0.2.10") == "192.0.2.10"
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("ip", "999.0.0.1")
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("ip", "2001:db8::1")


def test_ipv6_compression():
    assert (
        normalize_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001")
        == "2001:db8::1"
    )
    assert canonical_asset_identity(
        "ipv6",
        "2001:db8:0:0:0:0:0:1",
    ) == canonical_asset_identity("ipv6", "2001:db8::1")
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("ipv6", "192.0.2.10")


def test_url_scheme_and_host_normalization():
    assert (
        normalize_url("HTTPS://Example.COM:443/")
        == "https://example.com/"
    )


def test_url_default_port_removal():
    assert canonical_asset_identity("url", "https://example.com:443/") == (
        "https://example.com/"
    )
    assert canonical_asset_identity("url", "http://example.com:80/login") == (
        "http://example.com/login"
    )


def test_url_non_default_port_preservation():
    assert (
        normalize_url("https://Example.COM:8443/")
        == "https://example.com:8443/"
    )


def test_url_fragment_removal():
    assert (
        canonical_asset_identity("url", "https://example.com/path#section")
        == "https://example.com/path"
    )


def test_url_credential_removal():
    canonical = normalize_url("https://user:secret@example.com/path")
    assert canonical == "https://example.com/path"
    assert "user" not in canonical
    assert "secret" not in canonical


def test_url_path_preservation():
    assert canonical_asset_identity("url", "https://example.com/api/v1") == (
        "https://example.com/api/v1"
    )
    assert canonical_asset_identity("url", "https://example.com/api") != (
        canonical_asset_identity("url", "https://example.com/login")
    )


def test_url_query_preservation():
    assert canonical_asset_identity(
        "url",
        "https://example.com/search?q=vapt&page=2#top",
    ) == "https://example.com/search?q=vapt&page=2"


def test_url_empty_path_is_normalized_consistently():
    assert canonical_asset_identity("url", "https://example.com") == (
        "https://example.com/"
    )
    assert canonical_asset_identity("url", "HTTPS://Example.COM:443") == (
        "https://example.com/"
    )


def test_invalid_url_rejection():
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("url", "not-a-url")
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("url", "ftp://example.com/")
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("url", "https://")
    assert canonical_value("url", "javascript:alert(1)") is None


def test_port_validation():
    assert canonical_asset_identity("port", 443) == "443"
    assert canonical_asset_identity("port", "443/tcp") == "443"
    assert normalize_port("80") == "80"
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("port", 0)
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("port", 65536)
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("port", "http")
    assert canonical_value("port", "0") is None


def test_service_normalization():
    assert canonical_asset_identity("service", "  HTTP  ") == "http"
    assert canonical_asset_identity("service", "SSL/HTTP") == "ssl/http"
    assert normalize_service("HTTPS") == "https"


def test_technology_normalization_preserves_version():
    assert canonical_asset_identity("technology", "Nginx") == "nginx"
    assert canonical_asset_identity("technology", "nginx/1.24.0") == "nginx/1.24.0"
    assert canonical_asset_identity(
        "technology",
        "  Apache   HTTP   Server  2.4  ",
    ) == "apache http server 2.4"
    assert canonical_value("technology", "unknown") is None
    assert normalize_technology("*") == ""


def test_tls_endpoint_normalization():
    assert canonical_asset_identity("tls_endpoint", "Example.COM") == (
        "example.com:443"
    )
    assert canonical_asset_identity("tls_endpoint", "example.com:443") == (
        "example.com:443"
    )
    assert canonical_asset_identity("tls_endpoint", "example.com:8443") == (
        "example.com:8443"
    )
    assert normalize_tls_endpoint("HTTPS://Example.COM") == "example.com:443"


def test_dns_record_normalization():
    assert canonical_asset_identity("dns_cname", "WWW.Example.COM.") == (
        "www.example.com"
    )
    assert canonical_asset_identity("dns_mx", "MAIL.Example.COM.") == (
        "mail.example.com"
    )
    assert canonical_asset_identity("dns_ns", "NS1.Example.COM.") == (
        "ns1.example.com"
    )
    assert canonical_asset_identity("dns_soa", "NS1.Example.COM.") == (
        "ns1.example.com"
    )
    assert canonical_asset_identity("dns_txt", '  "v=spf1 -all"  ') == "v=spf1 -all"
    assert normalize_dns_txt("v=spf1 -all") == "v=spf1 -all"
    with pytest.raises(AssetNormalizationError):
        canonical_asset_identity("dns_txt", "   ")


def test_hostname_uses_hostname_rules():
    assert canonical_asset_identity("hostname", "Example.COM.") == "example.com"
    assert canonical_asset_identity(
        "hostname",
        "https://Example.COM./login",
    ) == "example.com"


def test_canonical_identity_is_consistent():
    left = canonical_asset_identity("domain", "Example.COM.")
    right = canonical_asset_identity("domain", " example.com ")
    assert left == right
    assert canonical_value("url", "HTTPS://Example.COM:443/") == (
        canonical_asset_identity("url", "https://example.com/")
    )
    assert canonical_value("ipv6", "2001:0db8::1") == (
        canonical_asset_identity("ipv6", "2001:db8::1")
    )
