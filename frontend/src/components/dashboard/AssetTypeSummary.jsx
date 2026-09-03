function formatAssetType(type) {
  const labels = {
    domain: "Domains",
    subdomain: "Subdomains",
    ip: "IPs",
    ipv6: "IPv6",
    url: "URLs",
    port: "Ports",
    service: "Services",
    technology: "Technologies",
    hostname: "Hostnames",
    host: "Hosts",
    web_site: "Web sites",
    web_host: "Web hosts",
    tls_endpoint: "TLS endpoints",
  };
  return labels[type] || type.replaceAll("_", " ");
}

export default function AssetTypeSummary({ counts }) {
  const entries = Object.entries(counts || {}).sort((left, right) => right[1] - left[1]);

  return (
    <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {entries.map(([type, count]) => (
        <li
          key={type}
          className="rounded-sm border border-border bg-canvas px-3 py-3"
        >
          <p className="text-xs text-muted">{formatAssetType(type)}</p>
          <p className="mt-1 text-xl font-semibold tabular-nums text-text">{count}</p>
        </li>
      ))}
    </ul>
  );
}
