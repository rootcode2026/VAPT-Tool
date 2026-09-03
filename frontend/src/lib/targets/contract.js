export const SCAN_TARGET_TYPES = [
  {
    value: "domain",
    label: "Domain",
    description: "A hostname to assess, such as example.com.",
  },
  {
    value: "url",
    label: "URL",
    description: "An http or https endpoint to assess.",
  },
  {
    value: "ip",
    label: "IP address",
    description: "An IPv4 or IPv6 address to assess.",
  },
];

const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
const IPV4_PATTERN =
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function isValidIPv6(value) {
  try {
    const url = new URL(`http://[${value}]`);
    return Boolean(url.hostname);
  } catch {
    return false;
  }
}

export function validateTargetValue(type, rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) {
    return "Enter a target value.";
  }

  if (type === "domain") {
    if (value.includes("://") || value.includes("/")) {
      return "Enter a hostname such as example.com, not a URL.";
    }
    if (!DOMAIN_PATTERN.test(value)) {
      return "Enter a valid domain name.";
    }
    return "";
  }

  if (type === "url") {
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return "URL must start with http:// or https://.";
      }
      if (!parsed.hostname) {
        return "Enter a valid http or https URL.";
      }
      return "";
    } catch {
      return "Enter a valid http or https URL.";
    }
  }

  if (type === "ip") {
    if (IPV4_PATTERN.test(value) || isValidIPv6(value)) {
      return "";
    }
    return "Enter a valid IPv4 or IPv6 address.";
  }

  return "Select a supported target type.";
}
