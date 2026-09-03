export const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function normalizeSeverity(value) {
  const key = String(value || "").trim().toLowerCase();
  if (SEVERITY_ORDER.includes(key)) {
    return key;
  }
  return "info";
}

export function severityClassName(value) {
  return `severity-${normalizeSeverity(value)}`;
}

export function severityLabel(value) {
  const key = normalizeSeverity(value);
  return key.charAt(0).toUpperCase() + key.slice(1);
}
