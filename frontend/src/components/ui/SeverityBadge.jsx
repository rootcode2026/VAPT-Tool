import { severityClassName, severityLabel } from "@/lib/severity";

export default function SeverityBadge({ severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium ${severityClassName(severity)}`}
    >
      {severityLabel(severity)}
    </span>
  );
}
