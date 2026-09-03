import { SEVERITY_ORDER, severityClassName, severityLabel } from "@/lib/severity";

export default function SeverityDistribution({ counts }) {
  const total = SEVERITY_ORDER.reduce(
    (sum, key) => sum + (Number(counts?.[key]) || 0),
    0
  );

  return (
    <div
      className="space-y-3"
      role="img"
      aria-label={`Finding severity distribution. Total ${total}. ${SEVERITY_ORDER.map(
        (key) => `${severityLabel(key)} ${counts?.[key] || 0}`
      ).join(", ")}`}
    >
      {SEVERITY_ORDER.map((key) => {
        const value = Number(counts?.[key]) || 0;
        const width = total > 0 ? Math.max((value / total) * 100, value > 0 ? 2 : 0) : 0;
        return (
          <div key={key}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="font-medium text-text">{severityLabel(key)}</span>
              <span className="tabular-nums text-muted">{value}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-sm bg-surface-hover">
              <div
                className={`h-full rounded-sm border ${severityClassName(key)}`}
                style={{ width: `${width}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
