const STATUS_STYLES = {
  active: "border-success/40 bg-success/10 text-success",
  inactive: "border-border bg-surface-hover text-muted",
  queued: "border-warning/40 bg-warning/10 text-warning",
  pending: "border-warning/40 bg-warning/10 text-warning",
  running: "border-info/40 bg-info/10 text-info",
  scanning: "border-info/40 bg-info/10 text-info",
  completed: "border-success/40 bg-success/10 text-success",
  success: "border-success/40 bg-success/10 text-success",
  failed: "border-danger/40 bg-danger/10 text-danger",
  error: "border-danger/40 bg-danger/10 text-danger",
  cancelled: "border-border bg-surface-hover text-muted",
  canceled: "border-border bg-surface-hover text-muted",
};

function formatStatus(value) {
  const raw = String(value || "unknown").replaceAll("_", " ");
  return raw.charAt(0).toUpperCase() + raw.slice(1);
}

export default function StatusBadge({ status }) {
  const key = String(status || "").toLowerCase();
  const style = STATUS_STYLES[key] || "border-border bg-surface-hover text-muted";

  return (
    <span className={`inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium ${style}`}>
      {formatStatus(status)}
    </span>
  );
}
