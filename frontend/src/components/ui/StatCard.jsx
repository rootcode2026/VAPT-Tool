export default function StatCard({ label, value, hint, unavailable = false }) {
  return (
    <article className="rounded-md border border-border bg-surface p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
      <p
        className={`mt-2 text-2xl font-semibold tabular-nums ${
          unavailable ? "text-muted" : "text-text"
        }`}
      >
        {value}
      </p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </article>
  );
}
