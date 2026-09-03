export default function EmptyState({
  title = "No security data available yet.",
  description,
  action,
}) {
  return (
    <div className="rounded-md border border-dashed border-border bg-surface px-6 py-12 text-center">
      <h2 className="text-sm font-semibold text-text">{title}</h2>
      {description ? <p className="mx-auto mt-2 max-w-md text-sm text-muted">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
