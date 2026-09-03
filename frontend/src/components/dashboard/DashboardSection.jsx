export default function DashboardSection({ title, action, children }) {
  return (
    <section className="rounded-md border border-border bg-surface p-4 sm:p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-text">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}
