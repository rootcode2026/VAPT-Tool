export default function ErrorState({
  title = "Unable to load security data.",
  message,
  onRetry,
}) {
  return (
    <div className="rounded-md border border-danger/40 bg-danger/10 px-6 py-8 text-center" role="alert">
      <h2 className="text-sm font-semibold text-text">{title}</h2>
      {message ? <p className="mx-auto mt-2 max-w-md text-sm text-muted">{message}</p> : null}
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text transition hover:bg-surface-hover"
        >
          Try again
        </button>
      ) : null}
    </div>
  );
}
