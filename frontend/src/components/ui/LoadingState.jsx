export default function LoadingState({ message = "Loading security data..." }) {
  return (
    <div className="flex items-center justify-center rounded-md border border-border bg-surface px-6 py-12" role="status" aria-live="polite">
      <div className="text-center">
        <div className="mx-auto h-6 w-6 animate-pulse rounded-full border-2 border-border border-t-primary" />
        <p className="mt-3 text-sm text-muted">{message}</p>
      </div>
    </div>
  );
}
