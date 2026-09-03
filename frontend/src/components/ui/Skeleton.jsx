export function Skeleton({ className = "" }) {
  return (
    <div
      className={`animate-pulse rounded-sm bg-surface-hover ${className}`}
      aria-hidden="true"
    />
  );
}

export function SkeletonTable({ rows = 5 }) {
  return (
    <div className="space-y-2" role="status" aria-label="Loading table">
      <Skeleton className="h-10 w-full" />
      {Array.from({ length: rows }).map((_, index) => (
        <Skeleton key={index} className="h-12 w-full" />
      ))}
    </div>
  );
}

export function SkeletonCards({ count = 4 }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" role="status" aria-label="Loading cards">
      {Array.from({ length: count }).map((_, index) => (
        <Skeleton key={index} className="h-24 w-full" />
      ))}
    </div>
  );
}
