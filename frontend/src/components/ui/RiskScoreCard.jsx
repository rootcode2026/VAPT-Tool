function scoreTone(score) {
  if (score == null || Number.isNaN(Number(score))) {
    return "text-muted";
  }
  const value = Number(score);
  if (value >= 80) return "text-critical";
  if (value >= 60) return "text-high";
  if (value >= 40) return "text-medium";
  if (value >= 20) return "text-low";
  return "text-info";
}

export default function RiskScoreCard({
  score,
  grade,
  label = "Risk score",
  description,
  unavailableLabel = "Not available",
}) {
  const missing = score == null || Number.isNaN(Number(score));
  const display = missing ? unavailableLabel : Number(score);

  return (
    <article className="rounded-md border border-border bg-surface p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tabular-nums ${scoreTone(score)}`}>
        {display}
      </p>
      {grade ? (
        <p className="mt-1 text-sm font-medium text-text">Grade {grade}</p>
      ) : null}
      {description ? <p className="mt-1 text-xs text-muted">{description}</p> : null}
    </article>
  );
}
