"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import { getAdminDashboardSummary } from "@/lib/api/admin";

function HealthBadge({ status }) {
  const map = {
    Healthy: "bg-emerald-500/10 text-emerald-600 border-emerald-500/20",
    Degraded: "bg-amber-500/10 text-amber-600 border-amber-500/20",
    Unavailable: "bg-red-500/10 text-red-600 border-red-500/20",
    Unknown: "bg-surface text-muted border-border",
  };
  return (
    <span className={`inline-flex rounded-sm border px-2 py-0.5 text-xs font-medium ${map[status] || map.Unknown}`}>
      {status}
    </span>
  );
}

export default function AdminSystemPage() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const data = await getAdminDashboardSummary();
        if (cancelled) return;
        setHealth(data.system_health || {});
      } catch (err) {
        if (cancelled) return;
        setError(err.message || "Unable to load system health.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div>
        <PageHeader title="System Health" description="Backend, Database, Redis, RabbitMQ, Worker health." />
        <LoadingState message="Loading system health..." />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="System Health" description="Backend, Database, Redis, RabbitMQ, Worker health." />
        <ErrorState title="Unable to load system health." message={error} onRetry={() => window.location.reload()} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader title="System Health" description="Backend, Database, Redis, RabbitMQ, Worker health." />

      <div className="grid gap-3 sm:grid-cols-2">
        {Object.entries(health || {}).map(([k, v]) => (
          <div key={k} className="flex items-center justify-between rounded-md border border-border bg-surface p-4">
            <span className="text-sm font-medium capitalize text-text">{k}</span>
            <HealthBadge status={v} />
          </div>
        ))}
      </div>
      <p className="text-xs text-muted">No database URLs, passwords, or credentials exposed. Unknown means no cheap safe probe (by design, no expensive health checks).</p>
    </div>
  );
}
