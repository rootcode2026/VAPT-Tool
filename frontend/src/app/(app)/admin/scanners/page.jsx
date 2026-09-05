"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { getAdminDashboardSummary } from "@/lib/api/admin";

export default function AdminScannersPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const result = await getAdminDashboardSummary();
        if (cancelled) return;
        setData(result);
      } catch (err) {
        if (cancelled) return;
        setError(err.message || "Unable to load scanner fleet.");
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
        <PageHeader title="Scanner Fleet" description="Registered scanners and operational overview." />
        <LoadingState message="Loading scanner fleet..." />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="Scanner Fleet" description="Registered scanners and operational overview." />
        <ErrorState title="Unable to load scanner fleet." message={error} onRetry={() => window.location.reload()} />
      </div>
    );
  }

  const scanners = data?.scanners?.names || [];
  const total = data?.scanners?.total ?? 14;

  return (
    <div className="space-y-4">
      <PageHeader title="Scanner Fleet" description="Registered scanners and operational overview." />

      <div className="rounded-md border border-border bg-surface p-4">
        <p className="text-sm font-medium text-text">Registered scanners: {total}</p>
        <p className="mt-1 text-xs text-muted">Baseline 14 scanners — future Scanner Control Plane will handle stable/candidate versions, health, upgrade/downgrade/rollback, canary, worker pools, capacity, 30+ fleet.</p>
        {scanners.length ? (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {scanners.map((n) => (
              <span key={n} className="rounded-sm border border-border bg-canvas px-2 py-1 text-xs font-medium">
                {n}
              </span>
            ))}
          </div>
        ) : (
          <p className="mt-3 text-xs text-muted">Scanner names not available yet.</p>
        )}
      </div>

      <EmptyState title="Scanner Control Plane — future phase" description="Stable/candidate versions, health, upgrade/downgrade/rollback, canary, worker pools, capacity, and 30+ scanner readiness will be available in a future phase. Current view is operational overview only." />
    </div>
  );
}
