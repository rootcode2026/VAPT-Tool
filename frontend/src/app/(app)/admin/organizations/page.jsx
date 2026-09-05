"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import DataTable from "@/components/ui/DataTable";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { getAdminOrganizationsSummary } from "@/lib/api/admin";

export default function AdminOrganizationsPage() {
  const [data, setData] = useState({ items: [], total: 0, total_pages: 0, page: 1, page_size: 20 });
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const result = await getAdminOrganizationsSummary({ page, page_size: 20 });
        if (cancelled) return;
        setData(result);
      } catch (err) {
        if (cancelled) return;
        setError(err.message || "Unable to load organizations.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [page]);

  if (loading) {
    return (
      <div>
        <PageHeader title="Organizations" description="Platform organization inventory — read-only." />
        <LoadingState message="Loading organizations..." />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="Organizations" description="Platform organization inventory — read-only." />
        <ErrorState title="Unable to load organizations." message={error} onRetry={() => setPage((p) => p)} />
      </div>
    );
  }

  if (data.items.length === 0) {
    return (
      <div>
        <PageHeader title="Organizations" description="Platform organization inventory — read-only." />
        <EmptyState title="No organizations" description="No organizations available." />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader title="Organizations" description="Platform organization inventory — read-only." />

      <DataTable
        rowKey={(r) => r.id}
        columns={[
          { key: "name", header: "Organization" },
          { key: "slug", header: "Slug" },
          { key: "projects", header: "Projects" },
          { key: "members", header: "Members" },
          { key: "open_findings", header: "Open Findings" },
          { key: "critical_findings", header: "Critical" },
          { key: "assets", header: "Assets" },
          { key: "active_scans", header: "Active Scans" },
        ]}
        rows={data.items}
      />

      <div className="flex flex-col items-center justify-between gap-3 border-t border-border pt-3 sm:flex-row">
        <p className="text-xs text-muted">
          Page <span className="font-medium text-text">{data.page}</span> of <span className="font-medium text-text">{data.total_pages || 1}</span> • {data.total} total
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={data.page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            Previous
          </button>
          <button
            type="button"
            disabled={data.page >= (data.total_pages || 1)}
            onClick={() => setPage((p) => Math.min(data.total_pages || 1, p + 1))}
            className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            Next
          </button>
        </div>
      </div>
      <p className="text-xs text-muted">No passwords, tokens, or sensitive finding evidence exposed. Lifecycle management in Phase 7B.</p>
    </div>
  );
}
