/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import { IconCopy, IconClose } from "@/components/icons";
import { useAuth } from "@/lib/auth/AuthProvider";
import { useProjectContext } from "@/lib/project-context";
import { listAuditLogs } from "@/lib/api/audit";

const RESULT_STYLES = {
  SUCCESS: "bg-emerald-500/10 text-emerald-600 border-emerald-500/20",
  FAILURE: "bg-red-500/10 text-red-600 border-red-500/20",
  DENIED: "bg-amber-500/10 text-amber-600 border-amber-500/20",
  PARTIAL: "bg-blue-500/10 text-blue-600 border-blue-500/20",
};

function formatTime(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

function truncate(value, len = 12) {
  if (!value) return "—";
  const s = String(value);
  return s.length > len ? `${s.slice(0, len)}…` : s;
}

function CopyButton({ value, label }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-muted">—</span>;
  return (
    <span className="inline-flex items-center gap-1">
      <span className="max-w-[10rem] truncate font-mono text-xs" title={value}>
        {truncate(value, 16)}
      </span>
      <button
        type="button"
        aria-label={`Copy ${label}`}
        title={`Copy ${label}`}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          } catch {}
        }}
        className="inline-flex h-6 w-6 items-center justify-center rounded-sm border border-transparent text-muted hover:border-border hover:bg-surface-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
      >
        <IconCopy className="h-3.5 w-3.5" />
      </button>
      {copied ? <span className="text-xs text-emerald-600">Copied</span> : null}
    </span>
  );
}

function AuditDetailDialog({ event, onClose }) {
  useEffect(() => {
    if (!event) return undefined;
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [event, onClose]);

  if (!event) return null;

  const metaText = event.metadata ? JSON.stringify(event.metadata, null, 2) : "—";
  const truncatedMeta = metaText.length > 4000 ? `${metaText.slice(0, 4000)}\n… truncated` : metaText;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="audit-detail-title"
    >
      <button type="button" className="absolute inset-0 bg-canvas/70" aria-label="Close details" onClick={onClose} />
      <div className="relative max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-md border border-border bg-canvas shadow-lg">
        <div className="sticky top-0 flex items-center justify-between border-b border-border bg-canvas px-4 py-3">
          <h2 id="audit-detail-title" className="text-sm font-semibold text-text">
            Audit Event Details
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="inline-flex h-8 w-8 items-center justify-center rounded-sm border border-border text-muted hover:bg-surface-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            <IconClose className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-3 p-4 text-sm">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <DetailField label="Event ID" value={event.id} mono />
            <DetailField label="Timestamp" value={formatTime(event.created_at)} />
            <DetailField label="Event Type" value={event.event_type} />
            <DetailField label="Action" value={event.action} />
            <DetailField label="Result" value={event.result} badge />
            <DetailField label="Resource" value={event.resource_type ? `${event.resource_type}:${truncate(event.resource_id, 8)}` : "—"} />
            <DetailField label="Resource ID" value={event.resource_id} mono />
            <DetailField label="Organization" value={event.organization_id} mono />
            <DetailField label="Project" value={event.project_id} mono />
            <DetailField label="Actor" value={event.actor_user_id} mono />
            <DetailField label="Target" value={event.target_user_id} mono />
            <DetailField label="Request ID" value={event.request_id} mono copy />
            <DetailField label="Correlation ID" value={event.correlation_id} mono copy />
            <DetailField label="IP Address" value={event.ip_address} />
            <DetailField label="User Agent" value={event.user_agent} />
          </div>
          <div>
            <p className="mb-1 text-xs font-medium text-muted">Sanitized audit metadata</p>
            <pre className="max-h-64 overflow-auto rounded-sm border border-border bg-surface p-3 text-xs text-text">
              {truncatedMeta}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

function DetailField({ label, value, mono, copy, badge }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium text-muted">{label}</p>
      <div className="mt-1 break-words text-sm text-text">
        {badge && value ? (
          <span className={`inline-flex rounded-sm border px-2 py-0.5 text-xs font-medium ${RESULT_STYLES[value] || "border-border bg-surface text-muted"}`}>
            {value}
          </span>
        ) : copy ? (
          <CopyButton value={value} label={label} />
        ) : (
          <span className={mono ? "font-mono text-xs" : ""} title={value || ""}>
            {value ? truncate(value, 36) : "—"}
          </span>
        )}
      </div>
    </div>
  );
}

export default function AuditPage() {
  const { user } = useAuth();
  const { projects, selectedProjectId } = useProjectContext();

  const isSuperAdmin = user?.role === "super_admin";
  const [filters, setFilters] = useState({
    project_id: "",
    event_type: "",
    action: "",
    result: "",
    resource_type: "",
    resource_id: "",
    actor_user_id: "",
    target_user_id: "",
    start_time: "",
    end_time: "",
  });
  const [applied, setApplied] = useState({});
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [data, setData] = useState({ items: [], total: 0, total_pages: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);

  const isPlatformAudit = isSuperAdmin && !applied.project_id;

  const fetchLogs = useCallback(async (nextPage = page, nextApplied = applied) => {
    setLoading(true);
    setError("");
    try {
      const params = {
        page: nextPage,
        page_size: pageSize,
        ...nextApplied,
      };
      // Remove empty
      Object.keys(params).forEach((k) => {
        if (!params[k]) delete params[k];
      });
      const result = await listAuditLogs(params);
      setData(result);
    } catch (err) {
      setError(err.message || "Unable to load audit logs.");
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, applied]);

  // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional fetch on mount/filter change
  useEffect(() => {
    fetchLogs(page, applied);
  }, [fetchLogs, page, applied]);

  const handleApply = () => {
    setApplied({ ...filters });
    setPage(1);
  };

  const handleClear = () => {
    const cleared = {
      project_id: "",
      event_type: "",
      action: "",
      result: "",
      resource_type: "",
      resource_id: "",
      actor_user_id: "",
      target_user_id: "",
      start_time: "",
      end_time: "",
    };
    setFilters(cleared);
    setApplied({});
    setPage(1);
  };

  const handleRefresh = () => fetchLogs(page, applied);

  const totalLabel = data.total ?? 0;
  const filterCount = Object.values(applied).filter(Boolean).length;

  if (error && error.includes("not authorized")) {
    // 403 from backend
  }

  const columns = [
    { key: "created_at", header: "Timestamp", render: (r) => formatTime(r.created_at) },
    { key: "event_type", header: "Event" },
    { key: "action", header: "Action" },
    {
      key: "result",
      header: "Result",
      render: (r) => (
        <span className={`inline-flex rounded-sm border px-2 py-0.5 text-xs font-medium ${RESULT_STYLES[r.result] || "border-border bg-surface text-muted"}`}>
          {r.result}
        </span>
      ),
    },
    { key: "resource_type", header: "Resource", render: (r) => (r.resource_type ? `${r.resource_type}` : "—") },
    { key: "actor_user_id", header: "Actor", render: (r) => truncate(r.actor_user_id, 8) },
    { key: "project_id", header: "Project", render: (r) => truncate(r.project_id, 8) },
    { key: "request_id", header: "Request ID", render: (r) => <CopyButton value={r.request_id} label="Request ID" /> },
    { key: "correlation_id", header: "Correlation ID", render: (r) => <CopyButton value={r.correlation_id} label="Correlation ID" /> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Audit Logs"
        description={isPlatformAudit ? "Platform-wide security and administrative activity." : "Security and administrative activity across the organization."}
        actions={
          <button
            type="button"
            onClick={handleRefresh}
            className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            Refresh
          </button>
        }
      />

      <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
        <span className="rounded-sm border border-border bg-surface px-2 py-1">
          Total: <span className="font-medium text-text">{totalLabel}</span> events
        </span>
        {filterCount > 0 ? (
          <span className="rounded-sm border border-border bg-surface px-2 py-1">
            Filters: <span className="font-medium text-text">{filterCount}</span> active
          </span>
        ) : null}
        {isPlatformAudit ? (
          <span className="rounded-sm border border-primary/20 bg-primary/10 px-2 py-1 font-medium text-primary">Platform Audit</span>
        ) : (
          <span className="rounded-sm border border-border bg-surface px-2 py-1">Organization Audit</span>
        )}
      </div>

      <div className="rounded-md border border-border bg-surface p-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Project</span>
            <select
              value={filters.project_id}
              onChange={(e) => setFilters((f) => ({ ...f, project_id: e.target.value }))}
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            >
              <option value="">All projects</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Event type</span>
            <input
              value={filters.event_type}
              onChange={(e) => setFilters((f) => ({ ...f, event_type: e.target.value }))}
              placeholder="e.g. TARGET_CREATED"
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Action</span>
            <input
              value={filters.action}
              onChange={(e) => setFilters((f) => ({ ...f, action: e.target.value }))}
              placeholder="e.g. SCAN_CREATED"
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Result</span>
            <select
              value={filters.result}
              onChange={(e) => setFilters((f) => ({ ...f, result: e.target.value }))}
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            >
              <option value="">All</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="FAILURE">FAILURE</option>
              <option value="DENIED">DENIED</option>
              <option value="PARTIAL">PARTIAL</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Resource type</span>
            <input
              value={filters.resource_type}
              onChange={(e) => setFilters((f) => ({ ...f, resource_type: e.target.value }))}
              placeholder="e.g. target"
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Resource ID</span>
            <input
              value={filters.resource_id}
              onChange={(e) => setFilters((f) => ({ ...f, resource_id: e.target.value }))}
              placeholder="UUID"
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm font-mono text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Actor</span>
            <input
              value={filters.actor_user_id}
              onChange={(e) => setFilters((f) => ({ ...f, actor_user_id: e.target.value }))}
              placeholder="Actor UUID"
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm font-mono text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Target</span>
            <input
              value={filters.target_user_id}
              onChange={(e) => setFilters((f) => ({ ...f, target_user_id: e.target.value }))}
              placeholder="Target UUID"
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm font-mono text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">Start time</span>
            <input
              type="datetime-local"
              value={filters.start_time}
              onChange={(e) => setFilters((f) => ({ ...f, start_time: e.target.value }))}
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-muted">End time</span>
            <input
              type="datetime-local"
              value={filters.end_time}
              onChange={(e) => setFilters((f) => ({ ...f, end_time: e.target.value }))}
              className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={handleApply}
            className="rounded-sm bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            Apply filters
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            Clear filters
          </button>
        </div>
      </div>

      {loading ? <LoadingState message="Loading audit logs..." /> : null}
      {!loading && error ? (
        <ErrorState
          title={error.includes("not authorized") ? "Access denied" : "Unable to load audit logs."}
          message={error}
          onRetry={handleRefresh}
        />
      ) : null}
      {!loading && !error && data.items.length === 0 ? (
        <EmptyState
          title="No audit events"
          description="No events match the current filters. Try clearing filters or adjusting the time range."
          action={
            <button
              type="button"
              onClick={handleClear}
              className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover"
            >
              Clear filters
            </button>
          }
        />
      ) : null}
      {!loading && !error && data.items.length > 0 ? (
        <>
          <div className="sr-only" aria-live="polite">
            {data.items.length} events loaded
          </div>
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="min-w-full text-left text-sm" role="table" aria-label="Audit logs">
              <thead className="border-b border-border bg-surface-hover text-xs uppercase tracking-wide text-muted">
                <tr>
                  {columns.map((c) => (
                    <th key={c.key} scope="col" className="whitespace-nowrap px-3 py-2.5 font-medium">
                      {c.header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.items.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelected(row)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelected(row);
                      }
                    }}
                    tabIndex={0}
                    role="button"
                    aria-label={`View details for ${row.event_type}`}
                    className="cursor-pointer border-b border-border last:border-0 hover:bg-surface-hover/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary"
                  >
                    {columns.map((c) => (
                      <td key={c.key} className="max-w-[18rem] truncate px-3 py-2.5 text-text">
                        {c.render ? c.render(row) : row[c.key] || "—"}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex flex-col items-center justify-between gap-3 border-t border-border pt-3 sm:flex-row">
            <p className="text-xs text-muted">
              Page <span className="font-medium text-text">{data.page}</span> of{" "}
              <span className="font-medium text-text">{data.total_pages || 1}</span> • {data.total} total
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={data.page <= 1}
                onClick={() => {
                  const next = Math.max(1, data.page - 1);
                  setPage(next);
                }}
                className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={data.page >= (data.total_pages || 1)}
                onClick={() => {
                  const next = Math.min(data.total_pages || 1, data.page + 1);
                  setPage(next);
                }}
                className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : null}

      <AuditDetailDialog event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
