/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with stale guards */
"use client";

import { useEffect, useState } from "react";
import DashboardSection from "@/components/dashboard/DashboardSection";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import SeverityBadge from "@/components/ui/SeverityBadge";
import StatusBadge from "@/components/ui/StatusBadge";
import {
  acknowledgeAlert,
  getAlert,
  listAlerts,
  resolveAlert,
} from "@/lib/api/alerts";

const STATUS_OPTIONS = ["", "open", "acknowledged", "resolved"];
const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low", "info"];
const TYPE_OPTIONS = [
  "",
  "NEW_CRITICAL_FINDING",
  "NEW_HIGH_FINDING",
  "CRITICAL_FINDING_REOPENED",
  "HIGH_FINDING_REOPENED",
  "CRITICAL_ASSET_EXPOSURE",
  "HIGH_ASSET_EXPOSURE",
  "SECURITY_RELEVANT_ASSET_CHANGE",
  "SECURITY_RELEVANT_RELATIONSHIP_CHANGE",
];

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export function AlertsPanel({ projectId }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [filters, setFilters] = useState({ status: "open", severity: "", alert_type: "" });
  const [detail, setDetail] = useState(null);

  async function load(p = page, f = filters) {
    if (!projectId) return;
    setLoading(true);
    setError("");
    try {
      const data = await listAlerts(projectId, {
        page: p,
        page_size: 15,
        status: f.status || undefined,
        severity: f.severity || undefined,
        alert_type: f.alert_type || undefined,
      });
      setItems(data.items || []);
      setTotal(data.total ?? 0);
    } catch (err) {
      setError(err.message || "Unable to load alerts.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load(1, filters);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  async function act(fn, id, label) {
    setActionError("");
    try {
      await fn(projectId, id);
      await load(page, filters);
      if (detail && detail.id === id) {
        setDetail(await getAlert(projectId, id));
      }
    } catch (err) {
      setActionError(err.message || `Unable to ${label} alert.`);
    }
  }

  return (
    <DashboardSection
      title="Alerts"
      action={<span className="text-xs text-muted">{total} alerts</span>}
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <select value={filters.status} onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))} aria-label="Filter by status" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-xs">
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{s === "" ? "All statuses" : s}</option>
          ))}
        </select>
        <select value={filters.severity} onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))} aria-label="Filter by severity" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-xs">
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>{s === "" ? "All severities" : s}</option>
          ))}
        </select>
        <select value={filters.alert_type} onChange={(e) => setFilters((f) => ({ ...f, alert_type: e.target.value }))} aria-label="Filter by alert type" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-xs">
          {TYPE_OPTIONS.map((t) => (
            <option key={t} value={t}>{t === "" ? "All types" : t.replaceAll("_", " ")}</option>
          ))}
        </select>
        <button type="button" onClick={() => { setPage(1); load(1, filters); }} className="rounded-sm border border-border px-2 py-1.5 text-xs hover:bg-surface-hover">Apply</button>
      </div>
      {actionError ? <p className="mb-2 text-xs text-danger">{actionError}</p> : null}
      {loading ? <p className="text-xs text-muted">Loading alerts...</p> : null}
      {!loading && error ? <ErrorState title="Unable to load alerts." message={error} onRetry={() => load(page, filters)} /> : null}
      {!loading && !error && items.length === 0 ? <EmptyState title="No alerts" description="Alerts appear here when monitored changes meet the project alert policy." /> : null}
      {!loading && !error && items.length > 0 ? (
        <>
          <DataTable
            rowKey={(r) => r.id}
            columns={[
              { key: "severity", header: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
              { key: "title", header: "Alert", render: (r) => <button type="button" onClick={() => setDetail(r)} className="text-left text-xs hover:underline break-all">{r.title}</button> },
              { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
              { key: "event_count", header: "Events", render: (r) => <span className="text-xs">{r.event_count}</span> },
              { key: "last_seen_at", header: "Last seen", render: (r) => <span className="text-xs">{formatWhen(r.last_seen_at)}</span> },
              {
                key: "actions", header: "Actions", render: (r) => (
                  <span className="flex gap-1">
                    {r.status === "open" ? <button type="button" onClick={() => act(acknowledgeAlert, r.id, "acknowledge")} className="rounded-sm border border-border px-2 py-1 text-xs hover:bg-surface-hover">Acknowledge</button> : null}
                    {r.status !== "resolved" ? <button type="button" onClick={() => act(resolveAlert, r.id, "resolve")} className="rounded-sm border border-border px-2 py-1 text-xs hover:bg-surface-hover">Resolve</button> : null}
                  </span>
                ),
              },
            ]}
            rows={items}
          />
          <div className="mt-2 flex items-center justify-between">
            <button type="button" disabled={page <= 1} onClick={() => { const n = page - 1; setPage(n); load(n, filters); }} className="rounded-sm border border-border px-2 py-1 text-xs disabled:opacity-50">Previous</button>
            <button type="button" onClick={() => { const n = page + 1; setPage(n); load(n, filters); }} className="rounded-sm border border-border px-2 py-1 text-xs">Next</button>
          </div>
        </>
      ) : null}
      {detail ? (
        <div className="mt-3 rounded-sm border border-border bg-canvas p-3">
          <p className="text-sm font-medium">{detail.title}</p>
          <p className="mt-1 text-xs text-muted">{detail.description}</p>
          <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
            <dt className="text-muted">Type</dt><dd>{detail.alert_type}</dd>
            <dt className="text-muted">Severity</dt><dd>{detail.severity}</dd>
            <dt className="text-muted">Status</dt><dd>{detail.status}</dd>
            <dt className="text-muted">Events</dt><dd>{detail.event_count}</dd>
            <dt className="text-muted">First seen</dt><dd>{formatWhen(detail.first_seen_at)}</dd>
            <dt className="text-muted">Last seen</dt><dd>{formatWhen(detail.last_seen_at)}</dd>
            <dt className="text-muted">Change event</dt><dd className="break-all">{detail.source_change_event_id || "—"}</dd>
            <dt className="text-muted">Monitoring run</dt><dd className="break-all">{detail.monitoring_run_id || "—"}</dd>
            <dt className="text-muted">Finding</dt><dd className="break-all">{detail.source_finding_id || detail.finding_fingerprint?.slice(0, 16) || "—"}</dd>
            <dt className="text-muted">Asset</dt><dd className="break-all">{detail.source_asset_id || "—"}</dd>
          </dl>
          <button type="button" onClick={() => setDetail(null)} className="mt-2 rounded-sm border border-border px-2 py-1 text-xs hover:bg-surface-hover">Close</button>
        </div>
      ) : null}
    </DashboardSection>
  );
}
