/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with stale guards */
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import DashboardSection from "@/components/dashboard/DashboardSection";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import {
  createMonitoringConfig,
  deleteMonitoringConfig,
  listAttackSurfaceChanges,
  listMonitoringConfigs,
  listMonitoringRuns,
  runMonitoringConfig,
  updateMonitoringConfig,
} from "@/lib/api/assets";

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export function AttackSurfaceChanges({ projectId }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [changeType, setChangeType] = useState("");

  async function load(p = page, ct = changeType) {
    if (!projectId) return;
    setLoading(true);
    setError("");
    try {
      const data = await listAttackSurfaceChanges(projectId, { page: p, page_size: 10, change_type: ct || undefined });
      setItems(data.items || []);
      setTotal(data.total ?? 0);
    } catch (err) {
      setError(err.message || "Unable to load changes.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load(1, changeType);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  return (
    <DashboardSection
      title="Recent Changes"
      action={<span className="text-xs text-muted">{total} events (7d window in summary)</span>}
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <select value={changeType} onChange={(e) => setChangeType(e.target.value)} className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-xs" aria-label="Filter by change type">
          <option value="">All change types</option>
          {["discovered", "changed", "stale", "inactive", "exposure_increased", "exposure_decreased"].map((c) => (
            <option key={c} value={c}>{c.replaceAll("_", " ")}</option>
          ))}
        </select>
        <button type="button" onClick={() => { setPage(1); load(1, changeType); }} className="rounded-sm border border-border px-2 py-1.5 text-xs hover:bg-surface-hover">Apply</button>
      </div>
      {loading ? <p className="text-xs text-muted">Loading changes...</p> : null}
      {!loading && error ? <ErrorState title="Unable to load changes." message={error} onRetry={() => load(page, changeType)} /> : null}
      {!loading && !error && items.length === 0 ? <EmptyState title="No changes" description="No asset or exposure changes recorded for this project yet." /> : null}
      {!loading && !error && items.length > 0 ? (
        <>
          <DataTable
            rowKey={(r) => r.id}
            columns={[
              { key: "change_type", header: "Change" },
              { key: "asset", header: "Asset", render: (r) => <Link href={r.asset_id ? `/assets/${r.asset_id}` : "#"} className="text-xs hover:underline break-all">{r.asset_value || r.asset_id}</Link> },
              { key: "source", header: "Source", render: (r) => <span className="text-xs">{r.scanner || r.source || "—"}</span> },
              { key: "detected_at", header: "Detected", render: (r) => <span className="text-xs">{formatWhen(r.detected_at)}</span> },
            ]}
            rows={items}
          />
          <div className="mt-2 flex items-center justify-between">
            <button type="button" disabled={page <= 1} onClick={() => { const n = page - 1; setPage(n); load(n, changeType); }} className="rounded-sm border border-border px-2 py-1 text-xs disabled:opacity-50">Previous</button>
            <button type="button" onClick={() => { const n = page + 1; setPage(n); load(n, changeType); }} className="rounded-sm border border-border px-2 py-1 text-xs">Next</button>
          </div>
        </>
      ) : null}
    </DashboardSection>
  );
}

export function MonitoringPanel({ projectId }) {
  const [configs, setConfigs] = useState([]);
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ name: "", frequency: "daily", profile: "quick" });
  const [actionError, setActionError] = useState("");

  async function load() {
    if (!projectId) return;
    setLoading(true);
    setError("");
    try {
      const [c, r] = await Promise.all([
        listMonitoringConfigs(projectId),
        listMonitoringRuns(projectId, { page: 1, page_size: 5 }),
      ]);
      setConfigs(c.items || []);
      setRuns(r.items || []);
    } catch (err) {
      setError(err.message || "Unable to load monitoring.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  async function handleCreate(e) {
    e.preventDefault();
    setActionError("");
    if (!form.name.trim()) {
      setActionError("Name is required.");
      return;
    }
    try {
      await createMonitoringConfig(projectId, { name: form.name.trim().slice(0, 255), frequency: form.frequency, profile: form.profile });
      setForm({ name: "", frequency: "daily", profile: "quick" });
      await load();
    } catch (err) {
      setActionError(err.message || "Unable to create monitor.");
    }
  }

  async function handleRun(configId) {
    setActionError("");
    try {
      await runMonitoringConfig(configId);
      await load();
    } catch (err) {
      setActionError(err.message || "Unable to run monitor.");
    }
  }

  async function handleToggle(cfg) {
    setActionError("");
    try {
      await updateMonitoringConfig(cfg.id, { enabled: !cfg.enabled });
      await load();
    } catch (err) {
      setActionError(err.message || "Unable to update monitor.");
    }
  }

  async function handleDelete(configId) {
    if (!window.confirm("Delete this monitoring configuration? Run history is preserved in audit logs.")) return;
    setActionError("");
    try {
      await deleteMonitoringConfig(configId);
      await load();
    } catch (err) {
      setActionError(err.message || "Unable to delete monitor.");
    }
  }

  return (
    <DashboardSection title="Continuous Monitoring" action={<span className="text-xs text-muted">Manual runs; recurring scheduler deferred</span>}>
      {loading ? <p className="text-xs text-muted">Loading monitoring...</p> : null}
      {!loading && error ? <ErrorState title="Unable to load monitoring." message={error} onRetry={load} /> : null}
      {!loading && !error ? (
        <>
          {actionError ? <p className="mb-2 text-xs text-red-400" role="alert">{actionError}</p> : null}
          <form onSubmit={handleCreate} className="grid gap-2 sm:grid-cols-4">
            <input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="Monitor name" maxLength={255} aria-label="Monitor name" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm" />
            <select value={form.frequency} onChange={(e) => setForm((f) => ({ ...f, frequency: e.target.value }))} aria-label="Frequency" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm">
              <option value="hourly">hourly</option>
              <option value="daily">daily</option>
              <option value="weekly">weekly</option>
            </select>
            <select value={form.profile} onChange={(e) => setForm((f) => ({ ...f, profile: e.target.value }))} aria-label="Profile" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm">
              <option value="quick">quick</option>
              <option value="web">web</option>
              <option value="full">full</option>
            </select>
            <button type="submit" className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground">Create</button>
          </form>
          {configs.length === 0 ? <p className="mt-3 text-xs text-muted">No monitors configured. Create one to track exposure changes.</p> : (
            <ul className="mt-3 space-y-2">
              {configs.map((c) => (
                <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 rounded-sm border border-border bg-canvas px-3 py-2">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{c.name} <span className="text-xs text-muted">• {c.frequency} • {c.profile} • {c.enabled ? "enabled" : "disabled"}</span></p>
                    {c.last_run ? <p className="text-xs text-muted">Last run: {c.last_run.status} {c.last_run.created_at ? `• ${formatWhen(c.last_run.created_at)}` : ""}</p> : <p className="text-xs text-muted">Never run — first run establishes the baseline.</p>}
                  </div>
                  <div className="flex gap-1">
                    <button type="button" onClick={() => handleRun(c.id)} className="rounded-sm border border-border px-2 py-1 text-xs hover:bg-surface-hover">Run now</button>
                    <button type="button" onClick={() => handleToggle(c)} className="rounded-sm border border-border px-2 py-1 text-xs hover:bg-surface-hover">{c.enabled ? "Disable" : "Enable"}</button>
                    <button type="button" onClick={() => handleDelete(c.id)} className="rounded-sm border border-border px-2 py-1 text-xs hover:bg-surface-hover">Delete</button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {runs.length > 0 ? (
            <div className="mt-3">
              <p className="text-xs font-medium text-muted">Recent runs</p>
              <ul className="mt-1 space-y-1">
                {runs.slice(0, 5).map((r) => (
                  <li key={r.id} className="flex justify-between rounded-sm border border-border bg-canvas px-3 py-1.5 text-xs">
                    <span>{r.status} • discovered {r.assets_discovered} • changed {r.assets_changed} • stale {r.assets_stale}</span>
                    <span className="text-muted">{formatWhen(r.created_at)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <p className="mt-2 text-xs text-muted">Schedules are configured and persisted; production recurring execution is deferred to the monitoring scheduler phase.</p>
        </>
      ) : null}
    </DashboardSection>
  );
}
