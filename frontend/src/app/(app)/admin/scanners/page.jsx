/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { listScanners, getFleet, listRollouts, triggerScannerHealthCheck, upgradeScanner, downgradeScanner, rollbackScanner, patchScanner } from "@/lib/api/admin";

function StatusBadge({ status }) {
  const map = {
    healthy: "bg-emerald-100 text-emerald-800 border-emerald-200",
    degraded: "bg-amber-100 text-amber-800 border-amber-200",
    unhealthy: "bg-red-100 text-red-800 border-red-200",
    unknown: "bg-gray-100 text-gray-700 border-gray-200",
  };
  const cls = map[status] || map.unknown;
  return <span className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}>{status}</span>;
}

export default function AdminScannersPage() {
  const [scanners, setScanners] = useState([]);
  const [fleet, setFleet] = useState(null);
  const [rollouts, setRollouts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionMsg, setActionMsg] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [s, f, r] = await Promise.all([listScanners(), getFleet().catch(() => null), listRollouts().catch(() => ({ items: [] }))]);
      setScanners(s?.items || []);
      setFleet(f || s?.fleet || null);
      setRollouts(r?.items || []);
    } catch (err) {
      setError(err.message || "Unable to load scanner fleet.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleHealth(key) {
    setActionMsg("");
    try {
      await triggerScannerHealthCheck(key);
      setActionMsg(`Health check triggered for ${key}`);
      load();
    } catch (e) {
      setActionMsg(e.message || "Health check failed");
    }
  }

  async function handleToggle(key, enabled) {
    setActionMsg("");
    try {
      await patchScanner(key, { enabled: !enabled });
      setActionMsg(`${key} ${!enabled ? "enabled" : "disabled"}`);
      load();
    } catch (e) {
      setActionMsg(e.message || "Toggle failed");
    }
  }

  if (loading) {
    return (
      <div>
        <PageHeader title="Scanner Fleet" description="Enterprise scanner control plane — catalog, versions, health, capacity, rollouts." />
        <LoadingState message="Loading scanner fleet..." />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="Scanner Fleet" description="Enterprise scanner control plane." />
        <ErrorState title="Unable to load scanner fleet." message={error} onRetry={load} />
      </div>
    );
  }

  const total = scanners.length || 14;
  const healthy = fleet?.scanners?.healthy ?? scanners.filter((s) => s.health_status === "healthy").length;
  const degraded = fleet?.scanners?.degraded ?? 0;
  const unhealthy = fleet?.scanners?.unhealthy ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader title="Scanner Fleet" description="Enterprise scanner control plane — catalog, versions, health, capacity, rollouts." />

      {actionMsg && <div className="rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800" role="status">{actionMsg}</div>}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="rounded-md border bg-surface p-4">
          <p className="text-xs text-muted">Total Scanners</p>
          <p className="text-2xl font-bold">{total}</p>
          <p className="text-xs text-muted">Ready for 30+ scale</p>
        </div>
        <div className="rounded-md border bg-surface p-4">
          <p className="text-xs text-muted">Healthy</p>
          <p className="text-2xl font-bold text-emerald-700">{healthy}</p>
          <p className="text-xs text-muted">Degraded: {degraded}</p>
        </div>
        <div className="rounded-md border bg-surface p-4">
          <p className="text-xs text-muted">Unhealthy</p>
          <p className="text-2xl font-bold text-red-700">{unhealthy}</p>
          <p className="text-xs text-muted">Isolated, not in profile</p>
        </div>
        <div className="rounded-md border bg-surface p-4">
          <p className="text-xs text-muted">Capacity</p>
          <p className="text-sm font-medium">{fleet ? `${fleet.available_capacity} available / ${fleet.total_capacity} total (buffer ${fleet.reserved_buffer}) — active ${fleet.active_jobs}` : "14 total, buffer 2"}</p>
        </div>
      </div>

      <div className="rounded-md border bg-surface overflow-hidden">
        <div className="border-b bg-canvas px-4 py-3">
          <h3 className="text-sm font-semibold">Scanner Catalog</h3>
          <p className="text-xs text-muted">14 scanners — capabilities, profiles, workspace, version, health, capacity. Unhealthy/disabled excluded from profile selection.</p>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/10 text-xs text-muted">
              <tr>
                <th className="px-3 py-2 text-left">Scanner</th>
                <th className="px-3 py-2 text-left">Category</th>
                <th className="px-3 py-2 text-left">Current</th>
                <th className="px-3 py-2 text-left">Stable</th>
                <th className="px-3 py-2 text-left">Candidate</th>
                <th className="px-3 py-2 text-left">Health</th>
                <th className="px-3 py-2 text-left">Profiles</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scanners.map((s) => (
                <tr key={s.key} className="border-t">
                  <td className="px-3 py-2">
                    <p className="font-medium">{s.name}</p>
                    <p className="text-xs text-muted">{s.key} • {s.family} {s.requires_workspace ? "• workspace" : ""}</p>
                    <p className="text-xs text-muted truncate max-w-[200px]">{s.capabilities?.join(", ")}</p>
                  </td>
                  <td className="px-3 py-2 text-xs">{s.category}</td>
                  <td className="px-3 py-2 text-xs font-mono">{s.current_version || "—"}</td>
                  <td className="px-3 py-2 text-xs font-mono">{s.stable_version || s.current_version || "—"}</td>
                  <td className="px-3 py-2 text-xs font-mono">{s.candidate_version || "—"}</td>
                  <td className="px-3 py-2"><StatusBadge status={s.health_status || "unknown"} /></td>
                  <td className="px-3 py-2 text-xs">{(s.supported_profiles || []).join(", ")}</td>
                  <td className="px-3 py-2 text-xs">{s.enabled ? "Enabled" : "Disabled"}</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      <button onClick={() => handleHealth(s.key)} className="rounded border px-2 py-1 text-xs hover:bg-muted/20" aria-label={`Health check ${s.key}`}>Health Check</button>
                      <button onClick={() => handleToggle(s.key, s.enabled)} className="rounded border px-2 py-1 text-xs hover:bg-muted/20" aria-label={`${s.enabled ? "Disable" : "Enable"} ${s.key}`}>{s.enabled ? "Disable" : "Enable"}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {fleet?.pools && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Worker Pools</h3>
          <p className="text-xs text-muted">Designed for 14 → 15 → 30+ scanners with buffer capacity (1–2 slots).</p>
          <div className="mt-3 grid gap-2 md:grid-cols-3">
            {fleet.pools.map((p) => (
              <div key={p.name} className="rounded border bg-canvas p-3">
                <p className="text-sm font-medium">{p.name}</p>
                <p className="text-xs text-muted">Families: {p.families.join(", ")}</p>
                <p className="text-xs">Capacity {p.total_capacity} • Buffer {p.reserved_buffer} • Available {p.available} • {p.status}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Active Rollouts</h3>
        <p className="text-xs text-muted">Canary → health validation → active / failed → rollback. Previous stable retained.</p>
        {rollouts.length === 0 ? (
          <p className="mt-2 text-xs text-muted">No rollouts yet.</p>
        ) : (
          <div className="mt-3 space-y-2">
            {rollouts.slice(0, 10).map((r) => (
              <div key={r.id} className="rounded border bg-canvas px-3 py-2 text-xs">
                <p className="font-medium">{r.scanner_key} {r.operation} {r.target_version} <StatusBadge status={r.state === "active" ? "healthy" : r.state === "failed" ? "unhealthy" : "unknown"} /> {r.state}</p>
                <p className="text-muted">Previous: {r.previous_version || "—"} • Canary {r.canary_count} • {r.failure_reason || ""}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
        <p className="font-medium">Security</p>
        <p>Scanner execution remains server-controlled (allowlisted images, no arbitrary docker/shell/mounts, no privileged containers, read-only workspace, bounded timeouts). All lifecycle mutations are audited and require Super Admin.</p>
      </div>
    </div>
  );
}
