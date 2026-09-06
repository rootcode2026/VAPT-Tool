/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { useProjectContext } from "@/lib/project-context";
import { createDastConfig, getDastConfig, createDastScan, listDastEndpoints, listDastScans } from "@/lib/api/dast";

export default function DastPage() {
  const { selectedProjectId, status } = useProjectContext();
  const [config, setConfig] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ profile: "web", target_id: "", allowed_domains: "", active_testing_enabled: false, database_testing_enabled: false, auth_secret: "" });
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [cfg, eps, sc] = await Promise.all([
        getDastConfig(selectedProjectId).catch(() => null),
        listDastEndpoints(selectedProjectId).catch(() => ({ endpoints: [] })),
        listDastScans(selectedProjectId).catch(() => ({ scans: [] })),
      ]);
      setConfig(cfg);
      setEndpoints(eps.endpoints || []);
      setScans(sc.scans || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    if (status === "ready" && selectedProjectId) load();
  }, [status, selectedProjectId, load]);

  async function handleCreateConfig() {
    setMsg("");
    try {
      await createDastConfig(selectedProjectId, {
        profile: form.profile,
        target_id: form.target_id || undefined,
        allowed_domains: form.allowed_domains ? form.allowed_domains.split(",").map((s) => s.trim()).filter(Boolean) : [],
        active_testing_enabled: form.active_testing_enabled,
        database_testing_enabled: form.database_testing_enabled,
        auth_secret: form.auth_secret || undefined,
      });
      setMsg("Config created");
      load();
    } catch (e) {
      setMsg(e.message);
    }
  }

  async function handleStartScan() {
    setMsg("");
    try {
      await createDastScan(selectedProjectId, {});
      setMsg("Scan queued");
      load();
    } catch (e) {
      setMsg(e.message);
    }
  }

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project" description="Select a project" />;
  if (loading) return <div><PageHeader title="DAST" description="Advanced DAST — authenticated, bounded, safe" /><LoadingState message="Loading DAST..." /></div>;
  if (error) return <div><PageHeader title="DAST" /><ErrorState title="Error" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Advanced DAST" description="Authenticated, active testing with safety policy (rate limit, SSRF protection, bounded requests)" />

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">DAST Configuration</h3>
        <p className="text-xs text-muted">Profiles: quick (safe), web (passive), api, api_authenticated (requires auth), advanced_dast (active), database_security (SQLmap, requires project_admin, explicit confirmation). Server-side policy always wins.</p>
        {config ? (
          <div className="mt-2 rounded bg-canvas p-3 text-xs">
            <p>Profile: {config.profile} • Active: {config.active_testing_enabled} • DB: {config.database_testing_enabled}</p>
            <p>Max endpoints: {config.max_endpoints} • Max requests: {config.max_requests} • Rate: {config.rate_limit}/s</p>
            <p>Auth: {config.auth_configured ? "configured" : "not configured"} (never displayed)</p>
          </div>
        ) : <p className="mt-2 text-xs text-muted">No config yet.</p>}
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <select value={form.profile} onChange={(e) => setForm((f) => ({ ...f, profile: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm">
            <option value="web">web (passive)</option><option value="api">api</option><option value="api_authenticated">api_authenticated</option><option value="advanced_dast">advanced_dast (active)</option><option value="database_security">database_security (SQLmap)</option>
          </select>
          <input placeholder="Target ID (must be project target)" value={form.target_id} onChange={(e) => setForm((f) => ({ ...f, target_id: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <input placeholder="Allowed domains comma-separated" value={form.allowed_domains} onChange={(e) => setForm((f) => ({ ...f, allowed_domains: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <input type="password" placeholder="Auth secret (bearer/api-key, stored encrypted)" value={form.auth_secret} onChange={(e) => setForm((f) => ({ ...f, auth_secret: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={form.active_testing_enabled} onChange={(e) => setForm((f) => ({ ...f, active_testing_enabled: e.target.checked }))} /> Active testing enabled</label>
          <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={form.database_testing_enabled} onChange={(e) => setForm((f) => ({ ...f, database_testing_enabled: e.target.checked }))} /> Database testing enabled (requires confirmation)</label>
        </div>
        {form.database_testing_enabled ? <p className="mt-2 text-xs font-medium text-red-600">ACTIVE DATABASE SECURITY TESTING CAN GENERATE SIGNIFICANT TRAFFIC AND MUST ONLY BE USED AGAINST AUTHORIZED TARGETS.</p> : null}
        <button type="button" onClick={handleCreateConfig} className="mt-3 rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Save Config</button>
        <button type="button" onClick={handleStartScan} className="ml-2 rounded border px-3 py-1 text-sm">Start Scan</button>
        {msg ? <p className="mt-2 text-xs text-muted">{msg}</p> : null}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Endpoints ({endpoints.length})</h3>
        <p className="text-xs text-muted">Discovered via target/heuristics, bounded to allowed domains, SSRF protected.</p>
        {endpoints.length === 0 ? <p className="mt-2 text-xs text-muted">No endpoints yet.</p> : <ul className="mt-2 space-y-1 text-xs">{endpoints.map((e) => <li key={e.id} className="rounded border bg-canvas px-2 py-1">{e.method} {e.url} ({e.host})</li>)}</ul>}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Scans ({scans.length})</h3>
        {scans.length === 0 ? <p className="text-xs text-muted">No scans.</p> : <ul className="space-y-1 text-xs">{scans.map((s) => <li key={s.id} className="rounded border bg-canvas px-2 py-1">{s.profile} • {s.status} • {new Date(s.created_at).toLocaleString()}</li>)}</ul>}
      </div>
    </div>
  );
}
