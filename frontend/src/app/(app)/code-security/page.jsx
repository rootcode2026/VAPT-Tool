/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import SeverityBadge from "@/components/ui/SeverityBadge";
import StatusBadge from "@/components/ui/StatusBadge";
import { useProjectContext } from "@/lib/project-context";
import { getCodeSecuritySummary, listCodeFindings } from "@/lib/api/codeSecurity";

function Stat({ label, value, hint }) {
  return (
    <div className="rounded-md border bg-surface p-4">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-2xl font-bold">{value}</p>
      {hint ? <p className="text-xs text-muted">{hint}</p> : null}
    </div>
  );
}

export default function CodeSecurityPage() {
  const { selectedProjectId, selectedProject, status } = useProjectContext();
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState({ scanner: "", severity: "" });

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [s, f] = await Promise.all([
        getCodeSecuritySummary(selectedProjectId),
        listCodeFindings(selectedProjectId, { page: 1, page_size: 20, scanner: filter.scanner || undefined, severity: filter.severity || undefined }),
      ]);
      setSummary(s);
      setFindings(f);
    } catch (e) {
      setError(e.message || "Unable to load code security.");
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId, filter.scanner, filter.severity]);

  useEffect(() => {
    if (status === "ready" && selectedProjectId) load();
  }, [status, selectedProjectId, load]);

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project selected" description="Select a project to view code security." />;
  if (loading) return <div><PageHeader title="Code Security" description="SAST • SCA • Secrets • Container • IaC • API" /><LoadingState message="Loading code security..." /></div>;
  if (error) return <div><PageHeader title="Code Security" description="SAST • SCA • Secrets • Container • IaC • API" /><ErrorState title="Unable to load" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Code Security" description={`Project: ${selectedProject?.name || selectedProjectId} — SAST, SCA, Secrets, Container, IaC, API`} />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Total findings" value={summary?.findings?.total ?? 0} hint="All code scanners" />
        <Stat label="Critical" value={summary?.findings?.critical ?? 0} hint="Requires immediate attention" />
        <Stat label="High" value={summary?.findings?.high ?? 0} />
        <Stat label="Secrets" value={summary?.by_scanner?.secrets ?? 0} hint="Redacted evidence" />
      </div>

      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {Object.entries(summary?.by_scanner || {}).map(([k, v]) => (
          <div key={k} className="rounded-md border bg-surface p-3">
            <p className="text-xs text-muted">{k.toUpperCase()}</p>
            <p className="text-lg font-semibold">{v}</p>
          </div>
        ))}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Assets</h3>
        <p className="text-xs text-muted">Repository, source files, packages, container images, IaC resources, API endpoints linked via asset intelligence.</p>
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          {Object.entries(summary?.assets || {}).map(([k, v]) => (
            <div key={k} className="rounded border bg-canvas p-2">
              <p className="text-xs text-muted">{k}</p>
              <p className="text-sm font-medium">{v}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Filters</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          <select value={filter.scanner} onChange={(e) => setFilter((f) => ({ ...f, scanner: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm">
            <option value="">All scanners</option>
            {["sast", "sca", "secrets", "container", "iac", "api"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={filter.severity} onChange={(e) => setFilter((f) => ({ ...f, severity: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm">
            <option value="">All severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div className="rounded-md border bg-surface">
        <div className="border-b px-4 py-3">
          <h3 className="text-sm font-semibold">Code Findings</h3>
          <p className="text-xs text-muted">Via FindingEngine — correlated, validated, risk-scored. Secret evidence is redacted.</p>
        </div>
        {findings.items.length === 0 ? (
          <div className="p-4"><EmptyState title="No code findings" description="No SAST/SCA/Secrets/Container/IaC/API findings for this project." /></div>
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/10 text-xs text-muted">
                <tr><th className="px-3 py-2 text-left">Severity</th><th className="px-3 py-2 text-left">Title</th><th className="px-3 py-2 text-left">Scanner</th><th className="px-3 py-2 text-left">Status</th><th className="px-3 py-2 text-left">Evidence</th></tr>
              </thead>
              <tbody>
                {findings.items.map((f) => (
                  <tr key={f.id} className="border-t">
                    <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-3 py-2">{f.title}</td>
                    <td className="px-3 py-2 text-xs">{f.scanner}</td>
                    <td className="px-3 py-2"><StatusBadge status={f.status} /></td>
                    <td className="px-3 py-2 text-xs truncate max-w-[300px]">{f.scanner === "secrets" ? "[REDACTED]" : f.evidence || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Git Intelligence</h3>
        <p className="text-xs text-muted">Preserves repository, branch, commit SHA, author, timestamp, changed files when source metadata is available. Future GitHub/GitLab connectors will populate this automatically; Phase 10 handles local/source snapshot metadata without fabrication.</p>
        <p className="mt-1 text-xs text-muted">Recent scans: {(summary?.recent_scans || []).map((s) => `${s.profile}:${s.status}`).join(", ") || "—"}</p>
      </div>

      <p className="text-xs text-muted">Code profile: <code>code</code> → sast, sca, secrets, container, iac, api (respects enabled/healthy/capacity via scanner control plane, SCANNER_MAX_ATTEMPTS=2).</p>
    </div>
  );
}
