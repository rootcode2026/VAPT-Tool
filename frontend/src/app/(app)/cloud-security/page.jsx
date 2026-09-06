/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { useProjectContext } from "@/lib/project-context";
import { getCloudSecuritySummary, listCloudChecks } from "@/lib/api/codeSecurity";

function Stat({ label, value, hint }) {
  return (
    <div className="rounded-md border bg-surface p-4">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-2xl font-bold">{value}</p>
      {hint ? <p className="text-xs text-muted">{hint}</p> : null}
    </div>
  );
}

export default function CloudSecurityPage() {
  const { selectedProjectId, selectedProject, status } = useProjectContext();
  const [summary, setSummary] = useState(null);
  const [checks, setChecks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [s, c] = await Promise.all([
        getCloudSecuritySummary(selectedProjectId),
        listCloudChecks(selectedProjectId).catch(() => ({ checks: [] })),
      ]);
      setSummary(s);
      setChecks(c.checks || c || []);
    } catch (e) {
      setError(e.message || "Unable to load cloud security.");
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    if (status === "ready" && selectedProjectId) load();
  }, [status, selectedProjectId, load]);

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project selected" description="Select a project to view cloud security." />;
  if (loading) return <div><PageHeader title="Cloud Security" description="AWS • GCP • Azure — provider-neutral posture" /><LoadingState message="Loading cloud security..." /></div>;
  if (error) return <div><PageHeader title="Cloud Security" description="AWS • GCP • Azure" /><ErrorState title="Unable to load" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Security" description={`Project: ${selectedProject?.name || selectedProjectId} — provider-neutral posture (mock, no live credentials)`} />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Accounts" value={summary?.accounts ?? 0} hint="cloud_account assets" />
        <Stat label="Resources" value={summary?.resources ?? 0} hint="cloud_resource assets" />
        <Stat label="Findings" value={summary?.findings?.total ?? 0} hint="via FindingEngine" />
        <Stat label="Critical" value={summary?.findings?.critical ?? 0} />
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        {Object.entries(summary?.by_provider || {}).map(([k, v]) => (
          <div key={k} className="rounded-md border bg-surface p-3">
            <p className="text-xs text-muted">{k.toUpperCase()}</p>
            <p className="text-sm font-medium">{v} resources</p>
          </div>
        ))}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Exposure</h3>
        <p className="text-xs text-muted">Classified via asset intelligence (INTERNET_EXPOSED / EXTERNALLY_REACHABLE / INTERNAL).</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Exposed resources</p><p className="text-sm font-medium">{summary?.exposure?.exposed_resources ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Relationships</p><p className="text-sm font-medium">{summary?.relationships ?? 0}</p></div>
        </div>
      </div>

      <div className="rounded-md border bg-surface">
        <div className="border-b px-4 py-3">
          <h3 className="text-sm font-semibold">Cloud Security Checks</h3>
          <p className="text-xs text-muted">Provider-neutral checks — storage public, SG 0.0.0.0/0, encryption, logging, IAM, etc. (observed vs mock vs unknown).</p>
        </div>
        <div className="p-4 space-y-2">
          {(checks || []).slice(0, 8).map((c) => (
            <div key={c.check_id} className="rounded border bg-canvas p-3">
              <p className="text-sm font-medium">{c.check_id}: {c.title} <SeverityBadge severity={c.severity} /></p>
              <p className="text-xs text-muted">{c.provider} • {c.resource_type}</p>
            </div>
          ))}
          {checks.length === 0 ? <EmptyState title="No checks" description="No provider checks available." /> : null}
        </div>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Relationships</h3>
        <p className="text-xs text-muted">cloud_account → contains → cloud_resource → exposes → ip / serves → url / runs → container_image. Only deterministic evidence-based relationships are created (no speculative graph).</p>
        <p className="mt-1 text-xs text-muted">Cross-domain: repository → contains → iac_resource → corresponds → cloud_resource; container_image → runs on → cloud_resource; api_endpoint → served_by → cloud_resource.</p>
      </div>

      <p className="text-xs text-muted">Cloud domain uses mock/provider-neutral adapters (worker/app/cloud/) — live AWS/GCP/Azure connectors, real credential vault, IAM auditing belong to Phase 11. No credentials stored in asset metadata.</p>
    </div>
  );
}
