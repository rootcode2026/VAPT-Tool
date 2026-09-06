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
import { listCloudConnections, createCloudConnection, validateCloudConnection, discoverCloudResources } from "@/lib/api/connectors";

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
  const [conns, setConns] = useState([]);
  const [newConn, setNewConn] = useState({ provider: "aws", account_id: "", credential: "" });
  const [connMsg, setConnMsg] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [s, c, cc] = await Promise.all([
        getCloudSecuritySummary(selectedProjectId),
        listCloudChecks(selectedProjectId).catch(() => ({ checks: [] })),
        listCloudConnections(selectedProjectId).catch(() => ({ connections: [] })),
      ]);
      setSummary(s);
      setChecks(c.checks || c || []);
      setConns(cc.connections || []);
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
        <h3 className="text-sm font-semibold">Cloud Connections</h3>
        <p className="text-xs text-muted">AWS, GCP, Azure — project-scoped, read-only least-privilege (role ARN / service account), credential never returned (KMS/Vault reference).</p>
        <div className="mt-3 space-y-2">
          {conns.length === 0 ? <p className="text-xs text-muted">No cloud connections.</p> : conns.map((c) => (
            <div key={c.id} className="flex flex-wrap items-center justify-between gap-2 rounded border bg-canvas px-3 py-2">
              <div><p className="text-sm font-medium">{c.provider} • {c.account_id}</p><p className="text-xs text-muted">{c.status}</p></div>
              <div className="flex gap-1"><button type="button" onClick={async () => { try { await validateCloudConnection(selectedProjectId, c.id); setConnMsg(`Validated ${c.account_id}`); load(); } catch (e) { setConnMsg(e.message);} }} className="rounded border px-2 py-1 text-xs">Validate</button><button type="button" onClick={async () => { try { await discoverCloudResources(selectedProjectId, c.id); setConnMsg(`Discovered ${c.account_id}`); load(); } catch (e) { setConnMsg(e.message);} }} className="rounded border px-2 py-1 text-xs">Discover</button></div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <select value={newConn.provider} onChange={(e) => setNewConn((r) => ({ ...r, provider: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm"><option value="aws">AWS</option><option value="gcp">GCP</option><option value="azure">Azure</option></select>
          <input placeholder="Account/Sub/Project ID" value={newConn.account_id} onChange={(e) => setNewConn((r) => ({ ...r, account_id: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <input type="password" placeholder="Credential (role ARN / SA — never stored plaintext)" value={newConn.credential} onChange={(e) => setNewConn((r) => ({ ...r, credential: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <button type="button" onClick={async () => { setConnMsg(""); try { await createCloudConnection(selectedProjectId, { provider: newConn.provider, account_id: newConn.account_id, credential: newConn.credential }); setConnMsg("Connection created (read-only, rate-limited)"); setNewConn({ provider: "aws", account_id: "", credential: ""}); load(); } catch (e) { setConnMsg(e.message);} }} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Connect</button>
        </div>
        {connMsg ? <p className="mt-2 text-xs text-muted">{connMsg}</p> : null}
        <p className="mt-2 text-xs text-muted">Requires project_admin. Discovery is bounded (max 500), rate-limited, read-only.</p>
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
