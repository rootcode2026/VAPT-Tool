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
import { listCloudConnections, createCloudConnection, validateCloudConnection, discoverCloudResources, listCloudDiscoveries, listCloudCheckCatalog, runCloudSecurityChecks, listCloudCheckRuns } from "@/lib/api/connectors";
import Link from "next/link";

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
  const [newConn, setNewConn] = useState({ provider: "aws", account_id: "", credential: "", role_arn: "", external_id: "", name: "" });
  const [discoveries, setDiscoveries] = useState([]);
  const [catalog, setCatalog] = useState({ checks: [], count: 0 });
  const [checkRuns, setCheckRuns] = useState([]);
  const [checkMsg, setCheckMsg] = useState("");
  const [connMsg, setConnMsg] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [s, c, cc, dd, cat, cr] = await Promise.all([
        getCloudSecuritySummary(selectedProjectId),
        listCloudChecks(selectedProjectId).catch(() => ({ checks: [] })),
        listCloudConnections(selectedProjectId).catch(() => ({ connections: [] })),
        listCloudDiscoveries(selectedProjectId, { limit: 10 }).catch(() => ({ discoveries: [] })),
        listCloudCheckCatalog(selectedProjectId).catch(() => ({ checks: [], count: 0 })),
        listCloudCheckRuns(selectedProjectId, { limit: 5 }).catch(() => ({ runs: [] })),
      ]);
      setSummary(s);
      setChecks(c.checks || c || []);
      setConns(cc.connections || []);
      setDiscoveries(dd.discoveries || []);
      setCatalog(cat);
      setCheckRuns(cr.runs || []);
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
      <PageHeader title="Cloud Security" description={`Project: ${selectedProject?.name || selectedProjectId} — AWS live discovery, provider-neutral posture`} />

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
              <div><p className="text-sm font-medium">{c.name || c.provider} • {c.account_id}</p><p className="text-xs text-muted">{c.status}{c.role_arn ? " • cross-account role" : ""}</p></div>
              <div className="flex gap-1"><button type="button" onClick={async () => { try { const r = await validateCloudConnection(selectedProjectId, c.id); setConnMsg(r.account_id ? `Validated AWS account ${r.account_id}` : `Validated ${c.account_id}`); load(); } catch (e) { setConnMsg(e.message);} }} className="rounded border px-2 py-1 text-xs">Validate</button><button type="button" onClick={async () => { try { const r = await discoverCloudResources(selectedProjectId, c.id); setConnMsg(r.discovery_id ? `Discovery queued (${r.discovery_id.slice(0, 8)})` : `Discovered ${c.account_id}`); load(); } catch (e) { setConnMsg(e.message);} }} className="rounded border px-2 py-1 text-xs">Discover</button></div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <select value={newConn.provider} onChange={(e) => setNewConn((r) => ({ ...r, provider: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm"><option value="aws">AWS</option><option value="gcp">GCP</option><option value="azure">Azure</option></select>
          <input placeholder="Account/Sub/Project ID" value={newConn.account_id} onChange={(e) => setNewConn((r) => ({ ...r, account_id: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <input placeholder="Name (optional)" value={newConn.name} onChange={(e) => setNewConn((r) => ({ ...r, name: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <input placeholder="AWS role ARN (cross-account, optional)" value={newConn.role_arn} onChange={(e) => setNewConn((r) => ({ ...r, role_arn: e.target.value }))} className="rounded border bg-canvas px-2 py-1 font-mono text-xs" />
          <input placeholder="External ID (optional)" value={newConn.external_id} onChange={(e) => setNewConn((r) => ({ ...r, external_id: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <input type="password" placeholder="Credential (legacy — never stored plaintext)" value={newConn.credential} onChange={(e) => setNewConn((r) => ({ ...r, credential: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <button type="button" onClick={async () => { setConnMsg(""); try { await createCloudConnection(selectedProjectId, { provider: newConn.provider, account_id: newConn.account_id, name: newConn.name || undefined, role_arn: newConn.role_arn || undefined, external_id: newConn.external_id || undefined, credential: newConn.credential || undefined }); setConnMsg("Connection created (read-only, rate-limited)"); setNewConn({ provider: "aws", account_id: "", credential: "", role_arn: "", external_id: "", name: ""}); load(); } catch (e) { setConnMsg(e.message);} }} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Connect</button>
        </div>
        {connMsg ? <p className="mt-2 text-xs text-muted">{connMsg}</p> : null}
        <p className="mt-2 text-xs text-muted">Requires project_admin. AWS live discovery uses cross-account role assumption (no stored keys). Discovery is bounded (max 500), rate-limited, read-only.</p>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Discovery Runs</h3>
        <p className="text-xs text-muted">Queued → running → completed / partial / failed. Partial means some regions failed; warnings record permission gaps (never reported as absence).</p>
        <div className="mt-2 space-y-2">
          {discoveries.length === 0 ? <p className="text-xs text-muted">No discovery runs yet.</p> : discoveries.map((d) => (
            <div key={d.id} className="rounded border bg-canvas px-3 py-2">
              <p className="text-sm font-medium">{d.status} • {d.assets_discovered} assets • {d.relationships_discovered} relationships</p>
              <p className="text-xs text-muted">Regions {d.regions_succeeded}/{d.regions_attempted} ok{d.regions_failed ? `, ${d.regions_failed} failed` : ""}{d.error ? ` • ${d.error.slice(0, 160)}` : ""}</p>
              {(d.warnings || []).slice(0, 3).map((w, i) => (
                <p key={i} className="text-xs text-muted">Warning: {typeof w === "string" ? w.slice(0, 160) : JSON.stringify(w).slice(0, 160)}</p>
              ))}
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Exposure</h3>
        <p className="text-xs text-muted">Classified via asset intelligence (INTERNET_EXPOSED / EXTERNALLY_REACHABLE / INTERNAL).</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Exposed resources</p><p className="text-sm font-medium">{summary?.exposure?.exposed_resources ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Relationships</p><p className="text-sm font-medium">{summary?.relationships ?? 0}</p></div>
        </div>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">AWS Security Checks (E2)</h3>
        <p className="text-xs text-muted">{catalog.count || 0} deterministic checks against persisted discovery evidence. Missing evidence yields NOT_ASSESSED — never PASS. Findings appear on the findings page.</p>
        <div className="mt-2 flex flex-wrap gap-2">
          <button type="button" onClick={async () => { setCheckMsg(""); try { const r = await runCloudSecurityChecks(selectedProjectId, {}); setCheckMsg(`Evaluated ${r.resources_evaluated} resources: ${r.failed} failed, ${r.passed} passed, ${r.not_assessed} not assessed, ${r.findings_created} findings`); load(); } catch (e) { setCheckMsg(e.message);} }} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Run checks</button>
          <Link href="/findings" className="rounded border px-3 py-1 text-sm">View findings</Link>
        </div>
        {checkMsg ? <p className="mt-2 text-xs text-muted">{checkMsg}</p> : null}
        <div className="mt-2 space-y-2">
          {checkRuns.length === 0 ? <p className="text-xs text-muted">No check runs yet.</p> : checkRuns.map((r) => (
            <div key={r.id} className="rounded border bg-canvas px-3 py-2">
              <p className="text-sm font-medium">{r.status} • {r.failed} failed • {r.passed} passed • {r.not_assessed} not assessed{r.errors ? ` • ${r.errors} errors` : ""}</p>
              <p className="text-xs text-muted">{r.findings_created} findings • pack {r.check_pack_version || "?"}</p>
            </div>
          ))}
        </div>
        <div className="mt-2 space-y-1">
          {(catalog.checks || []).map((c) => (
            <p key={c.check_id} className="text-xs text-muted"><span className="font-mono">{c.check_id}</span> • {c.title} <SeverityBadge severity={c.severity} /></p>
          ))}
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

      <p className="text-xs text-muted">AWS live discovery via cross-account IAM role (E1); GCP/Azure remain mock. Temporary credentials are never stored; asset metadata is bounded and sanitized.</p>
    </div>
  );
}
