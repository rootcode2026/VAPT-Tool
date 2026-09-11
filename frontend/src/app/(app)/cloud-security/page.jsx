/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { useProjectContext } from "@/lib/project-context";
import { getAzureSummary, getCloudSecuritySummary, getGcpSummary, getNetworkSummary, getStorageSummary, listCloudChecks } from "@/lib/api/codeSecurity";
import { getCspmSummary } from "@/lib/api/cspm";
import { listCloudAttackPaths, getCloudAttackPath, listAttackPathHistory, getAttackPathHistory, getAttackPathSummary, observeAttackPaths } from "@/lib/api/cloudAttackPaths";
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
  const [network, setNetwork] = useState(null);
  const [storage, setStorage] = useState(null);
  const [gcp, setGcp] = useState(null);
  const [azure, setAzure] = useState(null);
  const [cspm, setCspm] = useState(null);
  const [checks, setChecks] = useState([]);
  const [conns, setConns] = useState([]);
  const [newConn, setNewConn] = useState({ provider: "aws", account_id: "", credential: "", role_arn: "", external_id: "", name: "" });
  const [discoveries, setDiscoveries] = useState([]);
  const [catalog, setCatalog] = useState({ checks: [], count: 0 });
  const [checkRuns, setCheckRuns] = useState([]);
  const [checkMsg, setCheckMsg] = useState("");
  const [connMsg, setConnMsg] = useState("");
  const [attackPaths, setAttackPaths] = useState([]);
  const [selectedPath, setSelectedPath] = useState(null);
  const [pathDetail, setPathDetail] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyDetail, setHistoryDetail] = useState(null);
  const [historySummary, setHistorySummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [s, c, cc, dd, cat, cr, net, stor, gcpSummary, azureSummary, cspmSummary, ap, hist, histSum] = await Promise.all([
        getCloudSecuritySummary(selectedProjectId),
        listCloudChecks(selectedProjectId).catch(() => ({ checks: [] })),
        listCloudConnections(selectedProjectId).catch(() => ({ connections: [] })),
        listCloudDiscoveries(selectedProjectId, { limit: 10 }).catch(() => ({ discoveries: [] })),
        listCloudCheckCatalog(selectedProjectId).catch(() => ({ checks: [], count: 0 })),
        listCloudCheckRuns(selectedProjectId, { limit: 5 }).catch(() => ({ runs: [] })),
        getNetworkSummary(selectedProjectId).catch(() => null),
        getStorageSummary(selectedProjectId).catch(() => null),
        getGcpSummary(selectedProjectId).catch(() => null),
        getAzureSummary(selectedProjectId).catch(() => null),
        getCspmSummary(selectedProjectId).catch(() => null),
        listCloudAttackPaths(selectedProjectId, { limit: 20 }).catch(() => ({ paths: [] })),
        listAttackPathHistory(selectedProjectId, { limit: 20 }).catch(() => ({ paths: [] })),
        getAttackPathSummary(selectedProjectId).catch(() => null),
      ]);
      setSummary(s);
      setChecks(c.checks || c || []);
      setConns(cc.connections || []);
      setDiscoveries(dd.discoveries || []);
      setCatalog(cat);
      setCheckRuns(cr.runs || []);
      setNetwork(net);
      setStorage(stor);
      setGcp(gcpSummary);
      setAzure(azureSummary);
      setCspm(cspmSummary);
      setAttackPaths(ap?.paths || ap?.data?.paths || []);
      setHistory(hist?.paths || hist?.data?.paths || []);
      setHistorySummary(histSum);
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
        <h3 className="text-sm font-semibold">Network Security (E4)</h3>
        <p className="text-xs text-muted">VPC • subnet • SG ingress/egress • NACL • ENI • public exposure. Deterministic, bounded, read-only.</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-3">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">VPCs</p><p className="text-sm font-medium">{network?.counts?.aws_vpc ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Subnets</p><p className="text-sm font-medium">{network?.counts?.aws_subnet ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Security Groups</p><p className="text-sm font-medium">{network?.counts?.aws_security_group ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Internet Gateways</p><p className="text-sm font-medium">{network?.internet_gateways ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Exposed SGs (0.0.0.0/0)</p><p className="text-sm font-medium">{network?.exposed_security_groups ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Network Findings</p><p className="text-sm font-medium">{network?.network_findings ?? 0}</p></div>
        </div>
        <p className="mt-2 text-xs text-muted">Not assessed: {network?.not_assessed ?? 0} • Pack E4 adds EC2-002 + NET-001..010.</p>
        <Link href="/findings" className="mt-2 inline-block text-xs text-primary underline">View network findings</Link>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Storage Security (E5)</h3>
        <p className="text-xs text-muted">S3 • EBS • EFS • RDS storage. Deterministic exposure & encryption posture, bounded, read-only.</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-3">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">S3 Buckets</p><p className="text-sm font-medium">{storage?.counts?.aws_s3_bucket ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Public S3</p><p className="text-sm font-medium">{storage?.public_s3_buckets ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">EBS Volumes</p><p className="text-sm font-medium">{storage?.counts?.aws_ebs_volume ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Unencrypted EBS</p><p className="text-sm font-medium">{storage?.unencrypted_ebs_volumes ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Public Snapshots</p><p className="text-sm font-medium">{storage?.public_snapshots ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Storage Findings</p><p className="text-sm font-medium">{storage?.storage_findings ?? 0}</p></div>
        </div>
        <p className="mt-2 text-xs text-muted">Not assessed: {storage?.not_assessed ?? 0} • Pack E5 adds S3-003..008, EBS-001/002, EFS-001.</p>
        <Link href="/findings" className="mt-2 inline-block text-xs text-primary underline">View storage findings</Link>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">GCP Security (E6)</h3>
        <p className="text-xs text-muted">GCP project • compute • network • storage • IAM. Provider-neutral, deterministic, read-only.</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-3">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">GCP Projects</p><p className="text-sm font-medium">{gcp?.counts?.gcp_project ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">VMs</p><p className="text-sm font-medium">{gcp?.counts?.gcp_compute_instance ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Firewalls</p><p className="text-sm font-medium">{gcp?.counts?.gcp_firewall ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Public Buckets</p><p className="text-sm font-medium">{gcp?.public_buckets ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Public Firewalls</p><p className="text-sm font-medium">{gcp?.public_firewalls ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">GCP Findings</p><p className="text-sm font-medium">{gcp?.gcp_findings ?? 0}</p></div>
        </div>
        <p className="mt-2 text-xs text-muted">Not assessed: {gcp?.not_assessed ?? 0} • E6 adds GCP-IAM-001..004, GCP-NET-001..005, GCP-GCS-001..004, GCP-COMPUTE-001/002.</p>
        <Link href="/findings" className="mt-2 inline-block text-xs text-primary underline">View GCP findings</Link>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Azure Security (E7)</h3>
        <p className="text-xs text-muted">Azure subscription • resource groups • VMs • NSGs • storage • RBAC. Deterministic, bounded, read-only.</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-3">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Subscriptions</p><p className="text-sm font-medium">{azure?.counts?.azure_subscription ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">VMs</p><p className="text-sm font-medium">{azure?.counts?.azure_vm ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">NSGs</p><p className="text-sm font-medium">{azure?.counts?.azure_nsg ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Public Storage</p><p className="text-sm font-medium">{azure?.public_storage_accounts ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Public NSGs</p><p className="text-sm font-medium">{azure?.public_nsgs ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Azure Findings</p><p className="text-sm font-medium">{azure?.azure_findings ?? 0}</p></div>
        </div>
        <p className="mt-2 text-xs text-muted">Not assessed: {azure?.not_assessed ?? 0} • E7 adds AZURE-IAM-001..003, AZURE-NET-001..007, AZURE-STORAGE-001..004, AZURE-COMPUTE-001/002.</p>
        <Link href="/findings" className="mt-2 inline-block text-xs text-primary underline">View Azure findings</Link>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">CSPM Overview (E8)</h3>
        <p className="text-xs text-muted">Unified posture across AWS • GCP • Azure — provider-neutral controls, deterministic PASS/FAIL/NOT_ASSESSED.</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-4">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Score</p><p className="text-sm font-medium">{cspm?.score ?? 0} <span className="text-xs">({cspm?.grade ?? "-"})</span></p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Compliance</p><p className="text-sm font-medium">{cspm?.compliance_percent ?? 0}%</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Coverage</p><p className="text-sm font-medium">{cspm?.coverage_percent ?? 0}%</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Controls</p><p className="text-sm font-medium">{cspm?.controls?.total ?? 0} ({cspm?.controls?.passed ?? 0} pass, {cspm?.controls?.failed ?? 0} fail)</p></div>
        </div>
        <div className="mt-2 grid gap-2 sm:grid-cols-3">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">AWS</p><p className="text-xs">{cspm?.providers?.aws?.passed ?? 0} pass, {cspm?.providers?.aws?.failed ?? 0} fail</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">GCP</p><p className="text-xs">{cspm?.providers?.gcp?.passed ?? 0} pass, {cspm?.providers?.gcp?.failed ?? 0} fail</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Azure</p><p className="text-xs">{cspm?.providers?.azure?.passed ?? 0} pass, {cspm?.providers?.azure?.failed ?? 0} fail</p></div>
        </div>
        <p className="mt-2 text-xs text-muted">Top failures: {(cspm?.top_failures || []).slice(0,3).map(f => f.control_id).join(", ") || "none"}</p>
        <Link href="/findings" className="mt-2 inline-block text-xs text-primary underline">View findings</Link>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Cloud Attack Paths (E9)</h3>
        <p className="text-xs text-muted">Evidence-backed exposure paths: EXPOSURE + IDENTITY + NETWORK + RESOURCE + FINDING. Potential paths, not confirmed exploitation.</p>
        {attackPaths.length === 0 ? <p className="mt-2 text-xs text-muted">No attack paths detected — no evidence-backed internet → vulnerable path.</p> : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-muted"><th className="p-1">Priority</th><th className="p-1">Severity</th><th className="p-1">Provider</th><th className="p-1">Path Type</th><th className="p-1">Entry</th><th className="p-1">Target</th><th className="p-1">Conf</th><th className="p-1">Findings</th><th className="p-1">Status</th></tr></thead>
              <tbody>
                {attackPaths.map((p) => (
                  <tr key={p.id} className="cursor-pointer border-t hover:bg-canvas" onClick={async () => { setSelectedPath(p.id); try { const d = await getCloudAttackPath(selectedProjectId, p.id); setPathDetail(d); } catch (e) { setPathDetail(p); } }}>
                    <td className="p-1 font-medium">{p.priority_score} </td>
                    <td className="p-1"><SeverityBadge severity={p.severity} /></td>
                    <td className="p-1">{p.provider}</td>
                    <td className="p-1 font-mono">{p.path_type}</td>
                    <td className="p-1 truncate max-w-[120px]">{p.entry_asset_id.slice(0,8)}</td>
                    <td className="p-1 truncate max-w-[120px]">{p.target_asset_id.slice(0,8)}</td>
                    <td className="p-1">{p.confidence}</td>
                    <td className="p-1">{p.finding_count ?? p.findings?.length ?? 0}</td>
                    <td className="p-1">{p.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {selectedPath && pathDetail && (
              <div className="mt-3 rounded border bg-canvas p-3">
                <p className="text-sm font-semibold">Path Detail: {pathDetail.id.slice(0,8)} — {pathDetail.path_type} ({pathDetail.severity} / {pathDetail.confidence})</p>
                <p className="text-xs text-muted">Provider: {pathDetail.provider} • Score: {pathDetail.priority_score} • {pathDetail.explanation}</p>
                <div className="mt-2 space-y-1">
                  <p className="text-xs font-medium">Chain:</p>
                  {(pathDetail.nodes || []).map((n, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="font-mono">{n.asset_type}</span>
                      <span className="text-muted">{n.value.slice(0,40)}</span>
                      {i < (pathDetail.nodes.length -1) && <span className="text-muted">→</span>}
                    </div>
                  ))}
                </div>
                <div className="mt-2">
                  <p className="text-xs font-medium">Findings:</p>
                  {(pathDetail.findings || []).slice(0,5).map((f) => (
                    <p key={f.finding_id} className="text-xs text-muted font-mono">{f.rule_id} • {f.severity} • {f.title.slice(0,60)}</p>
                  ))}
                </div>
                <div className="mt-2">
                  <p className="text-xs font-medium">Relationships:</p>
                  {(pathDetail.relationships || []).map((r) => (
                    <p key={r.id} className="text-xs text-muted">{r.relationship_type}: {r.source_asset_id.slice(0,6)} → {r.target_asset_id.slice(0,6)}</p>
                  ))}
                </div>
                <button type="button" onClick={() => { setSelectedPath(null); setPathDetail(null); }} className="mt-2 rounded border px-2 py-1 text-xs">Close</button>
              </div>
            )}
          </div>
        )}
        <p className="mt-2 text-xs text-muted">Bounded: depth ≤6, ≤100 paths, evidence ≤20. Potential attack path, not confirmed exploitation.</p>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Attack Path History (E10)</h3>
        <p className="text-xs text-muted">Historical intelligence: first seen / last seen / resolved, severity & priority changes, reopened paths. Evidence-backed, not exploitation.</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-4">
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Active</p><p className="text-sm font-medium">{historySummary?.active ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Resolved</p><p className="text-sm font-medium">{historySummary?.resolved ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Critical</p><p className="text-sm font-medium">{historySummary?.critical ?? 0}</p></div>
          <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Highest Priority</p><p className="text-sm font-medium">{historySummary?.highest_priority ?? 0}</p></div>
        </div>
        <div className="mt-2 flex gap-2">
          <button type="button" onClick={async () => { try { await observeAttackPaths(selectedProjectId, { run_status: "completed" }); load(); } catch (e) { /* ignore */ } }} className="rounded border px-2 py-1 text-xs">Observe now</button>
          <span className="text-xs text-muted">Providers: {historySummary ? Object.entries(historySummary.providers || {}).map(([k,v])=> `${k}:${v}`).join(", ") || "none" : "—"} • Types: {historySummary ? Object.entries(historySummary.path_types || {}).map(([k,v])=> `${k}:${v}`).join(", ") || "none" : "—"}</span>
        </div>
        {history.length === 0 ? <p className="mt-2 text-xs text-muted">No historical paths yet — run observe or wait for monitoring.</p> : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-muted"><th className="p-1">First Seen</th><th className="p-1">Last Seen</th><th className="p-1">Provider</th><th className="p-1">Type</th><th className="p-1">Severity</th><th className="p-1">Priority</th><th className="p-1">Status</th></tr></thead>
              <tbody>
                {history.map((p) => (
                  <tr key={p.id} className="cursor-pointer border-t hover:bg-canvas" onClick={async () => { try { const d = await getAttackPathHistory(selectedProjectId, p.id); setHistoryDetail(d); } catch (e) { setHistoryDetail(p); } }}>
                    <td className="p-1">{p.first_seen_at ? new Date(p.first_seen_at).toLocaleDateString() : "—"}</td>
                    <td className="p-1">{p.last_seen_at ? new Date(p.last_seen_at).toLocaleDateString() : "—"}</td>
                    <td className="p-1">{p.provider}</td>
                    <td className="p-1 font-mono">{p.path_type}</td>
                    <td className="p-1"><SeverityBadge severity={p.severity} /></td>
                    <td className="p-1">{p.priority_score}</td>
                    <td className="p-1">{p.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {historyDetail && (
              <div className="mt-3 rounded border bg-canvas p-3">
                <p className="text-sm font-semibold">History Detail: {historyDetail.id.slice(0,8)} — {historyDetail.path_type} ({historyDetail.severity})</p>
                <p className="text-xs text-muted">First: {historyDetail.first_seen_at} • Last: {historyDetail.last_seen_at} • Resolved: {historyDetail.resolved_at || "—"} • Confidence: {historyDetail.confidence}</p>
                <div className="mt-2"><p className="text-xs font-medium">Observations: {historyDetail.observations?.length ?? 0}</p>{(historyDetail.observations || []).slice(0,5).map((o) => (<p key={o.id} className="text-xs text-muted">{o.observed_at?.slice(0,10)} • {o.severity} • {o.priority_score} • {o.status}</p>))}</div>
                <button type="button" onClick={() => setHistoryDetail(null)} className="mt-2 rounded border px-2 py-1 text-xs">Close</button>
              </div>
            )}
          </div>
        )}
        <p className="mt-2 text-xs text-muted">ACTIVE when observed, RESOLVED when missing from valid completed observation. Failed/partial runs never resolve.</p>
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
