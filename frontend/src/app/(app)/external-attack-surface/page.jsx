"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { useProjectContext } from "@/lib/project-context";
import { getEASSummary, listEASAssets, listEASCandidates, listEASScopes, createEASScope, createEASScopeEntry, discoverEAS, confirmEASAsset, rejectEASAsset } from "@/lib/api/externalAttackSurface";

function Stat({ label, value }) {
  return (
    <div className="rounded-md border bg-surface p-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-lg font-bold">{value}</p>
    </div>
  );
}

export default function ExternalAttackSurfacePage() {
  const { selectedProjectId, status } = useProjectContext();
  const [summary, setSummary] = useState(null);
  const [assets, setAssets] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [scopes, setScopes] = useState([]);
  const [newScope, setNewScope] = useState({ name: "", description: "" });
  const [newEntry, setNewEntry] = useState({ scopeId: "", entry_type: "DOMAIN", value: "" });
  const [filter, setFilter] = useState({ ownership: "", asset_type: "" });
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [sum, ast, cands, sc] = await Promise.all([
        getEASSummary(selectedProjectId).catch(() => null),
        listEASAssets(selectedProjectId, { limit: 50, ownership: filter.ownership || undefined, asset_type: filter.asset_type || undefined }).catch(() => ({ assets: [] })),
        listEASCandidates(selectedProjectId).catch(() => ({ candidates: [] })),
        listEASScopes(selectedProjectId).catch(() => ({ scopes: [] })),
      ]);
      setSummary(sum);
      setAssets(ast?.assets || ast?.data?.assets || []);
      setCandidates(cands?.candidates || cands?.data?.candidates || []);
      setScopes(sc?.scopes || sc?.data?.scopes || []);
    } catch (e) {
      setError(e.message || "Unable to load external attack surface.");
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId, filter]);

  useEffect(() => {
    if (status === "ready" && selectedProjectId) load();
  }, [status, selectedProjectId, load]);

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project selected" description="Select a project to view external attack surface." />;
  if (loading) return <div><PageHeader title="External Attack Surface" description="What this organization exposes to the Internet" /><LoadingState message="Loading external attack surface..." /></div>;
  if (error) return <div><PageHeader title="External Attack Surface" description="What this organization exposes" /><ErrorState title="Unable to load" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="External Attack Surface" description={`Project: ${selectedProjectId} — continuously understand what is exposed to the public Internet.`} />

      <div className="grid gap-2 sm:grid-cols-4">
        <Stat label="Total External" value={summary?.total_external_assets ?? 0} />
        <Stat label="Confirmed" value={summary?.confirmed_assets ?? 0} />
        <Stat label="Candidates" value={summary?.candidate_assets ?? 0} />
        <Stat label="Exposed Services" value={summary?.externally_exposed_services ?? 0} />
      </div>

      <div className="grid gap-2 sm:grid-cols-4">
        <Stat label="Newly Discovered" value={summary?.newly_discovered ?? 0} />
        <Stat label="Critical Findings" value={summary?.critical_findings ?? 0} />
        <Stat label="High Findings" value={summary?.high_findings ?? 0} />
        <Stat label="Changed" value={summary?.changed ?? 0} />
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">External Scope Management</h3>
        <p className="text-xs text-muted">Explicitly authorized scope. Only AUTHORIZED entries may be used for active discovery. CIDR limited to /24 (256 IPs), 50 entries/scope.</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <input placeholder="Scope name" value={newScope.name} onChange={(e) => setNewScope({ ...newScope, name: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <input placeholder="Description" value={newScope.description} onChange={(e) => setNewScope({ ...newScope, description: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <button type="button" onClick={async () => { try { await createEASScope(selectedProjectId, { name: newScope.name, description: newScope.description }); setNewScope({ name: "", description: "" }); load(); setMsg("Scope created"); } catch (e) { setMsg(e.message); } }} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Create Scope</button>
        </div>
        <div className="mt-3 space-y-2">
          {scopes.length === 0 ? <p className="text-xs text-muted">No scopes.</p> : scopes.map((s) => (
            <div key={s.id} className="rounded border bg-canvas p-2">
              <p className="text-sm font-medium">{s.name} • {s.status}</p>
              <div className="mt-2 flex gap-2">
                <select value={newEntry.scopeId === s.id ? newEntry.entry_type : "DOMAIN"} onChange={(e) => setNewEntry({ ...newEntry, scopeId: s.id, entry_type: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs">
                  <option value="DOMAIN">DOMAIN</option><option value="SUBDOMAIN">SUBDOMAIN</option><option value="IP">IP</option><option value="CIDR">CIDR</option><option value="URL">URL</option>
                </select>
                <input placeholder="Value (e.g., example.com)" value={newEntry.scopeId === s.id ? newEntry.value : ""} onChange={(e) => setNewEntry({ ...newEntry, scopeId: s.id, value: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs w-48" />
                <button type="button" onClick={async () => { try { await createEASScopeEntry(selectedProjectId, s.id, { entry_type: newEntry.entry_type, value: newEntry.value, authorization_status: "AUTHORIZED" }); setNewEntry({ scopeId: "", entry_type: "DOMAIN", value: "" }); load(); setMsg("Entry added"); } catch (e) { setMsg(e.message); } }} className="rounded border px-2 py-1 text-xs">Add AUTHORIZED Entry</button>
              </div>
            </div>
          ))}
        </div>
        {msg && <p className="mt-2 text-xs text-muted">{msg}</p>}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Discovery</h3>
        <p className="text-xs text-muted">Passive: subfinder/DNS. Active (WEB/FULL): bounded Nmap/HTTP/TLS, 20 targets max, 10 ports/target, SSRF protected, scope-authorized only.</p>
        <div className="mt-2 flex gap-2">
          <button type="button" onClick={async () => { try { const scope = scopes[0]; if (!scope) { setMsg("Create scope first"); return; } await discoverEAS(selectedProjectId, { external_scope_id: scope.id, profile: "QUICK" }); setMsg("Discovery queued (QUICK)"); load(); } catch (e) { setMsg(e.message); } }} className="rounded border px-2 py-1 text-xs">Run QUICK (passive)</button>
          <button type="button" onClick={async () => { try { const scope = scopes[0]; if (!scope) { setMsg("Create scope first"); return; } await discoverEAS(selectedProjectId, { external_scope_id: scope.id, profile: "WEB" }); setMsg("Discovery queued (WEB)"); load(); } catch (e) { setMsg(e.message); } }} className="rounded border px-2 py-1 text-xs">Run WEB</button>
          <button type="button" onClick={async () => { try { const scope = scopes[0]; if (!scope) { setMsg("Create scope first"); return; } await discoverEAS(selectedProjectId, { external_scope_id: scope.id, profile: "FULL" }); setMsg("Discovery queued (FULL)"); load(); } catch (e) { setMsg(e.message); } }} className="rounded border px-2 py-1 text-xs">Run FULL</button>
        </div>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Candidate Review</h3>
        <p className="text-xs text-muted">Possible organization asset — ownership requires analyst verification. Do not auto authorize.</p>
        {candidates.length === 0 ? <p className="mt-2 text-xs text-muted">No candidates.</p> : (
          <div className="mt-2 space-y-2">
            {candidates.map((c) => (
              <div key={c.id} className="flex items-center justify-between rounded border bg-canvas p-2">
                <div><p className="text-sm font-mono">{c.value}</p><p className="text-xs text-muted">{c.asset_type} • {c.extra_data?.ownership_confidence || "UNKNOWN"}</p></div>
                <div className="flex gap-1">
                  <button type="button" onClick={async () => { await confirmEASAsset(selectedProjectId, c.id); load(); }} className="rounded border px-2 py-1 text-xs">Confirm</button>
                  <button type="button" onClick={async () => { await rejectEASAsset(selectedProjectId, c.id); load(); }} className="rounded border px-2 py-1 text-xs">Reject</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">External Assets</h3>
        <div className="mt-2 flex gap-2">
          <select value={filter.ownership} onChange={(e) => setFilter({ ...filter, ownership: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs">
            <option value="">All ownership</option><option value="CONFIRMED">CONFIRMED</option><option value="UNKNOWN">UNKNOWN</option><option value="LOW_CONFIDENCE">LOW</option>
          </select>
          <select value={filter.asset_type} onChange={(e) => setFilter({ ...filter, asset_type: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs">
            <option value="">All types</option><option value="domain">domain</option><option value="subdomain">subdomain</option><option value="ip">ip</option><option value="url">url</option><option value="port">port</option>
          </select>
          <button type="button" onClick={() => load()} className="rounded border px-2 py-1 text-xs">Filter</button>
        </div>
        {assets.length === 0 ? <p className="mt-2 text-xs text-muted">No external assets.</p> : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-muted"><th className="p-1">Asset</th><th className="p-1">Type</th><th className="p-1">Exposure</th><th className="p-1">Ownership</th><th className="p-1">Status</th><th className="p-1">Risk</th><th className="p-1">First Seen</th></tr></thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a.id} className="cursor-pointer border-t hover:bg-canvas" onClick={() => setSelectedAsset(a)}>
                    <td className="p-1 font-mono">{a.value.slice(0,40)}</td>
                    <td className="p-1">{a.asset_type}</td>
                    <td className="p-1">{a.extra_data?.exposure_type || "UNKNOWN"}</td>
                    <td className="p-1">{a.extra_data?.ownership_confidence || "UNKNOWN"}</td>
                    <td className="p-1">{a.extra_data?.externally_reachable ? "reachable" : "unknown"}</td>
                    <td className="p-1">—</td>
                    <td className="p-1">{a.extra_data?.first_external_seen?.slice(0,10) || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {selectedAsset && (
          <div className="mt-3 rounded border bg-canvas p-3">
            <p className="text-sm font-semibold">{selectedAsset.value}</p>
            <p className="text-xs text-muted">Type: {selectedAsset.asset_type} • Ownership: {selectedAsset.extra_data?.ownership_confidence} • Exposure: {selectedAsset.extra_data?.exposure_type}</p>
            <p className="text-xs text-muted">Discovery: {(selectedAsset.extra_data?.discovery_sources || []).join(", ") || "—"} • Scope: {selectedAsset.extra_data?.scope_id?.slice(0,8) || "—"}</p>
            <button type="button" onClick={() => setSelectedAsset(null)} className="mt-2 rounded border px-2 py-1 text-xs">Close</button>
          </div>
        )}
      </div>

      <p className="text-xs text-muted">What's exposed and what changed? Prioritize: newly exposed, critical/high findings, unknown candidates, significant changes.</p>
    </div>
  );
}
