"use client";
/* eslint-disable react-hooks/set-state-in-effect */
import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { useProjectContext } from "@/lib/project-context";
import { listApplications, createApplication, getApplicationSummary, listApplicationAssets, listApplicationFindings, getApplicationRisk, getApplicationExposure, listApplicationCorrelations, createApplicationInvestigation } from "@/lib/api/applications";

function RiskBadge({ tier }) {
  const color = tier === "CRITICAL" ? "bg-red-600 text-white" : tier === "HIGH" ? "bg-orange-500 text-white" : tier === "MEDIUM" ? "bg-yellow-500 text-black" : tier === "LOW" ? "bg-green-600 text-white" : "bg-gray-400 text-white";
  return <span className={`rounded px-2 py-0.5 text-xs font-semibold ${color}`}>{tier || "UNKNOWN"}</span>;
}

export default function ApplicationsPage() {
  const { selectedProjectId, status } = useProjectContext();
  const [apps, setApps] = useState([]);
  const [filter, setFilter] = useState({ lifecycle: "", criticality: "" });
  const [newApp, setNewApp] = useState({ name: "", description: "", application_type: "WEB", lifecycle: "PRODUCTION", criticality: "high" });
  const [selected, setSelected] = useState(null);
  const [summary, setSummary] = useState(null);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [risk, setRisk] = useState(null);
  const [exposure, setExposure] = useState(null);
  const [correlations, setCorrelations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const res = await listApplications(selectedProjectId, { limit: 50 }).catch(() => ({ applications: [] }));
      const list = res?.applications || res?.data?.applications || [];
      setApps(list);
    } catch (e) {
      setError(e.message || "Unable to load applications");
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  const loadDetail = useCallback(async (appId) => {
    if (!selectedProjectId || !appId) return;
    try {
      const [s, a, f, r, e, c] = await Promise.all([
        getApplicationSummary(selectedProjectId, appId).catch(() => null),
        listApplicationAssets(selectedProjectId, appId).catch(() => ({ assets: [] })),
        listApplicationFindings(selectedProjectId, appId).catch(() => ({ findings: [] })),
        getApplicationRisk(selectedProjectId, appId).catch(() => null),
        getApplicationExposure(selectedProjectId, appId).catch(() => null),
        listApplicationCorrelations(selectedProjectId, appId).catch(() => ({ correlations: [] })),
      ]);
      setSummary(s);
      setAssets(a?.assets || a?.data?.assets || []);
      setFindings(f?.findings || f?.data?.findings || []);
      setRisk(r);
      setExposure(e);
      setCorrelations(c?.correlations || c?.data?.correlations || []);
    } catch (e) {
      setMsg(e.message);
    }
  }, [selectedProjectId]);

  useEffect(() => { if (status === "ready" && selectedProjectId) load(); }, [status, selectedProjectId, load]);

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project selected" description="Select a project to view applications." />;
  if (loading) return <div><PageHeader title="Applications" description="Application Security Intelligence — one trustworthy context per application" /><LoadingState message="Loading applications..." /></div>;
  if (error) return <div><PageHeader title="Applications" description="Application Security Intelligence" /><ErrorState title="Unable to load" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Applications" description={`Project: ${selectedProjectId} — correlate repository, dependencies, secrets, containers, IaC, APIs and exposure into one application context.`} />

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Create Application</h3>
        <p className="text-xs text-muted">Deterministic identity: project + name (unique). Provide explicit application context — do not guess repository = application.</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <input placeholder="Name (e.g., Payments API)" value={newApp.name} onChange={(e) => setNewApp({ ...newApp, name: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-sm w-48" />
          <select value={newApp.application_type} onChange={(e) => setNewApp({ ...newApp, application_type: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs">
            <option value="WEB">WEB</option><option value="API">API</option><option value="SERVICE">SERVICE</option><option value="MOBILE_BACKEND">MOBILE_BACKEND</option><option value="WORKER">WORKER</option><option value="LIBRARY">LIBRARY</option>
          </select>
          <select value={newApp.lifecycle} onChange={(e) => setNewApp({ ...newApp, lifecycle: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs">
            <option value="PRODUCTION">PRODUCTION</option><option value="STAGING">STAGING</option><option value="DEVELOPMENT">DEVELOPMENT</option><option value="TESTING">TESTING</option>
          </select>
          <select value={newApp.criticality} onChange={(e) => setNewApp({ ...newApp, criticality: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs">
            <option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
          </select>
          <button type="button" onClick={async () => { try { await createApplication(selectedProjectId, { name: newApp.name, application_type: newApp.application_type, lifecycle: newApp.lifecycle, criticality: newApp.criticality, description: newApp.description }); setNewApp({ ...newApp, name: "", description: "" }); load(); setMsg("Application created"); } catch (e) { setMsg(e.message); } }} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Create</button>
        </div>
        {msg && <p className="mt-2 text-xs text-muted">{msg}</p>}
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Applications ({apps.length})</h3>
        <div className="mt-2 flex gap-2">
          <select value={filter.lifecycle} onChange={(e) => setFilter({ ...filter, lifecycle: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs"><option value="">All lifecycle</option><option value="PRODUCTION">PRODUCTION</option><option value="STAGING">STAGING</option></select>
          <select value={filter.criticality} onChange={(e) => setFilter({ ...filter, criticality: e.target.value })} className="rounded border bg-canvas px-2 py-1 text-xs"><option value="">All criticality</option><option value="critical">critical</option><option value="high">high</option></select>
          <button type="button" onClick={async () => { const res = await listApplications(selectedProjectId, { lifecycle: filter.lifecycle || undefined, criticality: filter.criticality || undefined }).catch(()=>({applications:[]})); setApps(res?.applications || res?.data?.applications || []); }} className="rounded border px-2 py-1 text-xs">Filter</button>
        </div>
        {apps.length === 0 ? <p className="mt-2 text-xs text-muted">No applications. Create one.</p> : (
          <div className="mt-3 space-y-2">
            {apps.map((a) => (
              <div key={a.id} onClick={() => { setSelected(a); loadDetail(a.id); }} className={`cursor-pointer rounded border p-3 ${selected?.id === a.id ? "bg-canvas border-primary" : "bg-canvas hover:bg-surface-hover"}`}>
                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold">{a.name}</p>
                  <span className="text-xs text-muted">{a.lifecycle} • {a.criticality}</span>
                </div>
                <p className="text-xs text-muted">{a.application_type} • {a.status} {a.primary_domain ? `• ${a.primary_domain}` : ""}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {selected && (
        <div className="space-y-4">
          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Overview — {selected.name}</h3>
            {risk && <div className="mt-2 flex items-center gap-2"><RiskBadge tier={risk.tier} /><span className="text-sm font-bold">{risk.score}/100</span><span className="text-xs text-muted">{risk.factors?.slice(0,3).join(" • ") || "No factors"}</span></div>}
            {summary && (
              <div className="mt-3 grid gap-2 sm:grid-cols-4">
                <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Findings</p><p className="text-sm font-bold">{summary.findings?.total ?? 0}</p><p className="text-xs text-muted">C:{summary.findings?.by_severity?.critical ?? 0} H:{summary.findings?.by_severity?.high ?? 0}</p></div>
                <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Assets</p><p className="text-sm font-bold">{summary.assets?.total ?? 0}</p></div>
                <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Exposure</p><p className="text-sm font-bold">{exposure?.internet_facing ? "Internet-facing" : "Internal"}</p></div>
                <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Owner</p><p className="text-sm font-bold">{selected.owner_user_id ? selected.owner_user_id.slice(0,8) : "UNKNOWN"}</p></div>
              </div>
            )}
          </div>

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Architecture Context</h3>
            <p className="text-xs text-muted">Repository • APIs • External assets • Containers • Cloud resources — via explicit asset linking with confidence.</p>
            <div className="mt-2">
              {assets.length === 0 ? <p className="text-xs text-muted">No linked assets.</p> : (
                <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="text-left text-muted"><th className="p-1">Asset</th><th className="p-1">Type</th><th className="p-1">Relationship</th><th className="p-1">Confidence</th></tr></thead><tbody>{assets.map((a)=> <tr key={a.id} className="border-t"><td className="p-1 font-mono">{a.value.slice(0,40)}</td><td className="p-1">{a.asset_type}</td><td className="p-1">{a.relationship_type}</td><td className="p-1">{a.confidence}</td></tr>)}</tbody></table></div>
              )}
            </div>
          </div>

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Findings</h3>
            <p className="text-xs text-muted">Aggregated SAST • SCA • secrets • container • IaC • API • DAST — evidence redacted, scanner provenance preserved.</p>
            {findings.length === 0 ? <p className="mt-2 text-xs text-muted">No findings linked.</p> : (
              <div className="mt-2 space-y-1">{findings.slice(0,20).map((f)=> <div key={f.id} className="rounded border bg-canvas p-2"><p className="text-xs font-semibold">{f.title.slice(0,80)} • {f.severity} • {f.scanner}</p><p className="text-xs text-muted truncate">{f.evidence ? f.evidence.slice(0,120) : ""} {f.cve ? `• ${f.cve}` : ""}</p></div>)}</div>
            )}
          </div>

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Correlations</h3>
            <p className="text-xs text-muted">Same application / repository / source file / package / API / container / root cause — via E12 with confidence HIGH/MEDIUM/LOW.</p>
            {correlations.length === 0 ? <p className="mt-2 text-xs text-muted">No correlations.</p> : (
              <div className="mt-2 space-y-1">{correlations.map((c)=> <div key={c.id} className="rounded border bg-canvas p-2"><p className="text-xs font-semibold">{c.correlation_type || c.type} • {c.confidence}</p><p className="text-xs text-muted">{c.explanation || c.title || ""}</p></div>)}</div>
            )}
          </div>

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Exposure</h3>
            {exposure ? <div className="text-xs"><p>Internet-facing: {exposure.internet_facing ? "YES" : "NO"}</p><p>External assets: {exposure.external_assets?.length ?? 0} • API endpoints: {exposure.api_endpoints?.length ?? 0} • Cloud: {exposure.cloud_resources?.length ?? 0}</p></div> : <p className="text-xs text-muted">No exposure data.</p>}
          </div>

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Risk Explanation</h3>
            {risk ? <div className="text-xs"><p className="font-semibold">{risk.tier} — {risk.score}/100</p><ul className="list-disc pl-4">{risk.factors?.map((f,i)=><li key={i}>{f}</li>)}</ul></div> : <p className="text-xs text-muted">No risk.</p>}
          </div>

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Investigation</h3>
            <button type="button" onClick={async()=>{ try{ await createApplicationInvestigation(selectedProjectId, selected.id, {}); setMsg("Investigation created"); }catch(e){ setMsg(e.message);} }} className="rounded border px-2 py-1 text-xs">Create Investigation from Application</button>
          </div>
        </div>
      )}

      <p className="text-xs text-muted">Evidence-first • deterministic • tenant-isolated • no AI • no graph DB. Each relationship needs provenance.</p>
    </div>
  );
}
