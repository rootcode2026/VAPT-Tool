"use client";
/* eslint-disable react-hooks/set-state-in-effect */
import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import { useProjectContext } from "@/lib/project-context";
import { listApplications } from "@/lib/api/applications";
import { getSecurityContext, getBlastRadius, getExposureChain, getImpact, getPriorities, getTopRisks, getPrioritySummary } from "@/lib/api/securityIntelligence";

export default function SecurityIntelligencePage() {
  const { selectedProjectId, status } = useProjectContext();
  const [apps, setApps] = useState([]);
  const [subject, setSubject] = useState({ type: "application", id: "" });
  const [ctx, setCtx] = useState(null);
  const [blast, setBlast] = useState(null);
  const [chain, setChain] = useState(null);
  const [impact, setImpact] = useState(null);
  const [priorities, setPriorities] = useState([]);
  const [topRisks, setTopRisks] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const loadApps = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    try {
      const [res, pri, top, sum] = await Promise.all([
        listApplications(selectedProjectId, { limit: 50 }).catch(() => ({ applications: [] })),
        getPriorities(selectedProjectId, { limit: 10 }).catch(() => ({ priorities: [] })),
        getTopRisks(selectedProjectId).catch(() => null),
        getPrioritySummary(selectedProjectId).catch(() => null),
      ]);
      setApps(res?.applications || res?.data?.applications || []);
      setPriorities(pri?.priorities || pri?.data?.priorities || []);
      setTopRisks(top);
      setSummary(sum);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, [selectedProjectId]);

  useEffect(() => { if (status === "ready" && selectedProjectId) loadApps(); }, [status, selectedProjectId, loadApps]);

  const loadAll = async () => {
    if (!selectedProjectId || !subject.id) { setMsg("Select subject"); return; }
    setMsg("");
    try {
      const [c, b, ch, im] = await Promise.all([
        getSecurityContext(selectedProjectId, subject.type, subject.id).catch(e => { throw e; }),
        getBlastRadius(selectedProjectId, subject.type, subject.id).catch(() => null),
        getExposureChain(selectedProjectId, subject.type, subject.id).catch(() => null),
        getImpact(selectedProjectId, subject.type, subject.id).catch(() => null),
      ]);
      setCtx(c); setBlast(b); setChain(ch); setImpact(im);
    } catch (e) { setMsg(e.message || "Failed to load"); }
  };

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project selected" description="Select a project to view security intelligence." />;
  if (loading) return <div><PageHeader title="Security Intelligence" description="Deterministic exposure chains, blast radius and impact" /><LoadingState message="Loading..." /></div>;
  if (error) return <div><PageHeader title="Security Intelligence" description="Deterministic" /><ErrorState title="Unable to load" message={error} onRetry={loadApps} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Security Intelligence" description={`Project: ${selectedProjectId} — prioritization, exposure chains, blast radius, impact, evidence-backed relationships (no AI, no graph DB).`} />

      {summary && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Priority Summary</h3>
          <div className="mt-2 grid gap-2 sm:grid-cols-4">
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Critical Priority</p><p className="text-sm font-bold">{summary.by_tier?.CRITICAL ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">High Priority</p><p className="text-sm font-bold">{summary.by_tier?.HIGH ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Total Findings</p><p className="text-sm font-bold">{summary.total_findings ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">SLA Breached</p><p className="text-sm font-bold">{summary.sla_breached ?? 0}</p></div>
          </div>
          {summary.top_priority && <p className="mt-2 text-xs">Top: {summary.top_priority.finding_id.slice(0,8)} • {summary.top_priority.tier} {summary.top_priority.score} • {summary.top_priority.reasons?.[0] || ""}</p>}
        </div>
      )}

      {priorities.length > 0 && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Priority Ranking — What to fix first</h3>
          <p className="text-xs text-muted">Deterministic 0-100, tier CRITICAL≥80 HIGH≥60 MEDIUM≥40 LOW≥20, same evidence → same score. Explainable per factor.</p>
          <div className="mt-2 space-y-1">{priorities.slice(0,8).map(p=> <div key={p.finding_id} className="flex items-center justify-between rounded border bg-canvas p-2 text-xs"><div><span className="font-semibold">{p.finding_id.slice(0,8)}</span> <span className="font-bold">{p.tier} {p.score}</span> <span className="text-muted">{p.reasons?.[0] || ""}</span></div><span className="text-muted">{p.severity}</span></div>)}</div>
        </div>
      )}

      {topRisks && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Top Risks</h3>
          <div className="text-xs">
            <p>Top findings: {(topRisks.top_findings||[]).map(f=> `${f.finding_id.slice(0,6)} ${f.tier} ${f.score}`).join(", ") || "—"}</p>
            <p>Top apps: {(topRisks.top_applications||[]).map(a=> a.name).join(", ") || "—"}</p>
            <p>Top attack paths: {(topRisks.top_attack_paths||[]).map(p=> p.path_type).join(", ") || "—"}</p>
            {topRisks.recently_worsened_exposure?.length >0 && <p>Recently worsened: {topRisks.recently_worsened_exposure.map(e=> e.value).join(", ")}</p>}
          </div>
        </div>
      )}

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Subject</h3>
        <p className="text-xs text-muted">Select application or finding/asset to build deterministic context (bounded, evidence-first).</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <select value={subject.type} onChange={(e)=>setSubject({...subject, type:e.target.value})} className="rounded border bg-canvas px-2 py-1 text-xs">
            <option value="application">application</option><option value="finding">finding</option><option value="asset">asset</option><option value="external_asset">external_asset</option><option value="cloud_resource">cloud_resource</option><option value="attack_path">attack_path</option>
          </select>
          {subject.type === "application" ? (
            <select value={subject.id} onChange={(e)=>setSubject({...subject, id:e.target.value})} className="rounded border bg-canvas px-2 py-1 text-xs w-48">
              <option value="">Select application</option>
              {apps.map(a=> <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
          ) : (
            <input placeholder="Subject ID (uuid)" value={subject.id} onChange={(e)=>setSubject({...subject, id:e.target.value})} className="rounded border bg-canvas px-2 py-1 text-xs w-64" />
          )}
          <button type="button" onClick={loadAll} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Load Context</button>
        </div>
        {msg && <p className="mt-2 text-xs text-muted">{msg}</p>}
      </div>

      {ctx && (
        <div className="space-y-4">
          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Security Context — {ctx.subject_type}:{ctx.subject_id.slice(0,8)} • {ctx.confidence}</h3>
            <p className="text-xs text-muted">Fingerprint {ctx.fingerprint.slice(0,16)} • {ctx.generated_at?.slice(0,19)} • Assets {ctx.assets.length} • Findings {ctx.findings.length} • Apps {ctx.applications.length}</p>
            <div className="mt-3 grid gap-2 sm:grid-cols-3">
              <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Related Applications</p><p className="text-sm font-bold">{ctx.applications.length}</p></div>
              <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Related Findings</p><p className="text-sm font-bold">{ctx.findings.length}</p></div>
              <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Evidence Chains</p><p className="text-sm font-bold">{ctx.evidence_chains.length}</p></div>
            </div>
            <div className="mt-3">
              <h4 className="text-xs font-semibold">Evidence Chains (deterministic, confidence)</h4>
              <div className="mt-1 space-y-1">{ctx.evidence_chains.slice(0,8).map(e=> <div key={e.id} className="rounded border bg-canvas p-2 text-xs"><span className="font-mono">{e.source}</span> → {e.target} <span className="text-muted">[{e.confidence}]</span> <span className="text-muted">{e.explanation.slice(0,100)}</span></div>)}</div>
            </div>
          </div>

          {chain && (
            <div className="rounded-md border bg-surface p-4">
              <h3 className="text-sm font-semibold">Exposure Chain</h3>
              <div className="mt-2 space-y-1">{chain.chain.map(s=> <div key={s.step} className="flex gap-2 text-xs"><span className="font-bold">{s.step}.</span><span className="font-mono">{s.type}</span><span>{s.value.slice(0,50)}</span><span className="text-muted">[{s.confidence}]</span></div>)}</div>
            </div>
          )}
          {blast && (
            <div className="rounded-md border bg-surface p-4">
              <h3 className="text-sm font-semibold">Blast Radius — depth {blast.depth} • {blast.confidence}</h3>
              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Affected Assets</p><p className="text-sm font-bold">{blast.affected_assets.length}</p></div>
                <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Affected Apps</p><p className="text-sm font-bold">{blast.affected_applications.length}</p></div>
                <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Related Findings</p><p className="text-sm font-bold">{blast.related_findings.length}</p></div>
              </div>
              <p className="mt-2 text-xs text-muted">Traversed {blast.evidence.traversed_assets} assets, depth {blast.evidence.depth}, bounded MAX_ASSETS 500, MAX_DEPTH 6</p>
            </div>
          )}
          {impact && (
            <div className="rounded-md border bg-surface p-4">
              <h3 className="text-sm font-semibold">Impact — {impact.priority}</h3>
              <ul className="mt-2 list-disc pl-4 text-xs">{impact.factors.map((f,i)=><li key={i}>{f}</li>)}</ul>
              <p className="mt-2 text-xs text-muted">Internet: {impact.internet_exposure ? "YES" : "NO"} • Criticality: {impact.application_criticality} • Cloud: {impact.cloud_exposure ? "YES" : "NO"} • Dependent: {impact.dependent_assets}</p>
            </div>
          )}

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Findings & Evidence</h3>
            <div className="mt-2 space-y-1">{ctx.findings.slice(0,10).map(f=> <div key={f.id} className="rounded border bg-canvas p-2 text-xs"><span className="font-semibold">{f.title.slice(0,60)}</span> <span className="text-muted">{f.severity} • {f.scanner}</span><span className="ml-2 text-muted">{f.evidence?.slice(0,60) || ""}</span></div>)}</div>
            <p className="mt-2 text-xs text-muted">All secret evidence shows [REDACTED]; no passwords/tokens in response.</p>
          </div>

          <div className="rounded-md border bg-surface p-4">
            <h3 className="text-sm font-semibold">Remediation • Validation • Investigation • Changes</h3>
            <div className="text-xs">
              <p>Remediation: {ctx.remediation.length} records (open/blocked)</p>
              <p>Validations: {ctx.validations.length} • Retests: {ctx.retests.length}</p>
              <p>Investigations: {ctx.investigations.length} • Changes: {ctx.changes.length}</p>
            </div>
          </div>
        </div>
      )}
      <p className="text-xs text-muted">Deterministic • SHA-256 fingerprints • bounded • tenant-isolated • no AI • no graph DB • evidence-first</p>
    </div>
  );
}
