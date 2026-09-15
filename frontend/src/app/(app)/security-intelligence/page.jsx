"use client";
/* eslint-disable react-hooks/set-state-in-effect */
import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import { useProjectContext } from "@/lib/project-context";
import { listApplications } from "@/lib/api/applications";
import { getSecurityContext, getBlastRadius, getExposureChain, getImpact, getPriorities, getTopRisks, getPrioritySummary, getTrends, getAttackSurface, getAttackDistribution, getAttackHotspots, getAttackConcentration, getAttackCoverage, getAttackTechnology, getAttackCloud, getAttackApplications, getAttackTop, getExposureChains, getExposureDecision, getExposureConcentration, getChangeExposure, getCoverageF5, getRootCause, getScorecard, getHistoryF6, getRecurringExposure, getRemediationEffectiveness, getAttackPathHistory, getDecisionCenter, getAttentionQueue, getExecutiveSummary, getSecuritySnapshot, getRecentChanges } from "@/lib/api/securityIntelligence";

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
  const [trends, setTrends] = useState(null);
  const [trendsWindow, setTrendsWindow] = useState("7d");
  const [attackSurface, setAttackSurface] = useState(null);
  const [distribution, setDistribution] = useState(null);
  const [hotspots, setHotspots] = useState(null);
  const [concentration, setConcentration] = useState(null);
  const [coverage, setCoverage] = useState(null);
  const [tech, setTech] = useState(null);
  const [cloud, setCloud] = useState(null);
  const [appExp, setAppExp] = useState(null);
  const [top, setTop] = useState(null);
  const [exposureChains, setExposureChains] = useState(null);
  const [decision, setDecision] = useState(null);
  const [expConc, setExpConc] = useState(null);
  const [changeExp, setChangeExp] = useState(null);
  const [cov5, setCov5] = useState(null);
  const [rootCause, setRootCause] = useState(null);
  const [scorecard, setScorecard] = useState(null);
  const [historyF6, setHistoryF6] = useState(null);
  const [recurring, setRecurring] = useState(null);
  const [remEff, setRemEff] = useState(null);
  const [aph, setAph] = useState(null);
  const [decisionCenter, setDecisionCenter] = useState(null);
  const [attentionQueue, setAttentionQueue] = useState(null);
  const [execSummary, setExecSummary] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [recentChanges, setRecentChanges] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const loadApps = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    try {
      const [res, pri, topR, sum, tr, surf, dist, hs, conc, cov, tc, cl, ae, tp, ech, dec, econc, chExp, cov5d, rc, sc, hf6, rec, reff, aphd, dc, aq, es, snap, rch] = await Promise.all([
        listApplications(selectedProjectId, { limit: 50 }).catch(() => ({ applications: [] })),
        getPriorities(selectedProjectId, { limit: 10 }).catch(() => ({ priorities: [] })),
        getTopRisks(selectedProjectId).catch(() => null),
        getPrioritySummary(selectedProjectId).catch(() => null),
        getTrends(selectedProjectId, { window: trendsWindow }).catch(() => null),
        getAttackSurface(selectedProjectId).catch(() => null),
        getAttackDistribution(selectedProjectId).catch(() => null),
        getAttackHotspots(selectedProjectId).catch(() => null),
        getAttackConcentration(selectedProjectId).catch(() => null),
        getAttackCoverage(selectedProjectId).catch(() => null),
        getAttackTechnology(selectedProjectId).catch(() => null),
        getAttackCloud(selectedProjectId).catch(() => null),
        getAttackApplications(selectedProjectId).catch(() => null),
        getAttackTop(selectedProjectId).catch(() => null),
        getExposureChains(selectedProjectId).catch(() => null),
        getExposureDecision(selectedProjectId).catch(() => null),
        getExposureConcentration(selectedProjectId).catch(() => null),
        getChangeExposure(selectedProjectId).catch(() => null),
        getCoverageF5(selectedProjectId).catch(() => null),
        getRootCause(selectedProjectId).catch(() => null),
        getScorecard(selectedProjectId, { window: trendsWindow }).catch(() => null),
        getHistoryF6(selectedProjectId, { window: trendsWindow }).catch(() => null),
        getRecurringExposure(selectedProjectId).catch(() => null),
        getRemediationEffectiveness(selectedProjectId).catch(() => null),
        getAttackPathHistory(selectedProjectId).catch(() => null),
        getDecisionCenter(selectedProjectId).catch(() => null),
        getAttentionQueue(selectedProjectId).catch(() => null),
        getExecutiveSummary(selectedProjectId).catch(() => null),
        getSecuritySnapshot(selectedProjectId).catch(() => null),
        getRecentChanges(selectedProjectId).catch(() => null),
      ]);
      setApps(res?.applications || res?.data?.applications || []);
      setPriorities(pri?.priorities || pri?.data?.priorities || []);
      setTopRisks(topR?.data || topR);
      setSummary(sum?.data || sum);
      setTrends(tr?.data || tr);
      setAttackSurface(surf?.data || surf);
      setDistribution(dist?.data || dist);
      setHotspots(hs?.data || hs);
      setConcentration(conc?.data || conc);
      setCoverage(cov?.data || cov);
      setTech(tc?.data || tc);
      setCloud(cl?.data || cl);
      setAppExp(ae?.data || ae);
      setTop(tp?.data || tp);
      setExposureChains(ech?.data || ech);
      setDecision(dec?.data || dec);
      setExpConc(econc?.data || econc);
      setChangeExp(chExp?.data || chExp);
      setCov5(cov5d?.data || cov5d);
      setRootCause(rc?.data || rc);
      setScorecard(sc?.data || sc);
      setHistoryF6(hf6?.data || hf6);
      setRecurring(rec?.data || rec);
      setRemEff(reff?.data || reff);
      setAph(aphd?.data || aphd);
      setDecisionCenter(dc?.data || dc);
      setAttentionQueue(aq?.data || aq);
      setExecSummary(es?.data || es);
      setSnapshot(snap?.data || snap);
      setRecentChanges(rch?.data || rch);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, [selectedProjectId, trendsWindow]);

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
      setCtx(c?.data || c); setBlast(b?.data || b); setChain(ch?.data || ch); setImpact(im?.data || im);
    } catch (e) { setMsg(e.message || "Failed to load"); }
  };

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project selected" description="Select a project to view security intelligence." />;
  if (loading) return <div><PageHeader title="Security Intelligence" description="Deterministic exposure chains, blast radius and impact" /><LoadingState message="Loading..." /></div>;
  if (error) return <div><PageHeader title="Security Intelligence" description="Deterministic" /><ErrorState title="Unable to load" message={error} onRetry={loadApps} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Security Intelligence" description={`Project: ${selectedProjectId} — prioritization, exposure chains, blast radius, impact, risk evolution, attack surface analytics (no AI, no graph DB).`} />

      {attackSurface && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Attack Surface Overview</h3>
          <p className="text-xs text-muted">Deterministic • {attackSurface.data_quality?.status || "SUFFICIENT"} • generated {attackSurface.generated_at?.slice(0,19)}</p>
          <div className="mt-2 grid gap-2 sm:grid-cols-4">
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Total Assets</p><p className="text-sm font-bold">{attackSurface.total_assets ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">External Assets</p><p className="text-sm font-bold">{attackSurface.externally_reachable_assets ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Applications</p><p className="text-sm font-bold">{attackSurface.applications ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Cloud Resources</p><p className="text-sm font-bold">{attackSurface.cloud_resources ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">APIs</p><p className="text-sm font-bold">{attackSurface.apis ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Attack Paths</p><p className="text-sm font-bold">{attackSurface.attack_paths ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Critical Findings</p><p className="text-sm font-bold">{attackSurface.critical_findings ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">High Findings</p><p className="text-sm font-bold">{attackSurface.high_findings ?? 0}</p></div>
          </div>
          <div className="mt-2 text-xs text-muted">Repositories {attackSurface.repositories ?? 0} • Source {attackSurface.source_files ?? 0} • Containers {attackSurface.containers ?? 0} • Dependencies {attackSurface.dependencies ?? 0} • Technologies {attackSurface.technologies ?? 0} • Services {attackSurface.services ?? 0}</div>
        </div>
      )}

      {distribution && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Exposure Distribution</h3>
          <p className="text-xs text-muted">External • Cloud • Application • API • Network • Container • Code • Dependency • Secrets • IaC</p>
          <div className="mt-2 overflow-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-muted"><th className="p-1 text-left">Category</th><th className="p-1">Total</th><th className="p-1">Exposed</th><th className="p-1">Critical</th><th className="p-1">High</th><th className="p-1">%</th></tr></thead>
              <tbody>
                {(distribution.distribution || distribution || []).slice(0,10).map(d=> (
                  <tr key={d.category} className="border-t"><td className="p-1 font-mono">{d.category}</td><td className="p-1 text-center">{d.total}</td><td className="p-1 text-center">{d.exposed}</td><td className="p-1 text-center">{d.critical}</td><td className="p-1 text-center">{d.high}</td><td className="p-1 text-center">{d.percentage}%</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {hotspots && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Security Hotspots</h3>
          <p className="text-xs text-muted">Top hotspots — deterministic ranking by priority → severity → signal count → id</p>
          <div className="mt-2 space-y-1">
            {(hotspots.hotspots || []).slice(0,10).map(h=> (
              <div key={h.subject_id} className="flex flex-wrap items-center justify-between rounded border bg-canvas p-2 text-xs">
                <div><span className="font-mono">{h.subject_type}:{h.subject_id.slice(0,8)}</span> <span className="font-semibold">{h.name?.slice(0,40)}</span> <span className="text-muted">P{h.priority} {h.severity}</span></div>
                <div className="text-muted">{h.exposure_signals?.slice(0,3).join(", ")}</div>
                <div className="text-muted">{h.reasons?.[0]?.slice(0,60) || ""}</div>
              </div>
            ))}
            {(!hotspots.hotspots || hotspots.hotspots.length===0) && <p className="text-xs text-muted">No hotspots — insufficient exposure signals</p>}
          </div>
        </div>
      )}

      {concentration && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Concentration</h3>
          <p className="text-xs text-muted">Where exposure and risk are concentrated — top 10 share</p>
          <div className="mt-2 grid gap-2 sm:grid-cols-3 text-xs">
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Critical/High in top 10 assets</p><p className="font-bold">{concentration.concentration?.top_assets_critical_high_pct ?? 0}%</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Attack paths in top 10 assets</p><p className="font-bold">{concentration.concentration?.top_assets_attack_path_pct ?? 0}%</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">External in top apps</p><p className="font-bold">{concentration.concentration?.top_applications_external_pct ?? 0}%</p></div>
          </div>
          {concentration.risk_concentration && (
            <div className="mt-2 text-xs"><p>Total priority {concentration.risk_concentration.total_priority} • Avg {concentration.risk_concentration.average_priority} • Critical {concentration.risk_concentration.critical_priority_count}</p></div>
          )}
        </div>
      )}

      {coverage && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Coverage Gaps</h3>
          <p className="text-xs text-muted">Evidence-backed gaps — NOT_ASSESSED vs vulnerable distinction</p>
          <div className="mt-2 space-y-1">
            {(coverage.coverage_gaps || []).slice(0,10).map(g=> (
              <div key={g.subject_id + g.gap_type} className="rounded border bg-canvas p-2 text-xs">
                <span className="font-mono">{g.gap_type}</span> <span className="font-semibold">{g.name?.slice(0,40)}</span> <span className="text-muted">{g.status}</span>
                <p className="text-muted">{g.evidence?.slice(0,80)}</p>
                <p className="text-muted">→ {g.recommendation?.slice(0,80)}</p>
              </div>
            ))}
            {(!coverage.coverage_gaps || coverage.coverage_gaps.length===0) && <p className="text-xs text-muted">No coverage gaps</p>}
          </div>
        </div>
      )}

      {tech && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Technology & Service Concentration</h3>
          <div className="mt-2 grid gap-4 sm:grid-cols-2 text-xs">
            <div>
              <p className="font-semibold">Top Technologies</p>
              {(tech.technologies || []).slice(0,5).map(t=> <div key={t.technology} className="flex justify-between border-b py-1"><span>{t.technology}</span><span className="text-muted">{t.assets} assets • {t.critical} crit</span></div>)}
              {(!tech.technologies || tech.technologies.length===0) && <p className="text-muted">No technology data</p>}
            </div>
            <div>
              <p className="font-semibold">Top Services</p>
              {(tech.services || []).slice(0,5).map(s=> <div key={s.service} className="flex justify-between border-b py-1"><span>{s.service}</span><span className="text-muted">{s.assets} assets • {s.critical} crit</span></div>)}
              {(!tech.services || tech.services.length===0) && <p className="text-muted">No service data</p>}
            </div>
          </div>
        </div>
      )}

      {cloud && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Cloud Exposure Analytics</h3>
          <div className="mt-2 grid gap-2 sm:grid-cols-4 text-xs">
            <div className="rounded border bg-canvas p-2"><p className="text-muted">AWS</p><p className="font-bold">{cloud.aws_resources ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">GCP</p><p className="font-bold">{cloud.gcp_resources ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Azure</p><p className="font-bold">{cloud.azure_resources ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Exposed Cloud</p><p className="font-bold">{cloud.externally_exposed_cloud_resources ?? 0}</p></div>
          </div>
          <p className="mt-2 text-xs text-muted">Attack paths {cloud.cloud_attack_paths ?? 0} • Critical {cloud.critical_attack_paths ?? 0} • IAM {cloud.privileged_iam_exposure ?? 0} • Storage {cloud.public_storage_exposure ?? 0}</p>
        </div>
      )}

      {appExp && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Application Exposure Analytics</h3>
          <div className="mt-2 grid gap-2 sm:grid-cols-4 text-xs">
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Total Apps</p><p className="font-bold">{appExp.total_applications ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Production</p><p className="font-bold">{appExp.production_applications ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Critical Apps</p><p className="font-bold">{appExp.critical_applications ?? 0}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Internet-Facing</p><p className="font-bold">{appExp.applications_with_internet_exposure ?? 0}</p></div>
          </div>
          <p className="mt-2 text-xs text-muted">Secrets {appExp.applications_with_secrets ?? 0} • Dependencies {appExp.applications_with_vulnerable_dependencies ?? 0} • Container {appExp.applications_with_container_findings ?? 0} • IaC {appExp.applications_with_iac_findings ?? 0}</p>
        </div>
      )}

      {top && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Top Risk Hotspots</h3>
          <div className="mt-2 grid gap-4 sm:grid-cols-2 text-xs">
            <div><p className="font-semibold">Top Assets by Risk</p>{(top.top_assets || []).slice(0,5).map(a=> <div key={a.asset_id} className="flex justify-between border-b py-1"><span className="font-mono">{a.asset_id.slice(0,6)}</span><span>P{a.priority} {a.severity}</span></div>)}</div>
            <div><p className="font-semibold">Top Applications</p>{(top.top_applications || []).slice(0,5).map(a=> <div key={a.application_id} className="flex justify-between border-b py-1"><span>{a.name?.slice(0,20)}</span><span>{a.score}</span></div>)}</div>
          </div>
        </div>
      )}

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

      {trends && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Risk Evolution — {trendsWindow} <span className="text-muted">({trends.data_quality})</span></h3>
          <div className="mt-2 flex gap-2">
            <button type="button" onClick={()=>{ setTrendsWindow("7d"); }} className={`rounded border px-2 py-1 text-xs ${trendsWindow==="7d"?"bg-primary text-primary-foreground":""}`}>7d</button>
            <button type="button" onClick={()=>{ setTrendsWindow("30d"); }} className={`rounded border px-2 py-1 text-xs ${trendsWindow==="30d"?"bg-primary text-primary-foreground":""}`}>30d</button>
            <button type="button" onClick={()=>{ setTrendsWindow("90d"); }} className={`rounded border px-2 py-1 text-xs ${trendsWindow==="90d"?"bg-primary text-primary-foreground":""}`}>90d</button>
            <button type="button" onClick={()=> loadApps()} className="rounded border px-2 py-1 text-xs">Refresh</button>
          </div>
          <div className="mt-3">
            <p className="text-sm font-bold">Posture {trends.posture.tier} {trends.posture.score} (prev {trends.posture.previous_score}) Δ {trends.posture.delta} • {trends.posture.direction}</p>
            <p className="text-xs text-muted">Confidence {trends.posture.confidence} • {trends.reasons.slice(0,2).join(" • ")}</p>
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-3">
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Critical</p><p className="text-xs">Current {trends.metrics.current.critical} Prev {trends.metrics.previous.critical} Δ {trends.trends.critical.delta} ({trends.trends.critical.direction})</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Attack Paths</p><p className="text-xs">Current {trends.metrics.current.attack_paths} Prev {trends.metrics.previous.attack_paths} Δ {trends.trends.attack_paths.delta}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs text-muted">Internet Exposure</p><p className="text-xs">Current {trends.metrics.current.externally_reachable} Prev {trends.metrics.previous.externally_reachable} Δ {trends.trends.externally_reachable.delta}</p></div>
          </div>
          <div className="mt-3">
            <h4 className="text-xs font-semibold">Why Risk Changed</h4>
            <ul className="list-disc pl-4 text-xs">{trends.reasons.map((r,i)=><li key={i}>{r}</li>)}</ul>
          </div>
          {trends.top_worsening?.length>0 && <div className="mt-3"><h4 className="text-xs font-semibold">Top Worsening</h4><div className="text-xs">{trends.top_worsening.slice(0,5).map(w=> <div key={w.id} className="rounded border bg-canvas p-1 mt-1">{w.type}:{w.id.slice(0,6)} — {w.reason}</div>)}</div></div>}
          {trends.top_improving?.length>0 && <div className="mt-3"><h4 className="text-xs font-semibold">Top Improving</h4><div className="text-xs">{trends.top_improving.slice(0,5).map(w=> <div key={w.id} className="rounded border bg-canvas p-1 mt-1">{w.type}:{w.id.slice(0,6)} — {w.reason}</div>)}</div></div>}
        </div>
      )}

      {/* F5 Security Exposure Decision */}
      {decision && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Security Exposure Decision — What Needs Attention</h3>
          <p className="text-xs text-muted">Top exposures • worsening • coverage gaps • validation failures — deterministic, F2 priority</p>
          <div className="mt-2 text-xs">
            <p><span className="font-semibold">Top exposures:</span> {(decision.top_exposures||[]).slice(0,3).map(e=> `${e.subject_type}:${e.subject_id.slice(0,6)} P${e.priority}`).join(", ") || "—"}</p>
            <p><span className="font-semibold">Recent worsening:</span> {(decision.recent_worsening||[]).slice(0,3).map(w=> `${w.type}:${w.id.slice(0,6)}`).join(", ") || "—"}</p>
            <p><span className="font-semibold">Coverage gaps:</span> {(decision.major_coverage_gaps||[]).slice(0,3).map(g=> g.gap_type).join(", ") || "—"} • Validation failures {decision.validation_failures} • Overdue {decision.overdue_remediation} • Reopened {decision.reopened_issues}</p>
            {decision.why_it_matters?.length>0 && <ul className="list-disc pl-4 mt-1">{decision.why_it_matters.slice(0,3).map((w,i)=><li key={i}>{w}</li>)}</ul>}
          </div>
        </div>
      )}
      {exposureChains && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Exposure Chains</h3>
          <p className="text-xs text-muted">Evidence-backed Internet → External → App → Finding → Cloud → Attack Path (MAX_CHAINS 100, MAX_DEPTH 6)</p>
          <div className="mt-2 space-y-1">{(exposureChains.chains||[]).slice(0,5).map(c=> <div key={c.chain_id} className="rounded border bg-canvas p-2 text-xs"><p className="font-mono">P{c.priority} {c.severity} [{c.confidence}]</p><p>{c.explanation.slice(0,120)}</p><p className="text-muted">Entry {c.entry_asset?.value?.slice(0,20) || "—"} → Finding {c.finding?.title?.slice(0,30) || "—"} {c.attack_path ? `→ ${c.attack_path.path_type}` : ""}</p></div>)}</div>
          {(!exposureChains.chains||exposureChains.chains.length===0) && <p className="text-xs text-muted">No exposure chains — insufficient evidence</p>}
        </div>
      )}
      {expConc && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Exposure Concentration (F5)</h3>
          <p className="text-xs text-muted">Tier {expConc.concentration_tier || "—"} • Top assets {expConc.concentration?.top_assets_critical_high_pct ?? 0}% • Details bounded</p>
          <div className="mt-2 text-xs">{expConc.concentration_tier && <p>Concentration tier: {expConc.concentration_tier}</p>}</div>
        </div>
      )}
      {changeExp && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Recent Change → Exposure</h3>
          <p className="text-xs text-muted">TEMPORALLY_ASSOCIATED — change type + time relationship, not proven causality</p>
          <div className="mt-2 space-y-1">{(changeExp.correlations||[]).slice(0,5).map(r=> <div key={r.change_event.id} className="rounded border bg-canvas p-2 text-xs"><p>{r.change_event.change_type} on {r.affected_asset.value} — {r.time_relationship} [{r.confidence}]</p><p className="text-muted">{r.explanation.slice(0,100)}</p></div>)}</div>
          {(!changeExp.correlations||changeExp.correlations.length===0) && <p className="text-xs text-muted">No recent change→exposure correlations</p>}
        </div>
      )}
      {cov5 && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Security Coverage (F5)</h3>
          <p className="text-xs text-muted">Overall {cov5.overall_coverage} • {cov5.total_gaps} gaps — COVERAGE_GAP / NOT_ASSESSED / ASSESSED distinction</p>
          <div className="mt-2 space-y-1">{(cov5.coverage_gaps||[]).slice(0,5).map(g=> <div key={g.subject_id+g.gap_type} className="rounded border bg-canvas p-2 text-xs"><span className="font-mono">{g.gap_type}</span> <span className="text-muted">{g.status}</span><p className="text-muted">{g.evidence?.slice(0,70)}</p></div>)}</div>
        </div>
      )}
      {rootCause && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Root-Cause Context</h3>
          <p className="text-xs text-muted">RELATED_ROOT_CAUSE_CANDIDATE from E12 correlations — same asset/CVE/CWE/package</p>
          <div className="mt-2 space-y-1">{(rootCause.candidates||[]).slice(0,5).map(c=> <div key={c.canonical_key} className="rounded border bg-canvas p-2 text-xs"><p>{c.root_cause_candidate} [{c.confidence}] — {c.finding_count} findings</p><p className="text-muted">{c.explanation.slice(0,80)}</p></div>)}</div>
          {(!rootCause.candidates||rootCause.candidates.length===0) && <p className="text-xs text-muted">No root-cause candidates</p>}
        </div>
      )}
      {scorecard && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Security Decision History — Scorecard</h3>
          <p className="text-xs text-muted">Overall {scorecard.overall_direction} • Strongest {scorecard.strongest_improvement} • Worst {scorecard.biggest_deterioration} • Confidence {scorecard.confidence}</p>
          <div className="mt-2 text-xs">
            <p>Highest recurring: {scorecard.highest_recurring?.subject_id?.slice(0,8) || "—"} ({scorecard.highest_recurring?.recurrence_count || 0})</p>
            <p>Biggest unresolved: {scorecard.biggest_unresolved_exposure?.name?.slice(0,30) || scorecard.biggest_unresolved_exposure?.subject_id?.slice(0,8) || "—"}</p>
            <p>Remediation failures: {scorecard.remediation_failure_area}</p>
            <p>Evidence: {scorecard.evidence?.join(" • ")}</p>
          </div>
        </div>
      )}
      {historyF6 && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Exposure History — {historyF6.window}</h3>
          <p className="text-xs text-muted">{historyF6.data_quality?.status} • Critical {historyF6.history?.current?.critical ?? "—"} → High {historyF6.history?.current?.high ?? "—"}</p>
        </div>
      )}
      {recurring && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Recurring Exposure</h3>
          <p className="text-xs text-muted">{recurring.total} recurring • bounded MAX_RESULTS 20</p>
          <div className="mt-2 space-y-1">{(recurring.recurring||[]).slice(0,5).map(r=> <div key={r.subject_id} className="rounded border bg-canvas p-2 text-xs"><p>{r.recurrence_type} {r.subject_id.slice(0,8)} ×{r.recurrence_count}</p><p className="text-muted">{r.evidence?.slice(0,60)}</p></div>)}</div>
        </div>
      )}
      {remEff && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Remediation Effectiveness</h3>
          <p className="text-xs text-muted">Total {remEff.total} • Successful {remEff.successful} • Success {remEff.success_rate}% • Reopened {remEff.reopened}</p>
          <div className="mt-2 text-xs">Partial {remEff.partial} • Failed {remEff.failed} • Not verified {remEff.not_verified}</div>
        </div>
      )}
      {aph && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Attack Path History</h3>
          <p className="text-xs text-muted">{aph.total} paths • {aph.recurring?.length || 0} recurring</p>
          <div className="mt-2 space-y-1">{(aph.recurring||[]).slice(0,5).map(p=> <div key={p.fingerprint} className="rounded border bg-canvas p-2 text-xs"><p>{p.path_type} {p.provider} {p.current_severity} [{p.severity_change}] ×{p.recurrence_count}</p></div>)}</div>
        </div>
      )}
      {decisionCenter && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">F7 — Security Operations Decision Center</h3>
          <p className="text-xs text-muted">{decisionCenter.total} decisions • deterministic priority</p>
          <div className="mt-2 space-y-1">{(decisionCenter.decisions||[]).slice(0,5).map(d=> <div key={d.decision_id} className="rounded border bg-canvas p-2 text-xs"><p className="font-semibold">{d.title} P{d.priority} {d.severity} [{d.status}]</p><p className="text-muted">{d.why_it_matters.slice(0,80)} → {d.recommended_action}</p></div>)}</div>
        </div>
      )}
      {execSummary && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Executive Summary</h3>
          <p className="text-xs text-muted">Overall {execSummary.overall_direction} • Critical {execSummary.critical_active} High {execSummary.high_active} • Worsening {execSummary.worsening_count} Recurring {execSummary.recurring_count}</p>
          <div className="mt-2 text-xs">Unresolved {execSummary.unresolved_remediation} • Failed validation {execSummary.failed_validation} • Attack paths {execSummary.active_attack_paths} • Gaps {execSummary.major_coverage_gaps}</div>
        </div>
      )}
      {snapshot && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Security Snapshot</h3>
          <div className="mt-2 grid gap-2 sm:grid-cols-4 text-xs">
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Assets</p><p className="font-bold">{snapshot.assets}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Findings</p><p className="font-bold">{snapshot.findings}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Critical</p><p className="font-bold">{snapshot.critical_findings}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-muted">Internet</p><p className="font-bold">{snapshot.internet_facing_assets}</p></div>
          </div>
          <p className="mt-2 text-xs text-muted">Cloud {snapshot.cloud_exposures} • Paths {snapshot.active_attack_paths} • Open rem {snapshot.open_remediation} • Coverage gaps {snapshot.coverage_gaps}</p>
        </div>
      )}
      {attentionQueue && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Attention Queue</h3>
          <p className="text-xs text-muted">IMMEDIATE / HIGH / NORMAL / WATCH</p>
          <div className="mt-2 space-y-1">{(attentionQueue.queue||[]).slice(0,5).map(q=> <div key={q.decision_id} className="rounded border bg-canvas p-2 text-xs"><p>{q.queue} — {q.title} P{q.priority}</p><p className="text-muted">{q.reason.slice(0,80)} → {q.suggested_next_step}</p></div>)}</div>
        </div>
      )}
      {recentChanges && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Recent Security Changes</h3>
          <div className="mt-2 space-y-1">{(recentChanges.changes||[]).slice(0,5).map(c=> <div key={c.id} className="rounded border bg-canvas p-2 text-xs"><p>{c.change_type || c.type} — {c.asset_id || c.id.slice(0,6)}</p><p className="text-muted">{c.detected_at || c.created_at}</p></div>)}</div>
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
      <p className="text-xs text-muted">Deterministic • SHA-256 fingerprints • bounded • tenant-isolated • no AI • no graph DB • evidence-first • F4 Attack Surface Analytics</p>
    </div>
  );
}
