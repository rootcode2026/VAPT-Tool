/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { useProjectContext } from "@/lib/project-context";
import { listInvestigations, getInvestigation, createInvestigation, updateInvestigation, addInvestigationNote, getInvestigationTimeline, getInvestigationsSummary } from "@/lib/api/investigations";

function Stat({ label, value }) {
  return (
    <div className="rounded-md border bg-surface p-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-lg font-bold">{value}</p>
    </div>
  );
}

export default function InvestigationsPage() {
  const { selectedProjectId, status } = useProjectContext();
  const [investigations, setInvestigations] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [subjectType, setSubjectType] = useState("finding");
  const [subjectId, setSubjectId] = useState("");

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError("");
    try {
      const [list, sum] = await Promise.all([
        listInvestigations(selectedProjectId, { limit: 50 }).catch(() => ({ investigations: [] })),
        getInvestigationsSummary(selectedProjectId).catch(() => null),
      ]);
      setInvestigations(list?.investigations || list?.data?.investigations || []);
      setSummary(sum);
    } catch (e) {
      setError(e.message || "Unable to load investigations.");
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    if (status === "ready" && selectedProjectId) load();
  }, [status, selectedProjectId, load]);

  const openDetail = async (id) => {
    setSelected(id);
    try {
      const [d, t] = await Promise.all([
        getInvestigation(selectedProjectId, id),
        getInvestigationTimeline(selectedProjectId, id).catch(() => ({ timeline: [] })),
      ]);
      setDetail(d);
      setTimeline(t?.timeline || t?.data?.timeline || []);
    } catch (e) {
      setDetail(null);
    }
  };

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project selected" description="Select a project to view investigations." />;
  if (loading) return <div><PageHeader title="Security Investigations" description="Unified investigation & operations" /><LoadingState message="Loading investigations..." /></div>;
  if (error) return <div><PageHeader title="Security Investigations" description="Unified investigation & operations" /><ErrorState title="Unable to load" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Security Investigations" description="One investigation context — finding, correlations, assets, attack paths, CSPM, exposure, history, remediation, retest, audit." />

      <div className="grid gap-2 sm:grid-cols-4">
        <Stat label="Open" value={summary?.open ?? 0} />
        <Stat label="In Progress" value={summary?.in_progress ?? 0} />
        <Stat label="Critical" value={summary?.critical ?? 0} />
        <Stat label="SLA Breached" value={summary?.sla_breached ?? 0} />
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Create Investigation</h3>
        <p className="text-xs text-muted">From existing subject: finding, asset, correlation, attack_path, exposure. Deterministic identity.</p>
        <div className="mt-2 flex flex-wrap gap-2">
          <select value={subjectType} onChange={(e) => setSubjectType(e.target.value)} className="rounded border bg-canvas px-2 py-1 text-sm">
            <option value="finding">finding</option>
            <option value="asset">asset</option>
            <option value="correlation">correlation</option>
            <option value="attack_path">attack_path</option>
            <option value="exposure">exposure</option>
          </select>
          <input placeholder="Subject ID" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} className="rounded border bg-canvas px-2 py-1 text-sm w-64" />
          <button type="button" onClick={async () => { try { await createInvestigation(selectedProjectId, { subject_type: subjectType, subject_id: subjectId }); setSubjectId(""); load(); } catch (e) { setError(e.message); } }} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Create</button>
        </div>
      </div>

      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Investigations</h3>
        <p className="text-xs text-muted">Priority | Subject | Severity | Owner | Status — bounded 100</p>
        {investigations.length === 0 ? <p className="mt-2 text-xs text-muted">No investigations yet.</p> : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-muted"><th className="p-1">Priority</th><th className="p-1">Subject</th><th className="p-1">Severity</th><th className="p-1">Owner</th><th className="p-1">Status</th></tr></thead>
              <tbody>
                {investigations.map((inv) => (
                  <tr key={inv.id} className="cursor-pointer border-t hover:bg-canvas" onClick={() => openDetail(inv.id)}>
                    <td className="p-1 font-medium">{inv.priority}</td>
                    <td className="p-1 font-mono">{inv.subject_type}:{inv.subject_id.slice(0,8)}</td>
                    <td className="p-1"><SeverityBadge severity={inv.severity} /></td>
                    <td className="p-1">{inv.assigned_to ? inv.assigned_to.slice(0,8) : "—"}</td>
                    <td className="p-1">{inv.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && detail && (
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Investigation Detail — {detail.id.slice(0,8)} [{detail.priority}] {detail.status}</h3>
          <p className="text-xs text-muted">{detail.title}</p>
          <div className="mt-2 rounded border bg-canvas p-3">
            <p className="text-xs font-semibold">WHY THIS MATTERS</p>
            <p className="text-xs text-muted">{detail.why_matters}</p>
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            <div className="rounded border bg-canvas p-2"><p className="text-xs font-medium">Security Summary</p><p className="text-xs text-muted">Severity {detail.severity} • Confidence {detail.confidence}</p><p className="text-xs text-muted">Scanners: {(detail.scanners || []).join(", ") || "—"}</p></div>
            <div className="rounded border bg-canvas p-2"><p className="text-xs font-medium">Subject</p><p className="text-xs text-muted">{detail.subject_type}:{detail.subject_id}</p><p className="text-xs text-muted">Assigned: {detail.assigned_to || "unassigned"}</p></div>
          </div>
          <div className="mt-2"><p className="text-xs font-medium">Correlated Signals ({(detail.correlations || []).length})</p>{(detail.correlations || []).slice(0,5).map((c) => (<p key={c.id} className="text-xs text-muted">{c.type} • {c.confidence} • {c.score}</p>))}</div>
          <div className="mt-2"><p className="text-xs font-medium">Attack Paths ({(detail.attack_paths || []).length})</p>{(detail.attack_paths || []).slice(0,3).map((p) => (<p key={p.id} className="text-xs text-muted">{p.path_type} • {p.provider} • {p.severity}</p>))}</div>
          <div className="mt-2"><p className="text-xs font-medium">CSPM ({(detail.cspm_controls || []).length})</p>{(detail.cspm_controls || []).slice(0,3).map((c) => (<p key={c.control_id} className="text-xs text-muted">{c.control_id} • {c.severity}</p>))}</div>
          <div className="mt-2"><p className="text-xs font-medium">Exposure</p><p className="text-xs text-muted">{detail.exposure ? `${detail.exposure.exposure_type} • ${detail.exposure.severity} • ${detail.exposure.priority_score}` : "—"}</p></div>
          <div className="mt-2"><p className="text-xs font-medium">Remediation: {detail.remediation ? detail.remediation.status : "—"} • Retest: {detail.retest ? detail.retest.status : "—"} • SLA: {detail.sla ? detail.sla.status : "NOT CONFIGURED"}</p></div>
          <div className="mt-3">
            <p className="text-xs font-semibold">Timeline ({timeline.length})</p>
            {timeline.slice(0,20).map((e, i) => (<p key={i} className="text-xs text-muted">{e.timestamp?.slice(0,19)} • {e.source} • {e.type} • {e.detail.slice(0,80)}</p>))}
          </div>
          <div className="mt-3">
            <p className="text-xs font-semibold">Analyst Notes ({(detail.notes || []).length})</p>
            {(detail.notes || []).map((n) => (<p key={n.id} className="text-xs text-muted">{n.created_at?.slice(0,16)} • {n.content.slice(0,80)}</p>))}
            <div className="mt-2 flex gap-2">
              <input placeholder="Add note (max 4000)" value={note} onChange={(e) => setNote(e.target.value)} className="rounded border bg-canvas px-2 py-1 text-sm flex-1" />
              <button type="button" onClick={async () => { try { await addInvestigationNote(selectedProjectId, detail.id, { content: note }); setNote(""); const d = await getInvestigation(selectedProjectId, detail.id); setDetail(d); } catch (e) { setError(e.message); } }} className="rounded border px-2 py-1 text-xs">Add</button>
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <button type="button" onClick={async () => { await updateInvestigation(selectedProjectId, detail.id, { status: "IN_PROGRESS" }); openDetail(detail.id); }} className="rounded border px-2 py-1 text-xs">In Progress</button>
            <button type="button" onClick={async () => { await updateInvestigation(selectedProjectId, detail.id, { status: "RESOLVED" }); openDetail(detail.id); }} className="rounded border px-2 py-1 text-xs">Resolved</button>
            <button type="button" onClick={async () => { await updateInvestigation(selectedProjectId, detail.id, { status: "CLOSED" }); openDetail(detail.id); }} className="rounded border px-2 py-1 text-xs">Closed</button>
            <button type="button" onClick={() => { setSelected(null); setDetail(null); }} className="rounded border px-2 py-1 text-xs">Close</button>
          </div>
        </div>
      )}
    </div>
  );
}
