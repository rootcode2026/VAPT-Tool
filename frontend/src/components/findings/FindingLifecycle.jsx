/* eslint-disable react-hooks/set-state-in-effect -- load lifecycle on finding change */
"use client";

import { useEffect, useState } from "react";
import {
  createRemediation,
  getFindingSLA,
  getProjectSLASummary,
  listRemediations,
  listRetests,
  listRiskAcceptances,
  requestRetest,
  requestRiskAcceptance,
  reviewRiskAcceptance,
  startFindingSLA,
  updateFindingSLA,
  updateRemediation,
  updateRetest,
} from "@/lib/api/findings";

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export default function FindingLifecycle({ findingId, projectId }) {
  const [sla, setSla] = useState(null);
  const [slaError, setSlaError] = useState("");
  const [ras, setRas] = useState([]);
  const [rems, setRems] = useState([]);
  const [retests, setRetests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [raForm, setRaForm] = useState({ reason: "", business_justification: "", compensating_controls: "", expires_at: "" });
  const [remForm, setRemForm] = useState({ title: "", description: "", assigned_to: "", due_at: "" });
  const [actionError, setActionError] = useState("");
  const [actionOk, setActionOk] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [s, ra, rem, ret] = await Promise.allSettled([
        getFindingSLA(findingId),
        listRiskAcceptances(findingId),
        listRemediations(findingId),
        listRetests(findingId),
      ]);
      if (s.status === "fulfilled") setSla(s.value);
      else setSlaError(s.reason?.message || "");
      if (ra.status === "fulfilled") setRas(ra.value.items || []);
      if (rem.status === "fulfilled") setRems(rem.value.items || []);
      if (ret.status === "fulfilled") setRetests(ret.value.items || []);
    } catch (err) {
      setError(err.message || "Unable to load lifecycle.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId]);

  async function handleStartSLA() {
    setActionError("");
    setActionOk("");
    try {
      const created = await startFindingSLA(findingId);
      setSla(created);
      setActionOk("SLA started.");
    } catch (err) {
      setActionError(err.message || "Unable to start SLA.");
    }
  }

  async function handleWaiveSLA() {
    setActionError("");
    try {
      const updated = await updateFindingSLA(findingId, { action: "waive", reason: "waived by analyst" });
      setSla(updated);
    } catch (err) {
      setActionError(err.message || "Unable to waive SLA.");
    }
  }

  async function handleRequestRA(e) {
    e.preventDefault();
    setActionError("");
    setActionOk("");
    if (!raForm.reason.trim() || !raForm.expires_at) {
      setActionError("Reason and expiration are required.");
      return;
    }
    try {
      await requestRiskAcceptance(findingId, {
        reason: raForm.reason.trim().slice(0, 2000),
        business_justification: raForm.business_justification.trim().slice(0, 2000) || undefined,
        compensating_controls: raForm.compensating_controls.trim().slice(0, 2000) || undefined,
        expires_at: new Date(raForm.expires_at).toISOString(),
      });
      setRaForm({ reason: "", business_justification: "", compensating_controls: "", expires_at: "" });
      setActionOk("Risk acceptance requested.");
      const ra = await listRiskAcceptances(findingId);
      setRas(ra.items || []);
    } catch (err) {
      setActionError(err.message || "Unable to request risk acceptance.");
    }
  }

  async function handleReviewRA(raId, action) {
    setActionError("");
    try {
      const notes = window.prompt(`Review notes for ${action} (optional):`) || undefined;
      await reviewRiskAcceptance(findingId, raId, { action, review_notes: notes });
      const ra = await listRiskAcceptances(findingId);
      setRas(ra.items || []);
    } catch (err) {
      setActionError(err.message || `Unable to ${action}.`);
    }
  }

  async function handleCreateRem(e) {
    e.preventDefault();
    setActionError("");
    if (!remForm.title.trim()) {
      setActionError("Remediation title is required.");
      return;
    }
    try {
      await createRemediation(findingId, {
        title: remForm.title.trim().slice(0, 255),
        description: remForm.description.trim().slice(0, 2000) || undefined,
        assigned_to: remForm.assigned_to.trim() || undefined,
        due_at: remForm.due_at ? new Date(remForm.due_at).toISOString() : undefined,
      });
      setRemForm({ title: "", description: "", assigned_to: "", due_at: "" });
      const rem = await listRemediations(findingId);
      setRems(rem.items || []);
    } catch (err) {
      setActionError(err.message || "Unable to create remediation.");
    }
  }

  async function handleRemStatus(remId, status) {
    setActionError("");
    try {
      const notes = status === "completed" ? window.prompt("Completion notes (optional):") || undefined : undefined;
      let blocked_reason;
      if (status === "blocked") {
        blocked_reason = window.prompt("Blocker reason (required):") || "";
        if (!blocked_reason.trim()) {
          setActionError("blocked_reason is required to block remediation.");
          return;
        }
      }
      await updateRemediation(findingId, remId, { status, completion_notes: notes, blocked_reason: blocked_reason ? blocked_reason.slice(0, 500) : undefined });
      const rem = await listRemediations(findingId);
      setRems(rem.items || []);
    } catch (err) {
      setActionError(err.message || "Unable to update remediation.");
    }
  }

  async function handleRequestRetest() {
    setActionError("");
    setActionOk("");
    try {
      await requestRetest(findingId);
      setActionOk("Verification scan queued — result is computed from scan evidence, never asserted manually.");
      const ret = await listRetests(findingId);
      setRetests(ret.items || []);
    } catch (err) {
      setActionError(err.message || "Unable to request retest.");
    }
  }

  async function handleRetestRefresh() {
    setActionError("");
    try {
      const ret = await listRetests(findingId);
      setRetests(ret.items || []);
    } catch (err) {
      setActionError(err.message || "Unable to refresh retests.");
    }
  }

  async function handleRetestCancel(retestId) {
    setActionError("");
    try {
      await updateRetest(findingId, retestId, { status: "cancelled" });
      const ret = await listRetests(findingId);
      setRetests(ret.items || []);
    } catch (err) {
      setActionError(err.message || "Unable to cancel retest.");
    }
  }

  if (loading) return <p className="text-sm text-slate-500">Loading lifecycle...</p>;

  return (
    <div className="space-y-6">
      {actionError ? <p className="text-sm text-red-400" role="alert">{actionError}</p> : null}
      {actionOk ? <p className="text-sm text-emerald-400" role="status">{actionOk}</p> : null}

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="SLA">
        <h2 className="text-lg font-semibold text-white">SLA</h2>
        {sla ? (
          <div className="mt-3 grid gap-3 text-sm sm:grid-cols-3">
            <div><p className="text-xs text-slate-500">Status</p><p className="font-medium">{sla.status}{sla.breached ? " (breached)" : ""}</p></div>
            <div><p className="text-xs text-slate-500">Due</p><p>{formatWhen(sla.due_at)}</p></div>
            <div><p className="text-xs text-slate-500">Remaining</p><p>{sla.remaining_hours != null ? `${sla.remaining_hours}h` : "—"}</p></div>
          </div>
        ) : (
          <p className="mt-3 text-sm text-slate-500">No SLA yet. {slaError ? "" : "Start SLA from triage."}</p>
        )}
        <div className="mt-3 flex gap-2">
          <button type="button" onClick={handleStartSLA} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500">Start SLA</button>
          {sla && sla.status === "active" ? <button type="button" onClick={handleWaiveSLA} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Waive</button> : null}
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Risk Acceptance">
        <h2 className="text-lg font-semibold text-white">Risk Acceptance</h2>
        <form onSubmit={handleRequestRA} className="mt-3 grid gap-3 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs">Reason*<textarea value={raForm.reason} onChange={(e) => setRaForm((f) => ({ ...f, reason: e.target.value }))} rows={2} maxLength={2000} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
          <label className="flex flex-col gap-1 text-xs">Business justification<textarea value={raForm.business_justification} onChange={(e) => setRaForm((f) => ({ ...f, business_justification: e.target.value }))} rows={2} maxLength={2000} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
          <label className="flex flex-col gap-1 text-xs">Compensating controls<textarea value={raForm.compensating_controls} onChange={(e) => setRaForm((f) => ({ ...f, compensating_controls: e.target.value }))} rows={2} maxLength={2000} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
          <label className="flex flex-col gap-1 text-xs">Expires at*<input type="datetime-local" value={raForm.expires_at} onChange={(e) => setRaForm((f) => ({ ...f, expires_at: e.target.value }))} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
          <div className="sm:col-span-2"><button type="submit" className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500">Request acceptance</button></div>
        </form>
        <ul className="mt-4 space-y-2">
          {ras.map((ra) => (
            <li key={ra.id} className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
              <p className="text-sm font-medium">{ra.status} • expires {formatWhen(ra.expires_at)}</p>
              <p className="mt-1 text-xs text-slate-500">Requested by {ra.requested_by ? ra.requested_by.slice(0, 8) : "—"}{ra.approved_by ? ` • approved by ${ra.approved_by.slice(0, 8)}` : ""}</p>
              {ra.status === "requested" ? (
                <div className="mt-2 flex gap-2">
                  <button type="button" onClick={() => handleReviewRA(ra.id, "approve")} className="rounded-lg border border-emerald-700 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-950">Approve</button>
                  <button type="button" onClick={() => handleReviewRA(ra.id, "reject")} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800">Reject</button>
                </div>
              ) : null}
              {ra.status === "approved" ? <button type="button" onClick={() => handleReviewRA(ra.id, "revoke")} className="mt-2 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800">Revoke</button> : null}
            </li>
          ))}
        </ul>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Remediation">
        <h2 className="text-lg font-semibold text-white">Remediation</h2>
        <form onSubmit={handleCreateRem} className="mt-3 grid gap-3 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs">Title*<input value={remForm.title} onChange={(e) => setRemForm((f) => ({ ...f, title: e.target.value }))} maxLength={255} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
          <label className="flex flex-col gap-1 text-xs">Assignee (UUID)<input value={remForm.assigned_to} onChange={(e) => setRemForm((f) => ({ ...f, assigned_to: e.target.value }))} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm" /></label>
          <label className="flex flex-col gap-1 text-xs sm:col-span-2">Description<textarea value={remForm.description} onChange={(e) => setRemForm((f) => ({ ...f, description: e.target.value }))} rows={2} maxLength={2000} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
          <div className="sm:col-span-2"><button type="submit" className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500">Create remediation</button></div>
        </form>
        <ul className="mt-4 space-y-2">
          {rems.map((r) => (
            <li key={r.id} className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
              <p className="text-sm font-medium">{r.title} • {r.status}</p>
              <p className="text-xs text-slate-500">Assignee {r.assigned_to ? r.assigned_to.slice(0, 8) : "—"}{r.overdue ? " • Overdue" : ""}{r.sla_status ? ` • SLA ${r.sla_status}` : ""}{r.due_at ? ` • due ${formatWhen(r.due_at)}` : ""}</p>
              {r.status === "blocked" && r.blocked_reason ? <p className="mt-1 text-xs text-red-300">Blocked: {r.blocked_reason}</p> : null}
              {r.evidence_ref ? <p className="mt-1 text-xs text-slate-400">Evidence: {r.evidence_ref.slice(0, 200)}</p> : null}
              {r.verification_required ? <p className="mt-1 text-xs text-amber-300">Owner-reported complete — verification required (D8 retest).</p> : null}
              {r.accepted_risk ? <p className="mt-1 text-xs text-slate-500">Finding is accepted risk — SLA follows risk-acceptance semantics.</p> : null}
              <div className="mt-2 flex flex-wrap gap-2">
                {[["in_progress", "Start"], ["submitted", "Submit"], ["blocked", "Block"], ["completed", "Complete"], ["cancelled", "Cancel"]].map(([s, label]) => (
                  <button key={s} type="button" onClick={() => handleRemStatus(r.id, s)} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800">{label}</button>
                ))}
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Retest">
        <h2 className="text-lg font-semibold text-white">Retest &amp; Verification</h2>
        <div className="mt-3 flex gap-2">
          <button type="button" onClick={handleRequestRetest} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500">Run retest</button>
          <button type="button" onClick={handleRetestRefresh} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Refresh</button>
        </div>
        {retests.length === 0 ? <p className="mt-3 text-sm text-slate-500">No verification runs yet.</p> : null}
        <ul className="mt-4 space-y-2">
          {retests.map((r) => (
            <li key={r.id} className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
              <p className="text-sm font-medium">
                {r.status === "passed" ? "Verified" : r.status === "failed" ? "Verification failed — finding still detected" : r.status === "error" ? "Verification inconclusive" : r.status === "cancelled" ? "Cancelled" : r.status === "running" ? "Retest running" : "Retest requested"}
                {r.result ? ` • ${r.result}` : ""} • {r.scanner || "—"}{r.scanner_version ? ` ${r.scanner_version}` : ""}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Target {r.target_value || "—"} • requested {formatWhen(r.created_at)}
                {r.started_at ? ` • started ${formatWhen(r.started_at)}` : ""}{r.completed_at ? ` • completed ${formatWhen(r.completed_at)}` : ""}
              </p>
              {r.image_digest ? <p className="mt-1 font-mono text-xs text-slate-500">digest: {String(r.image_digest).slice(0, 19)}…{r.channel ? ` • ${r.channel}` : ""}</p> : null}
              {r.verification_note ? <p className="mt-1 text-xs text-slate-400">{r.verification_note}</p> : null}
              {r.status === "passed" ? <p className="mt-1 text-xs text-emerald-300">Verified — original fingerprint absent from the completed verification scan.</p> : null}
              {["requested", "queued", "running"].includes(r.status) ? (
                <div className="mt-2 flex flex-wrap gap-2">
                  <button type="button" onClick={() => handleRetestCancel(r.id)} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800">Cancel</button>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-slate-500">Verification is computed from the verification scan&apos;s evidence: absent fingerprint → verified; present → still detected; scan/parser failure → inconclusive (never verified). Results cannot be asserted manually.</p>
      </section>
    </div>
  );
}

export function ProjectSLASummary({ projectId }) {
  const [summary, setSummary] = useState(null);
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { getProjectSLASummary: fetchSummary } = await import("@/lib/api/findings");
        const data = await fetchSummary(projectId);
        if (!cancelled) setSummary(data);
      } catch {
        if (!cancelled) setSummary(null);
      }
    }
    if (projectId) load();
    return () => {
      cancelled = true;
    };
  }, [projectId]);
  if (!summary) return null;
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="rounded-sm border border-border bg-canvas p-3"><p className="text-xs text-muted">Active SLAs</p><p className="text-lg font-semibold">{summary.active}</p></div>
      <div className="rounded-sm border border-border bg-canvas p-3"><p className="text-xs text-muted">Breached</p><p className="text-lg font-semibold text-critical">{summary.breached}</p></div>
      <div className="rounded-sm border border-border bg-canvas p-3"><p className="text-xs text-muted">Overdue critical</p><p className="text-lg font-semibold">{summary.overdue_critical}</p></div>
    </div>
  );
}
