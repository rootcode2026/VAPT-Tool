/* eslint-disable react-hooks/set-state-in-effect -- sync workflow state from loaded finding detail */
"use client";

import { useEffect, useState } from "react";
import { createFindingComment, listFindingComments, listFindingHistory, updateFinding } from "@/lib/api/findings";

const STATUSES = ["open", "triaged", "in_progress", "resolved", "false_positive", "accepted_risk", "reopened"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function FindingWorkflow({ findingId, initial, onChanged }) {
  const [detail, setDetail] = useState(initial || null);
  const [status, setStatus] = useState(initial?.status || "open");
  const [severity, setSeverity] = useState(initial?.severity_override || "");
  const [assignee, setAssignee] = useState(initial?.assigned_to || "");
  const [owner, setOwner] = useState(initial?.owner_user_id || "");
  const [tags, setTags] = useState((initial?.tags || []).join(", "));
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [comments, setComments] = useState(initial?.comments || []);
  const [history, setHistory] = useState(initial?.history || []);
  const [commentBody, setCommentBody] = useState("");
  const [commentSaving, setCommentSaving] = useState(false);

  useEffect(() => {
    if (initial) {
      setDetail(initial);
      setStatus(initial.status || "open");
      setSeverity(initial.severity_override || "");
      setAssignee(initial.assigned_to || "");
      setOwner(initial.owner_user_id || "");
      setTags((initial.tags || []).join(", "));
      setComments(initial.comments || []);
      setHistory(initial.history || []);
    }
  }, [initial]);

  async function refreshHistory() {
    try {
      const h = await listFindingHistory(findingId, { page: 1, page_size: 20 });
      setHistory(h.items || []);
      const c = await listFindingComments(findingId, { page: 1, page_size: 20 });
      setComments(c.items || []);
    } catch {}
  }

  async function handleSave(e) {
    e.preventDefault();
    setError("");
    setSuccess("");
    if ((status === "false_positive" || status === "accepted_risk") && !reason.trim()) {
      setError("Reason is required for false positive / accepted risk.");
      return;
    }
    setSaving(true);
    try {
      const payload = {};
      if (status !== detail?.status) payload.status = status;
      const sev = severity ? severity : null;
      if (sev !== (detail?.severity_override || null)) payload.severity_override = sev;
      const asg = assignee.trim() || null;
      if (asg !== (detail?.assigned_to || null)) payload.assigned_to = asg;
      const own = owner.trim() || null;
      if (own !== (detail?.owner_user_id || null)) payload.owner_user_id = own;
      const tagList = tags.split(",").map((t) => t.trim()).filter(Boolean);
      const currentTags = detail?.tags || [];
      if (JSON.stringify([...tagList].sort()) !== JSON.stringify([...currentTags].sort())) {
        payload.tags = tagList;
      }
      if (reason.trim()) payload.reason = reason.trim();
      if (Object.keys(payload).length === 0) {
        setError("No changes to save.");
        return;
      }
      const updated = await updateFinding(findingId, payload);
      setDetail(updated);
      setReason("");
      setSuccess("Finding updated.");
      await refreshHistory();
      if (onChanged) onChanged(updated);
    } catch (err) {
      setError(err.message || "Unable to update finding.");
    } finally {
      setSaving(false);
    }
  }

  async function handleComment(e) {
    e.preventDefault();
    if (!commentBody.trim()) return;
    setCommentSaving(true);
    try {
      const created = await createFindingComment(findingId, commentBody.trim().slice(0, 2000));
      setComments((prev) => [...prev, created]);
      setCommentBody("");
      await refreshHistory();
    } catch (err) {
      setError(err.message || "Unable to add comment.");
    } finally {
      setCommentSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Triage">
        <h2 className="text-lg font-semibold text-white">Triage & Ownership</h2>
        <p className="mt-1 text-sm text-slate-500">
          Original severity <span className="font-medium text-slate-300">{detail?.severity || "—"}</span>
          {" • "}Effective <span className="font-medium text-slate-300">{detail?.effective_severity || detail?.severity || "—"}</span>
        </p>
        <form onSubmit={handleSave} className="mt-5 grid gap-4 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-slate-400">Status</span>
            <select value={status} onChange={(e) => setStatus(e.target.value)} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
              {STATUSES.map((s) => (
                <option key={s} value={s}>{s.replaceAll("_", " ")}</option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-slate-400">Severity override (optional)</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
              <option value="">— use original —</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-slate-400">Assignee (user UUID)</span>
            <input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="Assignee user ID" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200" />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium text-slate-400">Owner (user UUID)</span>
            <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Owner user ID" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200" />
          </label>
          <label className="flex flex-col gap-1 text-xs sm:col-span-2">
            <span className="font-medium text-slate-400">Tags (comma-separated, lowercase)</span>
            <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="web, external" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200" />
          </label>
          <label className="flex flex-col gap-1 text-xs sm:col-span-2">
            <span className="font-medium text-slate-400">Reason (required for false positive / accepted risk)</span>
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} maxLength={1000} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200" />
          </label>
        </form>
        {error ? <p className="mt-3 text-sm text-red-400" role="alert">{error}</p> : null}
        {success ? <p className="mt-3 text-sm text-emerald-400" role="status">{success}</p> : null}
        <div className="mt-4 flex gap-3">
          <button type="button" onClick={handleSave} disabled={saving} className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-60">
            {saving ? "Saving..." : "Save triage"}
          </button>
        </div>
        <div className="mt-4 flex flex-wrap gap-2 text-xs">
          <span className="text-slate-500">Quick actions:</span>
          {[["false_positive", "Mark False Positive"], ["accepted_risk", "Accept Risk"], ["resolved", "Resolve"], ["reopened", "Reopen"]].map(([s, label]) => (
            <button key={s} type="button" onClick={() => setStatus(s)} className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300 hover:bg-slate-800">
              {label}
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Comments">
        <h2 className="text-lg font-semibold text-white">Comments</h2>
        {comments.length === 0 ? <p className="mt-3 text-sm text-slate-500">No comments yet.</p> : (
          <ul className="mt-4 space-y-3">
            {comments.map((c) => (
              <li key={c.id} className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="whitespace-pre-wrap text-sm text-slate-200">{c.body}</p>
                <p className="mt-2 text-xs text-slate-500">{c.author_user_id ? c.author_user_id.slice(0, 8) : "system"} • {c.created_at ? new Date(c.created_at).toLocaleString() : "—"}</p>
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={handleComment} className="mt-4 flex flex-col gap-2">
          <label htmlFor="finding-comment" className="text-xs font-medium text-slate-400">Add comment</label>
          <textarea id="finding-comment" value={commentBody} onChange={(e) => setCommentBody(e.target.value)} rows={3} maxLength={2000} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200" />
          <button type="submit" disabled={commentSaving || !commentBody.trim()} className="self-start rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-60">
            {commentSaving ? "Adding..." : "Add comment"}
          </button>
        </form>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="History">
        <h2 className="text-lg font-semibold text-white">History</h2>
        {history.length === 0 ? <p className="mt-3 text-sm text-slate-500">No history yet.</p> : (
          <ul className="mt-4 space-y-2">
            {history.map((h) => (
              <li key={h.id} className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
                <p className="text-sm font-medium text-slate-200">{String(h.action).replaceAll("_", " ")}</p>
                <p className="mt-1 text-xs text-slate-500">
                  {h.actor_user_id ? h.actor_user_id.slice(0, 8) : "system"} • {h.created_at ? new Date(h.created_at).toLocaleString() : "—"}
                </p>
                {(h.old_value || h.new_value) && <p className="mt-1 font-mono text-xs text-slate-400">{h.old_value || "—"} → {h.new_value || "—"}</p>}
                {h.reason && <p className="mt-1 text-xs text-slate-400">Reason: {h.reason}</p>}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
