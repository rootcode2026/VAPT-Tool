/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with bounded queue */
/* D7 remediation queue — project-scoped, bounded, no external ticketing. */
"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import PageHeader from "@/components/ui/PageHeader";
import SeverityBadge from "@/components/ui/SeverityBadge";
import StatusBadge from "@/components/ui/StatusBadge";
import { SkeletonTable } from "@/components/ui/Skeleton";
import {
  blockProjectRemediation,
  completeProjectRemediation,
  listProjectRemediations,
  startProjectRemediation,
  unblockProjectRemediation,
} from "@/lib/api/findings";

const STATUSES = ["", "open", "in_progress", "blocked", "submitted", "completed", "cancelled"];

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export default function ProjectRemediationsPage() {
  const params = useParams();
  const projectId = params?.project_id;
  const [items, setItems] = useState([]);
  const [status, setStatus] = useState("");
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");

  const load = useCallback(async () => {
    if (!projectId) return;
    setLoading(true);
    setError("");
    try {
      const query = { limit: 100 };
      if (status) query.status = status;
      if (overdueOnly) query.overdue = "true";
      const data = await listProjectRemediations(projectId, query);
      setItems(data.items || []);
    } catch (err) {
      setItems([]);
      setError(err.message || "Unable to load remediations.");
    } finally {
      setLoading(false);
    }
  }, [projectId, status, overdueOnly]);

  useEffect(() => {
    load();
  }, [load]);

  async function runAction(rem, fn) {
    setActionError("");
    try {
      let payload;
      if (fn === blockProjectRemediation) {
        const reason = window.prompt("Blocker reason (required, max 500 chars):");
        if (!reason || !reason.trim()) {
          setActionError("blocked_reason is required to block remediation.");
          return;
        }
        payload = { blocked_reason: reason.trim().slice(0, 500) };
        await fn(projectId, rem.id, payload);
      } else if (fn === completeProjectRemediation) {
        const notes = window.prompt("Completion notes (optional):") || undefined;
        await fn(projectId, rem.id, notes ? { completion_notes: notes.slice(0, 2000) } : {});
      } else {
        await fn(projectId, rem.id);
      }
      await load();
    } catch (err) {
      setActionError(err.message || "Action failed.");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remediation"
        description="Finding → owner → deadline → evidence → owner-reported completion. Verification requires a D8 retest."
      />
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-slate-400">
          Status
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
          >
            {STATUSES.map((s) => (
              <option key={s || "all"} value={s}>
                {s || "All"}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input type="checkbox" checked={overdueOnly} onChange={(e) => setOverdueOnly(e.target.checked)} />
          Overdue only
        </label>
        <button
          type="button"
          onClick={load}
          className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
        >
          Retry
        </button>
      </div>

      {actionError ? (
        <p className="text-sm text-red-400" role="alert">
          {actionError}
        </p>
      ) : null}

      {loading ? (
        <SkeletonTable rows={6} />
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : items.length === 0 ? (
        <EmptyState title="No remediation work" message="No remediation work currently assigned." />
      ) : (
        <div className="overflow-x-auto rounded-2xl border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 text-xs text-slate-500">
              <tr>
                <th className="px-4 py-3">Finding</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Owner</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">SLA</th>
                <th className="px-4 py-3">Due</th>
                <th className="px-4 py-3">Updated</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="border-t border-slate-800">
                  <td className="px-4 py-3">
                    <Link href={`/findings/${r.finding_id}`} className="text-blue-400 hover:underline">
                      {r.title}
                    </Link>
                    {r.verification_required ? (
                      <p className="mt-1 text-xs text-amber-300">Verification required (D8 retest)</p>
                    ) : null}
                    {r.accepted_risk ? <p className="mt-1 text-xs text-slate-500">Accepted risk</p> : null}
                    {r.status === "blocked" && r.blocked_reason ? (
                      <p className="mt-1 text-xs text-red-300">Blocked: {r.blocked_reason}</p>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={r.finding_severity} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{r.assigned_to ? r.assigned_to.slice(0, 8) : "—"}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={r.status} />
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {r.overdue ? <span className="font-semibold text-red-400">Overdue</span> : r.sla_status || "—"}
                  </td>
                  <td className="px-4 py-3 text-xs">{formatWhen(r.due_at)}</td>
                  <td className="px-4 py-3 text-xs">{formatWhen(r.created_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      <button
                        type="button"
                        onClick={() => runAction(r, startProjectRemediation)}
                        className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                      >
                        Start
                      </button>
                      <button
                        type="button"
                        onClick={() => runAction(r, blockProjectRemediation)}
                        className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                      >
                        Block
                      </button>
                      <button
                        type="button"
                        onClick={() => runAction(r, unblockProjectRemediation)}
                        className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                      >
                        Unblock
                      </button>
                      <button
                        type="button"
                        onClick={() => runAction(r, completeProjectRemediation)}
                        className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                      >
                        Complete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
