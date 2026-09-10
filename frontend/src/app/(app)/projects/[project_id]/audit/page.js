/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with bounded audit search */
/* D10 project audit — search, detail with integrity status, bounded export, verification. */
"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import PageHeader from "@/components/ui/PageHeader";
import { SkeletonTable } from "@/components/ui/Skeleton";
import {
  exportProjectAudit,
  getProjectAuditRecord,
  listProjectAudit,
  verifyProjectAudit,
} from "@/lib/api/audit";

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

function integrityLabel(status) {
  if (status === "verified") return "Integrity: verified";
  if (status === "mismatch") return "Integrity: MISMATCH";
  if (status === "broken_link") return "Integrity: broken link";
  return "Integrity: unchained (pre-D10 record)";
}

export default function ProjectAuditPage() {
  const params = useParams();
  const projectId = params?.project_id;
  const [items, setItems] = useState([]);
  const [filters, setFilters] = useState({ event_type: "", result: "", actor_user_id: "", correlation_id: "" });
  const [detail, setDetail] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionOk, setActionOk] = useState("");

  const load = useCallback(async () => {
    if (!projectId) return;
    setLoading(true);
    setError("");
    try {
      const data = await listProjectAudit(projectId, { limit: 50 });
      setItems(data.items || []);
    } catch (err) {
      setItems([]);
      setError(err.message || "Unable to load audit records.");
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleSearch(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const data = await listProjectAudit(projectId, { limit: 50, ...filters });
      setItems(data.items || []);
    } catch (err) {
      setItems([]);
      setError(err.message || "Search failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleDetail(id) {
    setActionError("");
    try {
      setDetail(await getProjectAuditRecord(projectId, id));
    } catch (err) {
      setActionError(err.message || "Unable to load record.");
    }
  }

  async function handleExport(fmt) {
    setActionError("");
    setActionOk("");
    try {
      await exportProjectAudit(projectId, { format: fmt, ...filters });
      setActionOk(`Audit export (${fmt}) downloaded. The export itself was audited.`);
    } catch (err) {
      setActionError(err.message || "Export failed.");
    }
  }

  async function handleVerify() {
    setActionError("");
    setActionOk("");
    try {
      const result = await verifyProjectAudit(projectId, { limit: 200 });
      setVerifyResult(result);
      setActionOk(
        result.valid
          ? `Integrity verified: ${result.checked} chained records checked.`
          : `Integrity FAILURE: ${result.failure_count} mismatched record(s).`
      );
    } catch (err) {
      setActionError(err.message || "Verification failed.");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit"
        description="Who did what, to which resource, when, and with what result. Append-only and tamper-evident."
      />

      {actionError ? (
        <p className="text-sm text-red-400" role="alert">
          {actionError}
        </p>
      ) : null}
      {actionOk ? (
        <p className="text-sm text-emerald-400" role="status">
          {actionOk}
        </p>
      ) : null}

      <form onSubmit={handleSearch} className="flex flex-wrap items-end gap-3">
        {[
          ["event_type", "Event type"],
          ["result", "Result"],
          ["actor_user_id", "Actor"],
          ["correlation_id", "Correlation ID"],
        ].map(([key, label]) => (
          <label key={key} className="flex flex-col gap-1 text-xs text-slate-400">
            {label}
            <input
              value={filters[key]}
              onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value }))}
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200"
            />
          </label>
        ))}
        <button
          type="submit"
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
        >
          Search
        </button>
        <button
          type="button"
          onClick={() => handleExport("json")}
          className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
        >
          Export JSON
        </button>
        <button
          type="button"
          onClick={() => handleExport("csv")}
          className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
        >
          Export CSV
        </button>
        <button
          type="button"
          onClick={handleVerify}
          className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
        >
          Verify integrity
        </button>
      </form>

      {verifyResult ? (
        <p className="text-xs text-slate-400">
          Chain check: {verifyResult.checked} checked, {verifyResult.unchained} unchained (pre-D10),{" "}
          {verifyResult.truncated ? "window truncated, " : ""}
          {verifyResult.valid ? "valid." : `INVALID (${verifyResult.failure_count} failures).`}
        </p>
      ) : null}

      {loading ? (
        <SkeletonTable rows={8} />
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : items.length === 0 ? (
        <EmptyState title="No audit records" message="No audit activity matches these filters." />
      ) : (
        <div className="overflow-x-auto rounded-2xl border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 text-xs text-slate-500">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Event</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Resource</th>
                <th className="px-4 py-3">Result</th>
                <th className="px-4 py-3">Detail</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="border-t border-slate-800">
                  <td className="px-4 py-3 text-xs">{formatWhen(r.created_at)}</td>
                  <td className="px-4 py-3 font-mono text-xs">{r.event_type}</td>
                  <td className="px-4 py-3 font-mono text-xs">{r.actor_user_id ? r.actor_user_id.slice(0, 8) : "system"}</td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {r.resource_type || "—"}
                    {r.resource_id ? ` ${r.resource_id.slice(0, 8)}` : ""}
                  </td>
                  <td className="px-4 py-3 text-xs">{r.result}</td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      onClick={() => handleDetail(r.id)}
                      className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {detail ? (
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6" aria-label="Audit detail">
          <h2 className="text-lg font-semibold text-white">Record detail</h2>
          <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
            {[
              ["ID", detail.id],
              ["Event", detail.event_type],
              ["Action", detail.action],
              ["Result", detail.result],
              ["Actor", detail.actor_user_id || "system"],
              ["Project", detail.project_id || "—"],
              ["Organization", detail.organization_id || "—"],
              ["Resource", `${detail.resource_type || "—"} ${detail.resource_id || ""}`],
              ["Request", detail.request_id || "—"],
              ["Correlation", detail.correlation_id || "—"],
              ["IP", detail.ip_address || "—"],
              ["Time", formatWhen(detail.created_at)],
              ["Prev hash", detail.prev_hash ? `${detail.prev_hash.slice(0, 19)}…` : "—"],
              ["Event hash", detail.event_hash ? `${detail.event_hash.slice(0, 19)}…` : "—"],
            ].map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <dt className="shrink-0 text-slate-500">{k}:</dt>
                <dd className="break-all font-mono text-slate-200">{v}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-xs text-slate-400">{integrityLabel(detail.integrity)}</p>
          <button
            type="button"
            onClick={() => setDetail(null)}
            className="mt-3 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
          >
            Close
          </button>
        </section>
      ) : null}
    </div>
  );
}
