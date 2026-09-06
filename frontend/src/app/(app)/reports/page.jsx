/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { useProjectContext } from "@/lib/project-context";
import { createReport, listReports } from "@/lib/api/reports";

const TYPES = ["executive_security","technical_vapt","security_posture","attack_surface","finding_risk","remediation_sla","code_security","cloud_security","compliance"];

export default function ReportsPage() {
  const { selectedProjectId, status } = useProjectContext();
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ report_type: "executive_security", title: "" });
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await listReports({ project_id: selectedProjectId || undefined, page: 1, page_size: 20 });
      setReports(res.items || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    if (status === "ready") load();
  }, [status, load]);

  async function handleCreate() {
    setMsg("");
    try {
      await createReport({ report_type: form.report_type, title: form.title || undefined, project_id: selectedProjectId || undefined });
      setMsg("Report generated");
      setForm({ report_type: "executive_security", title: "" });
      load();
    } catch (e) {
      setMsg(e.message);
    }
  }

  if (status === "loading") return <LoadingState message="Loading..." />;
  if (loading) return <div><PageHeader title="Reports" description="Enterprise reporting — executive, technical, posture, attack surface, code, cloud, compliance" /><LoadingState message="Loading reports..." /></div>;
  if (error) return <div><PageHeader title="Reports" /><ErrorState title="Unable to load" message={error} onRetry={load} /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="Reports" description="Professional auditable tenant-safe reports. Data is a deterministic snapshot (immutable version)." />
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Generate Report</h3>
        <p className="text-xs text-muted">Select type, scope is current project or organization-wide if no project selected. Viewer cannot generate.</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <select value={form.report_type} onChange={(e) => setForm((f) => ({ ...f, report_type: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm">
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input placeholder="Title (optional)" value={form.title} onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} className="rounded border bg-canvas px-2 py-1 text-sm" />
          <button type="button" onClick={handleCreate} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">Generate</button>
        </div>
        {msg ? <p className="mt-2 text-xs text-muted">{msg}</p> : null}
      </div>

      <div className="rounded-md border bg-surface">
        <div className="border-b px-4 py-3"><h3 className="text-sm font-semibold">Latest Reports</h3></div>
        {reports.length === 0 ? <div className="p-4"><EmptyState title="No reports" description="Generate your first report." /></div> : (
          <div className="divide-y">
            {reports.map((r) => (
              <div key={r.id} className="flex items-center justify-between p-3">
                <div><p className="text-sm font-medium">{r.title} <span className="text-xs text-muted">({r.report_type})</span></p><p className="text-xs text-muted">{r.status} • {new Date(r.created_at).toLocaleString()} • {r.project_id ? `Project ${r.project_id.slice(0,8)}` : "Organization"}</p></div>
                <Link href={`/reports/${r.id}`} className="rounded border px-2 py-1 text-xs">View</Link>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="text-xs text-muted">Exports: JSON, CSV (sanitized against formula injection), PDF (CONFIDENTIAL footer). Versioned, immutable.</p>
    </div>
  );
}
