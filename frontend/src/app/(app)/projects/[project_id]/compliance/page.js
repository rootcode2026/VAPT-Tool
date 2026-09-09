/* eslint-disable react-hooks/set-state-in-effect -- project-scoped reload with stale guards */
"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import DashboardSection from "@/components/dashboard/DashboardSection";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import PageHeader from "@/components/ui/PageHeader";
import StatCard from "@/components/ui/StatCard";
import StatusBadge from "@/components/ui/StatusBadge";
import { SkeletonCards, SkeletonTable } from "@/components/ui/Skeleton";
import {
  getProjectComplianceControl,
  getProjectComplianceSummary,
  listProjectComplianceControls,
} from "@/lib/api/compliance";

const STATUS_OPTIONS = ["", "PASS", "PARTIAL", "FAIL", "NOT_ASSESSED", "NOT_APPLICABLE"];

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export default function ProjectCompliancePage() {
  const params = useParams();
  const projectId = params?.project_id;
  const [summary, setSummary] = useState(null);
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState("");

  const load = useCallback(
    async (status = statusFilter) => {
      if (!projectId) return;
      setLoading(true);
      setError("");
      try {
        const [s, c] = await Promise.all([
          getProjectComplianceSummary(projectId),
          listProjectComplianceControls(projectId, { status: status || undefined, page_size: 100 }),
        ]);
        setSummary(s);
        setItems(c.items || []);
        setTotal(c.total ?? 0);
      } catch (err) {
        setSummary(null);
        setItems([]);
        setError(err.message || "Unable to load compliance evidence.");
      } finally {
        setLoading(false);
      }
    },
    [projectId, statusFilter]
  );

  useEffect(() => {
    load(statusFilter);
  }, [projectId, statusFilter, load]);

  async function openDetail(controlId) {
    setDetailError("");
    try {
      setDetail(await getProjectComplianceControl(projectId, controlId));
    } catch (err) {
      setDetailError(err.message || "Unable to load control detail.");
    }
  }

  if (!projectId) {
    return (
      <div className="space-y-4">
        <PageHeader title="Compliance Evidence" description="Control readiness from VAPT evidence — not certification." />
        <EmptyState title="No project selected." description="Open compliance from a project." action={<Link href="/projects" className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">View Projects</Link>} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Compliance Evidence"
        description="Evidence coverage / readiness from existing VAPT data. Not certification, not an audit, not a compliance guarantee."
      />
      {loading ? (
        <>
          <SkeletonCards count={4} />
          <SkeletonTable />
        </>
      ) : null}
      {!loading && error ? <ErrorState title="Unable to load compliance evidence." message={error} onRetry={() => load(statusFilter)} /> : null}
      {!loading && !error && summary ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="Evidence Coverage" value={summary.evidence_coverage === null || summary.evidence_coverage === undefined ? "—" : `${summary.evidence_coverage}%`} hint={`${summary.total_controls || 0} controls · ${summary.framework_version || ""}`} />
            <StatCard label="Pass / Partial" value={`${summary.pass || 0} / ${summary.partial || 0}`} hint={`${summary.fail || 0} fail`} />
            <StatCard label="Fail" value={summary.fail || 0} hint="Needs investigation" />
            <StatCard label="Not Assessed" value={summary.not_assessed || 0} hint={`${summary.not_applicable || 0} not applicable`} />
          </div>

          <DashboardSection
            title="Controls"
            action={
              <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter by status" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-xs">
                {STATUS_OPTIONS.map((s) => (
                  <option key={s} value={s}>{s === "" ? "All statuses" : s.replaceAll("_", " ")}</option>
                ))}
              </select>
            }
          >
            {items.length === 0 ? <EmptyState title="No controls" description="No controls match this filter." /> : (
              <DataTable
                rowKey={(r) => r.control_id}
                columns={[
                  { key: "control_id", header: "Control", render: (r) => <button type="button" onClick={() => openDetail(r.control_id)} className="text-xs font-medium hover:underline">{r.control_id}</button> },
                  { key: "title", header: "Title", render: (r) => <span className="text-xs break-all">{r.title}</span> },
                  { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
                  { key: "confidence", header: "Confidence", render: (r) => <span className="text-xs">{r.confidence}</span> },
                  { key: "freshness", header: "Freshness", render: (r) => <span className="text-xs">{r.freshness}</span> },
                ]}
                rows={items}
              />
            )}
            <p className="mt-2 text-xs text-muted">{total} controls · framework {summary.framework_version}</p>
          </DashboardSection>

          {detailError ? <p className="text-xs text-danger">{detailError}</p> : null}
          {detail ? (
            <DashboardSection title={`${detail.control_id} — ${detail.title}`}>
              <p className="text-xs text-muted">{detail.description}</p>
              <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <dt className="text-muted">Status</dt><dd><StatusBadge status={detail.status} /></dd>
                <dt className="text-muted">Confidence</dt><dd>{detail.confidence}</dd>
                <dt className="text-muted">Freshness</dt><dd>{detail.freshness}</dd>
                <dt className="text-muted">Evaluated</dt><dd>{formatWhen(detail.evaluated_at)}</dd>
              </dl>
              {(detail.reasons || []).length > 0 ? (
                <ul className="mt-2 list-disc pl-5 text-xs text-muted">
                  {detail.reasons.map((reason, i) => <li key={i}>{reason}</li>)}
                </ul>
              ) : null}
              <p className="mb-2 mt-3 text-xs font-medium uppercase tracking-wide text-muted">Contradictory evidence ({(detail.contradictory || []).length})</p>
              {(detail.contradictory || []).length === 0 ? <p className="text-xs text-muted">None.</p> : (
                <DataTable
                  rowKey={(r, i) => `${r.kind}-${r.id || i}`}
                  columns={[
                    { key: "kind", header: "Kind", render: (r) => <span className="text-xs">{r.kind}</span> },
                    { key: "title", header: "Evidence", render: (r) => <span className="text-xs break-all">{r.title || r.value || r.id}</span> },
                    { key: "severity", header: "Severity", render: (r) => <span className="text-xs">{r.severity || "—"}</span> },
                    { key: "observed_at", header: "Observed", render: (r) => <span className="text-xs">{formatWhen(r.observed_at)}</span> },
                  ]}
                  rows={detail.contradictory}
                />
              )}
              <p className="mb-2 mt-3 text-xs font-medium uppercase tracking-wide text-muted">Supporting evidence ({(detail.supporting || []).length})</p>
              {(detail.supporting || []).length === 0 ? <p className="text-xs text-muted">None.</p> : (
                <DataTable
                  rowKey={(r, i) => `${r.kind}-${r.id || r.scanner || i}`}
                  columns={[
                    { key: "kind", header: "Kind", render: (r) => <span className="text-xs">{r.kind}</span> },
                    { key: "title", header: "Evidence", render: (r) => <span className="text-xs break-all">{r.title || r.scanner || r.id}</span> },
                    { key: "observed_at", header: "Observed", render: (r) => <span className="text-xs">{formatWhen(r.observed_at)}</span> },
                  ]}
                  rows={detail.supporting}
                />
              )}
            </DashboardSection>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
