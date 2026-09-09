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
import SeverityBadge from "@/components/ui/SeverityBadge";
import StatCard from "@/components/ui/StatCard";
import StatusBadge from "@/components/ui/StatusBadge";
import { SkeletonCards, SkeletonTable } from "@/components/ui/Skeleton";
import { getProjectDashboardSummary } from "@/lib/api/dashboard";

const WINDOWS = ["24h", "7d", "30d"];

function formatWhen(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

function riskHint(grade, scans) {
  if (!grade) return "No scored scans yet";
  return `Grade ${grade} · ${scans} recent scan${scans === 1 ? "" : "s"}`;
}

export default function ProjectDashboardPage() {
  const params = useParams();
  const projectId = params?.project_id;
  const [window, setWindow] = useState("24h");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(
    async (w = window) => {
      if (!projectId) return;
      setLoading(true);
      setError("");
      try {
        setData(await getProjectDashboardSummary(projectId, { window: w }));
      } catch (err) {
        setData(null);
        setError(err.message || "Unable to load dashboard.");
      } finally {
        setLoading(false);
      }
    },
    [projectId, window]
  );

  useEffect(() => {
    load(window);
  }, [projectId, window, load]);

  if (!projectId) {
    return (
      <div className="space-y-4">
        <PageHeader title="SOC Dashboard" description="Project-level security operations view." />
        <EmptyState title="No project selected." description="Open the dashboard from a project." action={<Link href="/projects" className="inline-flex rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground">View Projects</Link>} />
      </div>
    );
  }

  const risk = data?.risk || {};
  const findings = data?.findings || {};
  const alerts = data?.alerts || {};
  const assets = data?.assets || {};
  const changes = data?.changes || {};
  const monitoring = data?.monitoring || {};

  return (
    <div className="space-y-4">
      <PageHeader
        title="SOC Dashboard"
        description="One trustworthy view of exposure, recent changes, important findings, and what to investigate next. All metrics are computed server-side."
        actions={
          <select value={window} onChange={(e) => setWindow(e.target.value)} aria-label="Time window" className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm">
            {WINDOWS.map((w) => (
              <option key={w} value={w}>Last {w}</option>
            ))}
          </select>
        }
      />
      {loading ? (
        <>
          <SkeletonCards count={4} />
          <SkeletonTable />
        </>
      ) : null}
      {!loading && error ? <ErrorState title="Unable to load dashboard." message={error} onRetry={() => load(window)} /> : null}
      {!loading && !error && data ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="Risk" value={risk.grade ? `${risk.grade} · ${risk.score}` : "—"} hint={riskHint(risk.grade, risk.scans_counted || 0)} />
            <StatCard label="Open Critical / High" value={`${findings.critical || 0} / ${findings.high || 0}`} hint={`${findings.open || 0} open findings`} />
            <StatCard label="Active Alerts" value={alerts.active || 0} hint={`${alerts.critical || 0} critical · ${alerts.high || 0} high`} />
            <StatCard label="Assets" value={assets.total || 0} hint={`${changes.new_assets || 0} new in window`} />
          </div>

          <DashboardSection title="What needs attention" action={<span className="text-xs text-muted">Top findings and active alerts</span>}>
            {(!data.top_findings || data.top_findings.length === 0) && (!data.active_alerts || data.active_alerts.length === 0) ? (
              <EmptyState title="Nothing needs attention" description="No open critical/high findings or active alerts." />
            ) : (
              <div className="grid gap-4 lg:grid-cols-2">
                <div>
                  <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted">Top findings</p>
                  {(data.top_findings || []).length === 0 ? <p className="text-xs text-muted">No open findings.</p> : (
                    <DataTable
                      rowKey={(r) => r.id}
                      columns={[
                        { key: "severity", header: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
                        { key: "title", header: "Finding", render: (r) => <Link href={`/findings/${r.id}`} className="text-xs hover:underline break-all">{r.title}</Link> },
                        { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
                      ]}
                      rows={data.top_findings}
                    />
                  )}
                </div>
                <div>
                  <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted">Active alerts</p>
                  {(data.active_alerts || []).length === 0 ? <p className="text-xs text-muted">No active alerts.</p> : (
                    <DataTable
                      rowKey={(r) => r.id}
                      columns={[
                        { key: "severity", header: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
                        { key: "title", header: "Alert", render: (r) => <Link href={`/alerts?alert=${r.id}`} className="text-xs hover:underline break-all">{r.title}</Link> },
                        { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
                      ]}
                      rows={data.active_alerts}
                    />
                  )}
                </div>
              </div>
            )}
          </DashboardSection>

          <DashboardSection title="What changed" action={<span className="text-xs text-muted">{changes.recent || 0} events in window</span>}>
            {(!changes.items || changes.items.length === 0) ? (
              <EmptyState title="No recent changes" description="D2 change events for this window will appear here." />
            ) : (
              <DataTable
                rowKey={(r) => r.id}
                columns={[
                  { key: "detected_at", header: "When", render: (r) => <span className="text-xs">{formatWhen(r.detected_at)}</span> },
                  { key: "change_type", header: "Change", render: (r) => <span className="text-xs">{String(r.change_type || "").replaceAll("_", " ")}</span> },
                  { key: "subject", header: "Subject", render: (r) => <Link href={r.finding_id ? `/findings/${r.finding_id}` : r.asset_id ? `/assets/${r.asset_id}` : "#"} className="text-xs hover:underline break-all">{r.finding_id ? r.finding_id.slice(0, 8) : r.asset_id ? r.asset_id.slice(0, 8) : "—"}</Link> },
                  { key: "scanners", header: "Scanners", render: (r) => <span className="text-xs">{(r.scanners || []).join(", ") || "—"}</span> },
                ]}
                rows={changes.items}
              />
            )}
          </DashboardSection>

          <div className="grid gap-4 lg:grid-cols-2">
            <DashboardSection title="Attack surface" action={<span className="text-xs text-muted">{assets.total || 0} assets</span>}>
              {Object.keys(assets.by_type || {}).length === 0 ? <p className="text-xs text-muted">No assets inventoried.</p> : (
                <DataTable
                  rowKey={(r) => r.type}
                  columns={[
                    { key: "type", header: "Type", render: (r) => <span className="text-xs">{r.type}</span> },
                    { key: "count", header: "Count", render: (r) => <span className="text-xs">{r.count}</span> },
                  ]}
                  rows={Object.entries(assets.by_type).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count)}
                />
              )}
              {(assets.exposure_highlights || []).length > 0 ? (
                <div className="mt-3">
                  <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted">Exposure highlights</p>
                  <DataTable
                    rowKey={(r) => r.asset_id}
                    columns={[
                      { key: "asset_value", header: "Asset", render: (r) => <Link href={`/assets/${r.asset_id}`} className="text-xs hover:underline break-all">{r.asset_value}</Link> },
                      { key: "exposure", header: "Exposure", render: (r) => <span className="text-xs">{String(r.exposure || "").replaceAll("_", " ")}</span> },
                      { key: "severity", header: "Finding", render: (r) => <SeverityBadge severity={r.severity} /> },
                    ]}
                    rows={assets.exposure_highlights}
                  />
                </div>
              ) : null}
            </DashboardSection>

            <DashboardSection title="Monitoring health" action={<Link href="/attack-surface" className="text-xs text-primary hover:underline">Attack surface</Link>}>
              {!monitoring.last_run ? <p className="text-xs text-muted">No monitoring runs yet.</p> : (
                <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <dt className="text-muted">Last run</dt><dd><StatusBadge status={monitoring.last_run.status} /></dd>
                  <dt className="text-muted">Completed</dt><dd>{formatWhen(monitoring.last_run.completed_at)}</dd>
                  <dt className="text-muted">Scanners</dt><dd>{monitoring.last_run.successful_scanners ?? "—"} ok / {monitoring.last_run.failed_scanners ?? "—"} failed</dd>
                  <dt className="text-muted">Next run</dt><dd>{formatWhen(monitoring.next_run_at)}</dd>
                  <dt className="text-muted">Last good observation</dt><dd>{monitoring.last_good_observation ? formatWhen(monitoring.last_good_observation.completed_at) : "—"}</dd>
                </dl>
              )}
              {(monitoring.recent_runs || []).length > 1 ? (
                <div className="mt-3">
                  <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted">Recent runs</p>
                  <DataTable
                    rowKey={(r) => r.id}
                    columns={[
                      { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
                      { key: "completed_at", header: "Completed", render: (r) => <span className="text-xs">{formatWhen(r.completed_at)}</span> },
                    ]}
                    rows={monitoring.recent_runs.slice(1, 5)}
                  />
                </div>
              ) : null}
            </DashboardSection>
          </div>
        </>
      ) : null}
    </div>
  );
}
