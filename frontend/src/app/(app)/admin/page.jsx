"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import PageHeader from "@/components/ui/PageHeader";
import StatCard from "@/components/ui/StatCard";
import DataTable from "@/components/ui/DataTable";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import DashboardSection from "@/components/dashboard/DashboardSection";
import { getAdminDashboardSummary, getAdminOrganizationsSummary } from "@/lib/api/admin";

function HealthBadge({ status }) {
  const map = {
    Healthy: "bg-emerald-500/10 text-emerald-600 border-emerald-500/20",
    Degraded: "bg-amber-500/10 text-amber-600 border-amber-500/20",
    Unavailable: "bg-red-500/10 text-red-600 border-red-500/20",
    Unknown: "bg-surface text-muted border-border",
  };
  return (
    <span className={`inline-flex rounded-sm border px-2 py-0.5 text-xs font-medium ${map[status] || map.Unknown}`}>
      {status}
    </span>
  );
}

export default function AdminDashboardPage() {
  const [summary, setSummary] = useState(null);
  const [orgs, setOrgs] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const [dash, orgSummary] = await Promise.all([
          getAdminDashboardSummary(),
          getAdminOrganizationsSummary({ page: 1, page_size: 5 }),
        ]);
        if (cancelled) return;
        setSummary(dash);
        setOrgs(orgSummary);
      } catch (err) {
        if (cancelled) return;
        setError(err.message || "Unable to load admin data.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div>
        <PageHeader title="Super Admin Dashboard" description="Platform-wide security operations and system health." />
        <LoadingState message="Loading platform overview..." />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="Super Admin Dashboard" description="Platform-wide security operations and system health." />
        <ErrorState title="Unable to load admin data." message={error} onRetry={() => window.location.reload()} />
      </div>
    );
  }

  if (!summary) {
    return (
      <div>
        <PageHeader title="Super Admin Dashboard" description="Platform-wide security operations and system health." />
        <EmptyState title="No admin data" description="Platform metrics are not available yet." />
      </div>
    );
  }

  const isPlatform = true;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Super Admin Dashboard"
        description="Platform-wide security operations and system health."
        actions={
          <span className="rounded-sm border border-primary/20 bg-primary/10 px-2 py-1 text-xs font-medium text-primary">
            Platform Administration
          </span>
        }
      />

      {/* KPI Overview */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Platform KPIs">
        <StatCard label="Organizations" value={summary.organizations?.total ?? "Unavailable"} />
        <StatCard label="Active Users" value={summary.users?.total ?? "Unavailable"} />
        <StatCard label="Projects" value={summary.projects?.total ?? "Unavailable"} />
        <StatCard label="Assets" value={summary.assets?.total ?? "Unavailable"} />
        <StatCard label="Active Scans" value={summary.scans?.active ?? "Unavailable"} />
        <StatCard label="Completed Scans" value={summary.scans?.completed ?? "Unavailable"} />
        <StatCard label="Failed Scans" value={summary.scans?.failed ?? "Unavailable"} />
        <StatCard label="Open Findings" value={summary.findings?.open ?? "Unavailable"} />
        <StatCard label="Critical Findings" value={summary.findings?.critical ?? "Unavailable"} />
        <StatCard label="High Findings" value={summary.findings?.high ?? "Unavailable"} />
        <StatCard label="Registered Scanners" value={summary.scanners?.total ?? "Unavailable"} />
        <StatCard label="Audit Events" value={summary.audit_events?.total ?? "Unavailable"} />
      </section>

      {/* Platform Security Posture */}
      <DashboardSection title="Platform Security Posture" action={<Link href="/findings" className="text-xs font-medium text-primary hover:underline">View findings</Link>}>
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-sm border border-border bg-canvas p-3">
            <p className="text-xs text-muted">Critical</p>
            <p className="mt-1 text-lg font-semibold tabular-nums text-critical">{summary.findings?.critical ?? "—"}</p>
          </div>
          <div className="rounded-sm border border-border bg-canvas p-3">
            <p className="text-xs text-muted">High</p>
            <p className="mt-1 text-lg font-semibold tabular-nums text-high">{summary.findings?.high ?? "—"}</p>
          </div>
          <div className="rounded-sm border border-border bg-canvas p-3">
            <p className="text-xs text-muted">Medium</p>
            <p className="mt-1 text-lg font-semibold tabular-nums text-medium">{summary.findings?.medium ?? "—"}</p>
          </div>
          <div className="rounded-sm border border-border bg-canvas p-3">
            <p className="text-xs text-muted">Low</p>
            <p className="mt-1 text-lg font-semibold text-low">{summary.findings?.low ?? "—"}</p>
          </div>
          <div className="rounded-sm border border-border bg-canvas p-3">
            <p className="text-xs text-muted">Info</p>
            <p className="mt-1 text-lg font-semibold text-muted">{summary.findings?.info ?? "—"}</p>
          </div>
          <div className="rounded-sm border border-border bg-canvas p-3">
            <p className="text-xs text-muted">Total Findings</p>
            <p className="mt-1 text-lg font-semibold tabular-nums">{summary.findings?.total ?? "—"}</p>
          </div>
        </div>
        <p className="mt-3 text-xs text-muted">Current posture only — historical trends will be available in a future phase.</p>
      </DashboardSection>

      {/* Scanner Fleet */}
      <DashboardSection title="Scanner Fleet" action={<Link href="/admin/scanners" className="text-xs font-medium text-primary hover:underline">View fleet</Link>}>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-sm border border-border bg-canvas p-3">
              <p className="text-xs text-muted">Registered scanners</p>
              <p className="mt-1 text-lg font-semibold tabular-nums">{summary.scanners?.total ?? 14}</p>
              <p className="mt-1 text-xs text-muted">Baseline 14 scanners</p>
            </div>
            <div className="rounded-sm border border-border bg-canvas p-3">
              <p className="text-xs text-muted">Categories</p>
              <p className="mt-1 text-sm">network, web, sast, sca, secrets, container, iac, api, cloud</p>
            </div>
          </div>
          {summary.scanners?.names?.length ? (
            <div className="flex flex-wrap gap-1.5">
              {summary.scanners.names.map((n) => (
                <span key={n} className="rounded-sm border border-border bg-surface px-2 py-1 text-xs font-medium">
                  {n}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted">Scanner names not available Yet — fleet will expand to 30+ scanners.</p>
          )}
          <p className="text-xs text-muted">Upgrade / downgrade / rollback and worker pools are part of the future Scanner Control Plane (Phase 7+).</p>
        </div>
      </DashboardSection>

      {/* System Health */}
      <DashboardSection title="System Health" action={<Link href="/admin/system" className="text-xs font-medium text-primary hover:underline">View system</Link>}>
        <div className="grid gap-3 sm:grid-cols-3">
          {Object.entries(summary.system_health || {}).map(([k, v]) => (
            <div key={k} className="flex items-center justify-between rounded-sm border border-border bg-canvas p-3">
              <span className="text-xs font-medium capitalize text-muted">{k}</span>
              <HealthBadge status={v} />
            </div>
          ))}
        </div>
        <p className="mt-2 text-xs text-muted">Health checks are lightweight `SELECT 1` for database; Redis/RabbitMQ/Worker show Unknown without expensive probes.</p>
      </DashboardSection>

      {/* Organization Inventory */}
      <DashboardSection title="Organization Inventory" action={<Link href="/admin/organizations" className="text-xs font-medium text-primary hover:underline">View all organizations</Link>}>
        {orgs.items.length === 0 ? (
          <EmptyState title="No organizations" description="No organizations available." />
        ) : (
          <DataTable
            rowKey={(r) => r.id}
            columns={[
              { key: "name", header: "Organization" },
              { key: "projects", header: "Projects" },
              { key: "members", header: "Members" },
              { key: "open_findings", header: "Open Findings" },
              { key: "critical_findings", header: "Critical" },
              { key: "assets", header: "Assets" },
              { key: "active_scans", header: "Active Scans" },
            ]}
            rows={orgs.items}
          />
        )}
        <p className="mt-2 text-xs text-muted">Read-only inventory — lifecycle management in Phase 7B. No sensitive evidence exposed.</p>
      </DashboardSection>

      {/* Audit */}
      <DashboardSection title="Super Admin Audit" action={<Link href="/audit" className="text-xs font-medium text-primary hover:underline">View audit logs</Link>}>
        <p className="text-sm text-muted">
          Platform-wide audit events are available via the existing <Link href="/audit" className="text-primary hover:underline">Audit</Link> workspace. No duplicate implementation.
        </p>
        <p className="text-xs text-muted">Audit is tenant-isolated for org users; super_admin sees platform-wide.</p>
      </DashboardSection>
    </div>
  );
}
