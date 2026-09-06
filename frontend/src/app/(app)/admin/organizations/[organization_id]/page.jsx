"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import { getAdminOrganization } from "@/lib/api/admin";

export default function AdminOrganizationDetailPage() {
  const params = useParams();
  const orgId = params.organization_id;
  const [org, setOrg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const data = await getAdminOrganization(orgId);
        if (cancelled) return;
        setOrg(data);
      } catch (err) {
        if (cancelled) return;
        setError(err.message || "Unable to load organization.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [orgId]);

  if (loading) {
    return (
      <div>
        <PageHeader title="Organization" description="Administrative overview." />
        <LoadingState message="Loading organization..." />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="Organization" description="Administrative overview." />
        <ErrorState title="Unable to load organization." message={error} onRetry={() => window.location.reload()} />
      </div>
    );
  }

  if (!org) {
    return (
      <div>
        <PageHeader title="Organization" description="Administrative overview." />
        <ErrorState title="Organization not found." message="The requested organization does not exist." />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title={org.name}
        description={`Slug: ${org.slug} • Status: ${org.status}`}
        actions={
          <Link href="/admin/organizations" className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover">
            Back to Organizations
          </Link>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Projects</p>
          <p className="mt-1 text-lg font-semibold tabular-nums">{org.projects}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Members</p>
          <p className="mt-1 text-lg font-semibold tabular-nums">{org.members}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Open Findings</p>
          <p className="mt-1 text-lg font-semibold tabular-nums">{org.open_findings}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Critical Findings</p>
          <p className="mt-1 text-lg font-semibold tabular-nums text-critical">{org.critical_findings}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Assets</p>
          <p className="mt-1 text-lg font-semibold tabular-nums">{org.assets}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Active Scans</p>
          <p className="mt-1 text-lg font-semibold tabular-nums">{org.active_scans}</p>
        </div>
      </div>

      <div className="rounded-md border border-border bg-surface p-4">
        <h3 className="text-sm font-semibold text-text">Recent Audit Activity</h3>
        {org.recent_audit && org.recent_audit.length > 0 ? (
          <ul className="mt-2 space-y-2">
            {org.recent_audit.map((a) => (
              <li key={a.id} className="flex items-center justify-between rounded-sm border border-border bg-canvas px-3 py-2">
                <div>
                  <p className="text-sm font-medium">{a.event_type} • {a.result}</p>
                  <p className="text-xs text-muted">{a.created_at ? new Date(a.created_at).toLocaleString() : "—"} • {a.actor_user_id ? a.actor_user_id.slice(0, 8) : "system"}</p>
                </div>
                <span className="rounded-sm border border-border bg-surface px-1.5 py-0.5 text-xs">{a.action}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-xs text-muted">No recent audit activity.</p>
        )}
      </div>

      <p className="text-xs text-muted">No passwords, tokens, or sensitive finding evidence exposed. Members management via existing membership APIs.</p>
    </div>
  );
}
