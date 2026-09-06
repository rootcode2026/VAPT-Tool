"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import { getAdminUser } from "@/lib/api/admin";

export default function AdminUserDetailPage() {
  const params = useParams();
  const userId = params.user_id;
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const data = await getAdminUser(userId);
        if (cancelled) return;
        setUser(data);
      } catch (err) {
        if (cancelled) return;
        setError(err.message || "Unable to load user.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [userId]);

  if (loading) {
    return (
      <div>
        <PageHeader title="User" description="Safe user details." />
        <LoadingState message="Loading user..." />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader title="User" description="Safe user details." />
        <ErrorState title="Unable to load user." message={error} onRetry={() => window.location.reload()} />
      </div>
    );
  }

  if (!user) {
    return (
      <div>
        <PageHeader title="User" description="Safe user details." />
        <ErrorState title="User not found." message="The requested user does not exist." />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title={user.email}
        description="Safe user details — no password, tokens, or secrets."
        actions={
          <Link href="/admin/users" className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover">
            Back to Users
          </Link>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">User ID</p>
          <p className="mt-1 font-mono text-xs">{user.id}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Organization</p>
          <p className="mt-1 font-mono text-xs">{user.organization_id}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Role</p>
          <p className="mt-1 text-sm font-medium">{user.role}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Status</p>
          <p className="mt-1 text-sm font-medium">{user.status}</p>
        </div>
        <div className="rounded-md border border-border bg-surface p-3">
          <p className="text-xs text-muted">Created</p>
          <p className="mt-1 text-sm">{user.created_at ? new Date(user.created_at).toLocaleString() : "—"}</p>
        </div>
      </div>

      <div className="rounded-md border border-border bg-surface p-4">
        <h3 className="text-sm font-semibold text-text">Organization Memberships</h3>
        {user.organization_memberships && user.organization_memberships.length > 0 ? (
          <ul className="mt-2 space-y-1">
            {user.organization_memberships.map((m, i) => (
              <li key={i} className="flex items-center justify-between rounded-sm border border-border bg-canvas px-3 py-2 text-xs">
                <span>{m.organization_id.slice(0, 8)}…</span>
                <span>
                  {m.role} • {m.status}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-xs text-muted">No organization memberships.</p>
        )}
      </div>

      <div className="rounded-md border border-border bg-surface p-4">
        <h3 className="text-sm font-semibold text-text">Project Memberships</h3>
        {user.project_memberships && user.project_memberships.length > 0 ? (
          <ul className="mt-2 space-y-1">
            {user.project_memberships.map((m, i) => (
              <li key={i} className="flex items-center justify-between rounded-sm border border-border bg-canvas px-3 py-2 text-xs">
                <span>{m.project_id.slice(0, 8)}…</span>
                <span>
                  {m.role} • {m.status}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-xs text-muted">No project memberships.</p>
        )}
      </div>

      <p className="text-xs text-muted">No password, password hash, tokens, or secrets exposed. Project membership respects strict RBAC.</p>
    </div>
  );
}
