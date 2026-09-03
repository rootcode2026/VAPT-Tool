"use client";

import PageHeader from "@/components/ui/PageHeader";
import { useAuth } from "@/lib/auth/AuthProvider";

export default function SettingsPage() {
  const { user } = useAuth();

  return (
    <div>
      <PageHeader
        title="Settings"
        description="Workspace identity from the authenticated session."
      />
      <section className="max-w-lg rounded-md border border-border bg-surface p-5">
        <dl className="space-y-3 text-sm">
          <div>
            <dt className="text-muted">Email</dt>
            <dd className="mt-1 text-text">{user?.email || "—"}</dd>
          </div>
          <div>
            <dt className="text-muted">Role</dt>
            <dd className="mt-1 text-text">{user?.role || "—"}</dd>
          </div>
          <div>
            <dt className="text-muted">Organization</dt>
            <dd className="mt-1 text-text">{user?.organization_name || "—"}</dd>
          </div>
        </dl>
      </section>
    </div>
  );
}
