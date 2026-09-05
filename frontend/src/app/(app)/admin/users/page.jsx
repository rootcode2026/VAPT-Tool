"use client";

import PageHeader from "@/components/ui/PageHeader";
import EmptyState from "@/components/ui/EmptyState";

export default function AdminUsersPage() {
  return (
    <div className="space-y-4">
      <PageHeader title="Users" description="Platform user administration." />
      <EmptyState title="Available in a future administration phase" description="User lifecycle, role assignment, and membership administration will be available in Phase 7B." />
    </div>
  );
}
