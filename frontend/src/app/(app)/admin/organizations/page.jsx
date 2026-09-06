/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { listAdminOrganizations, createAdminOrganization, updateAdminOrganization } from "@/lib/api/admin";

function StatusBadge({ status }) {
  const map = {
    active: "bg-emerald-500/10 text-emerald-600 border-emerald-500/20",
    suspended: "bg-amber-500/10 text-amber-600 border-amber-500/20",
    archived: "bg-slate-500/10 text-slate-600 border-slate-500/20",
  };
  return (
    <span className={`inline-flex rounded-sm border px-2 py-0.5 text-xs font-medium ${map[status] || map.active}`}>
      {status}
    </span>
  );
}

export default function AdminOrganizationsPage() {
  const [data, setData] = useState({ items: [], total: 0, total_pages: 0, page: 1, page_size: 20 });
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState({ name: "", slug: "", status: "active" });
  const [createError, setCreateError] = useState("");
  const [createLoading, setCreateLoading] = useState(false);
  const [editOrg, setEditOrg] = useState(null);
  const [editForm, setEditForm] = useState({ name: "", slug: "", status: "active" });
  const [editError, setEditError] = useState("");
  const [editLoading, setEditLoading] = useState(false);

  const load = async (p = page, s = search, st = statusFilter) => {
    setLoading(true);
    setError("");
    try {
      const result = await listAdminOrganizations({ page: p, page_size: 20, search: s || undefined, status: st || undefined });
      setData(result);
    } catch (err) {
      setError(err.message || "Unable to load organizations.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(page, search, statusFilter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  const handleSearchApply = () => {
    setPage(1);
    load(1, search, statusFilter);
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    setCreateError("");
    setCreateLoading(true);
    try {
      await createAdminOrganization(createForm);
      setShowCreate(false);
      setCreateForm({ name: "", slug: "", status: "active" });
      load(1, search, statusFilter);
    } catch (err) {
      setCreateError(err.message || "Unable to create organization.");
    } finally {
      setCreateLoading(false);
    }
  };

  const handleEdit = async (e) => {
    e.preventDefault();
    if (!editOrg) return;
    setEditError("");
    setEditLoading(true);
    try {
      await updateAdminOrganization(editOrg.id, editForm);
      setEditOrg(null);
      load(page, search, statusFilter);
    } catch (err) {
      setEditError(err.message || "Unable to update organization.");
    } finally {
      setEditLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title="Organizations"
        description="Platform organization lifecycle — create, view, and manage status."
        actions={
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            Create Organization
          </button>
        }
      />

      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <label className="flex flex-col gap-1 text-xs sm:w-64">
          <span className="font-medium text-muted">Search</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Name or slug"
            className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium text-muted">Status</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            <option value="">All</option>
            <option value="active">active</option>
            <option value="suspended">suspended</option>
            <option value="archived">archived</option>
          </select>
        </label>
        <button
          type="button"
          onClick={handleSearchApply}
          className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Apply
        </button>
        <button
          type="button"
          onClick={() => {
            setSearch("");
            setStatusFilter("");
            setPage(1);
            load(1, "", "");
          }}
          className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Clear
        </button>
      </div>

      {loading ? (
        <LoadingState message="Loading organizations..." />
      ) : error ? (
        <ErrorState title="Unable to load organizations." message={error} onRetry={() => load(page, search, statusFilter)} />
      ) : data.items.length === 0 ? (
        <EmptyState title="No organizations" description="No organizations match the current filters." />
      ) : (
        <>
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="min-w-full text-left text-sm" role="table" aria-label="Organizations">
              <thead className="border-b border-border bg-surface-hover text-xs uppercase tracking-wide text-muted">
                <tr>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Organization
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Slug
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Status
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Projects
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Members
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((org) => (
                  <tr key={org.id} className="border-b border-border last:border-0 hover:bg-surface-hover/60">
                    <td className="px-3 py-2.5 font-medium text-text">
                      <Link href={`/admin/organizations/${org.id}`} className="hover:underline">
                        {org.name}
                      </Link>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs text-muted">{org.slug}</td>
                    <td className="px-3 py-2.5">
                      <StatusBadge status={org.status} />
                    </td>
                    <td className="px-3 py-2.5 tabular-nums">{org.projects}</td>
                    <td className="px-3 py-2.5 tabular-nums">{org.members}</td>
                    <td className="px-3 py-2.5">
                      <div className="flex gap-1">
                        <Link
                          href={`/admin/organizations/${org.id}`}
                          className="rounded-sm border border-border bg-surface px-2 py-1 text-xs text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                        >
                          View
                        </Link>
                        <button
                          type="button"
                          onClick={() => {
                            setEditOrg(org);
                            setEditForm({ name: org.name, slug: org.slug, status: org.status });
                            setEditError("");
                          }}
                          className="rounded-sm border border-border bg-surface px-2 py-1 text-xs text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                        >
                          Edit
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex flex-col items-center justify-between gap-3 border-t border-border pt-3 sm:flex-row">
            <p className="text-xs text-muted">
              Page <span className="font-medium text-text">{data.page}</span> of <span className="font-medium text-text">{data.total_pages || 1}</span> • {data.total} total
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={data.page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={data.page >= (data.total_pages || 1)}
                onClick={() => setPage((p) => Math.min(data.total_pages || 1, p + 1))}
                className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}

      {showCreate ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="create-org-title">
          <button type="button" className="absolute inset-0 bg-canvas/70" aria-label="Close" onClick={() => setShowCreate(false)} />
          <form onSubmit={handleCreate} className="relative w-full max-w-md rounded-md border border-border bg-canvas p-4 shadow-lg">
            <h2 id="create-org-title" className="text-sm font-semibold text-text">
              Create Organization
            </h2>
            <div className="mt-3 space-y-3">
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Name *</span>
                <input
                  value={createForm.name}
                  onChange={(e) => setCreateForm((f) => ({ ...f, name: e.target.value }))}
                  required
                  maxLength={255}
                  className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Slug *</span>
                <input
                  value={createForm.slug}
                  onChange={(e) => setCreateForm((f) => ({ ...f, slug: e.target.value }))}
                  required
                  placeholder="e.g. acme-corp"
                  className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm font-mono text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                />
                <span className="text-xs text-muted">Lowercase, letters/numbers/hyphens only, unique.</span>
              </label>
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Status</span>
                <select
                  value={createForm.status}
                  onChange={(e) => setCreateForm((f) => ({ ...f, status: e.target.value }))}
                  className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                >
                  <option value="active">active</option>
                  <option value="suspended">suspended</option>
                  <option value="archived">archived</option>
                </select>
              </label>
              {createError ? <p className="text-xs text-red-600" role="alert">{createError}</p> : null}
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" onClick={() => setShowCreate(false)} className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover">
                Cancel
              </button>
              <button type="submit" disabled={createLoading} className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground hover:bg-primary/90 disabled:opacity-60">
                {createLoading ? "Creating..." : "Create"}
              </button>
            </div>
          </form>
        </div>
      ) : null}

      {editOrg ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="edit-org-title">
          <button type="button" className="absolute inset-0 bg-canvas/70" aria-label="Close" onClick={() => setEditOrg(null)} />
          <form onSubmit={handleEdit} className="relative w-full max-w-md rounded-md border border-border bg-canvas p-4 shadow-lg">
            <h2 id="edit-org-title" className="text-sm font-semibold text-text">
              Edit Organization
            </h2>
            <div className="mt-3 space-y-3">
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Name</span>
                <input
                  value={editForm.name}
                  onChange={(e) => setEditForm((f) => ({ ...f, name: e.target.value }))}
                  required
                  className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Slug</span>
                <input
                  value={editForm.slug}
                  onChange={(e) => setEditForm((f) => ({ ...f, slug: e.target.value }))}
                  required
                  className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm font-mono text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Status</span>
                <select
                  value={editForm.status}
                  onChange={(e) => setEditForm((f) => ({ ...f, status: e.target.value }))}
                  className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                >
                  <option value="active">active — normal operation</option>
                  <option value="suspended">suspended — org users blocked, Super Admin retains</option>
                  <option value="archived">archived — retained for audit, ops disabled</option>
                </select>
              </label>
              {editError ? <p className="text-xs text-red-600" role="alert">{editError}</p> : null}
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" onClick={() => setEditOrg(null)} className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover">
                Cancel
              </button>
              <button type="submit" disabled={editLoading} className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground hover:bg-primary/90 disabled:opacity-60">
                {editLoading ? "Saving..." : "Save"}
              </button>
            </div>
          </form>
        </div>
      ) : null}
    </div>
  );
}
