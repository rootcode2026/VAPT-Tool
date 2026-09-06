/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { listAdminUsers, updateAdminUser } from "@/lib/api/admin";

function StatusBadge({ status }) {
  const map = {
    active: "bg-emerald-500/10 text-emerald-600 border-emerald-500/20",
    suspended: "bg-amber-500/10 text-amber-600 border-amber-500/20",
  };
  return (
    <span className={`inline-flex rounded-sm border px-2 py-0.5 text-xs font-medium ${map[status] || map.active}`}>
      {status}
    </span>
  );
}

export default function AdminUsersPage() {
  const [data, setData] = useState({ items: [], total: 0, total_pages: 0, page: 1, page_size: 20 });
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [orgFilter, setOrgFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editUser, setEditUser] = useState(null);
  const [editStatus, setEditStatus] = useState("active");
  const [editError, setEditError] = useState("");
  const [editLoading, setEditLoading] = useState(false);

  const load = async (p = page) => {
    setLoading(true);
    setError("");
    try {
      const result = await listAdminUsers({
        page: p,
        page_size: 20,
        search: search || undefined,
        role: roleFilter || undefined,
        status: statusFilter || undefined,
        organization_id: orgFilter || undefined,
      });
      setData(result);
    } catch (err) {
      setError(err.message || "Unable to load users.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  const handleSearch = () => {
    setPage(1);
    load(1);
  };

  const handleStatusChange = async (e) => {
    e.preventDefault();
    if (!editUser) return;
    setEditError("");
    setEditLoading(true);
    try {
      await updateAdminUser(editUser.id, { status: editStatus });
      setEditUser(null);
      load(page);
    } catch (err) {
      setEditError(err.message || "Unable to update user.");
    } finally {
      setEditLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <PageHeader title="Users" description="Platform user administration — status and membership." />

      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-end">
        <label className="flex flex-col gap-1 text-xs sm:w-48">
          <span className="font-medium text-muted">Search (email)</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="email"
            className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium text-muted">Role</span>
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            <option value="">All</option>
            <option value="super_admin">super_admin</option>
            <option value="admin">admin</option>
            <option value="member">member</option>
          </select>
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
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs sm:w-48">
          <span className="font-medium text-muted">Organization ID</span>
          <input
            value={orgFilter}
            onChange={(e) => setOrgFilter(e.target.value)}
            placeholder="org UUID"
            className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm font-mono text-text placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          />
        </label>
        <button
          type="button"
          onClick={handleSearch}
          className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Apply
        </button>
        <button
          type="button"
          onClick={() => {
            setSearch("");
            setRoleFilter("");
            setStatusFilter("");
            setOrgFilter("");
            setPage(1);
            load(1);
          }}
          className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Clear
        </button>
      </div>

      {loading ? (
        <LoadingState message="Loading users..." />
      ) : error ? (
        <ErrorState title="Unable to load users." message={error} onRetry={() => load(page)} />
      ) : data.items.length === 0 ? (
        <EmptyState title="No users" description="No users match the current filters." />
      ) : (
        <>
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="min-w-full text-left text-sm" role="table" aria-label="Users">
              <thead className="border-b border-border bg-surface-hover text-xs uppercase tracking-wide text-muted">
                <tr>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Email
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Organization
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Role
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Status
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((u) => (
                  <tr key={u.id} className="border-b border-border last:border-0 hover:bg-surface-hover/60">
                    <td className="px-3 py-2.5 font-mono text-xs">{u.email}</td>
                    <td className="px-3 py-2.5 font-mono text-xs">{u.organization_id.slice(0, 8)}…</td>
                    <td className="px-3 py-2.5">{u.role}</td>
                    <td className="px-3 py-2.5">
                      <StatusBadge status={u.status} />
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex gap-1">
                        <Link
                          href={`/admin/users/${u.id}`}
                          className="rounded-sm border border-border bg-surface px-2 py-1 text-xs text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                        >
                          View
                        </Link>
                        <button
                          type="button"
                          onClick={() => {
                            setEditUser(u);
                            setEditStatus(u.status);
                            setEditError("");
                          }}
                          className="rounded-sm border border-border bg-surface px-2 py-1 text-xs text-text hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                        >
                          Status
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

      {editUser ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="edit-user-title">
          <button type="button" className="absolute inset-0 bg-canvas/70" aria-label="Close" onClick={() => setEditUser(null)} />
          <form onSubmit={handleStatusChange} className="relative w-full max-w-md rounded-md border border-border bg-canvas p-4 shadow-lg">
            <h2 id="edit-user-title" className="text-sm font-semibold text-text">
              Change User Status
            </h2>
            <p className="mt-1 text-xs text-muted">User: {editUser.email}</p>
            <div className="mt-3 space-y-3">
              <label className="flex flex-col gap-1 text-xs">
                <span className="font-medium text-muted">Status</span>
                <select
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                  className="rounded-sm border border-border bg-canvas px-2 py-1.5 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                >
                  <option value="active">active — can authenticate</option>
                  <option value="suspended">suspended — cannot authenticate</option>
                </select>
              </label>
              <p className="text-xs text-muted">Suspended users cannot authenticate. Super_admin status is platform-level; org_admin is via membership.</p>
              {editError ? <p className="text-xs text-red-600" role="alert">{editError}</p> : null}
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" onClick={() => setEditUser(null)} className="rounded-sm border border-border bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover">
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
