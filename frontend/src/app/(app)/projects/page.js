"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import ProjectCreateForm from "@/components/projects/ProjectCreateForm";
import ConfirmDialog from "@/components/ui/ConfirmDialog";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import FilterBar from "@/components/ui/FilterBar";
import PageHeader from "@/components/ui/PageHeader";
import SearchInput from "@/components/ui/SearchInput";
import { SkeletonTable } from "@/components/ui/Skeleton";
import { deleteProject } from "@/lib/api/projects";
import { listScans } from "@/lib/api/scans";
import { listTargets } from "@/lib/api/targets";
import { ApiError } from "@/lib/api/client";
import { useProjectContext } from "@/lib/project-context";

function scanItems(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  return [];
}

export default function ProjectsPage() {
  const router = useRouter();
  const {
    projects,
    status,
    error,
    refreshProjects,
    setSelectedProjectId,
  } = useProjectContext();

  const [search, setSearch] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [counts, setCounts] = useState({ targets: {}, scans: {} });
  const [countsError, setCountsError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [actionError, setActionError] = useState("");

  useEffect(() => {
    if (status !== "ready") return undefined;
    const id = window.setTimeout(async () => {
      try {
        const [targets, scans] = await Promise.all([
          listTargets(),
          listScans({ page: 1, page_size: 100 }),
        ]);
        const targetCounts = {};
        const scanCounts = {};
        const targetList = Array.isArray(targets) ? targets : [];
        for (const target of targetList) {
          targetCounts[target.project_id] =
            (targetCounts[target.project_id] || 0) + 1;
        }
        const targetProject = Object.fromEntries(
          targetList.map((target) => [target.id, target.project_id])
        );
        for (const scan of scanItems(scans)) {
          const projectId = targetProject[scan.target_id];
          if (!projectId) continue;
          scanCounts[projectId] = (scanCounts[projectId] || 0) + 1;
        }
        setCounts({ targets: targetCounts, scans: scanCounts });
        setCountsError("");
      } catch {
        setCountsError("Not available");
      }
    }, 0);
    return () => window.clearTimeout(id);
  }, [status, projects]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return projects;
    return projects.filter((project) => {
      return (
        project.name?.toLowerCase().includes(query) ||
        project.description?.toLowerCase().includes(query)
      );
    });
  }, [projects, search]);

  async function onCreated(project) {
    await refreshProjects({ silent: true });
    setSelectedProjectId(project.id);
    setShowCreate(false);
    router.push(`/projects/${project.id}`);
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    setActionError("");
    try {
      await deleteProject(deleteTarget.id);
      setDeleteTarget(null);
      await refreshProjects({ silent: true });
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err.message
          : "Unable to delete the project."
      );
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Projects"
        description="Projects organize targets, scans, findings, and assets."
        actions={
          <button
            type="button"
            onClick={() => setShowCreate((open) => !open)}
            className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground"
          >
            {showCreate ? "Cancel" : "Create Project"}
          </button>
        }
      />

      {showCreate ? (
        <div className="mb-6">
          <ProjectCreateForm
            onCreated={onCreated}
            onCancel={() => setShowCreate(false)}
          />
        </div>
      ) : null}

      {status === "loading" ? <SkeletonTable rows={4} /> : null}

      {status === "error" ? (
        <ErrorState
          title="Unable to load security data."
          message={error}
          onRetry={() => refreshProjects()}
        />
      ) : null}

      {status === "ready" && projects.length === 0 && !showCreate ? (
        <EmptyState
          title="Create your first security project"
          description="Projects organize targets, scans, findings, and assets."
          action={
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground"
            >
              Create Project
            </button>
          }
        />
      ) : null}

      {status === "ready" && projects.length > 0 ? (
        <>
          <FilterBar>
            <SearchInput
              id="project-search"
              label="Search projects"
              placeholder="Search projects"
              value={search}
              onChange={setSearch}
            />
          </FilterBar>
          {actionError ? (
            <p className="mb-3 text-sm text-danger" role="alert">
              {actionError}
            </p>
          ) : null}
          <DataTable
            rowKey={(row) => row.id}
            empty={
              <EmptyState title="No projects match this search." />
            }
            columns={[
              {
                key: "name",
                header: "Name",
                render: (row) => (
                  <Link
                    href={`/projects/${row.id}`}
                    className="font-medium hover:underline"
                    onClick={() => setSelectedProjectId(row.id)}
                  >
                    {row.name}
                  </Link>
                ),
              },
              {
                key: "description",
                header: "Description",
                render: (row) => row.description || "—",
              },
              {
                key: "targets",
                header: "Targets",
                render: (row) =>
                  countsError ? "Not available" : counts.targets[row.id] || 0,
              },
              {
                key: "scans",
                header: "Scans",
                render: (row) =>
                  countsError ? "Not available" : counts.scans[row.id] || 0,
              },
              {
                key: "actions",
                header: "Actions",
                render: (row) => (
                  <div className="flex gap-2">
                    <Link
                      href={`/projects/${row.id}?tab=targets`}
                      className="text-xs text-primary hover:underline"
                      onClick={() => setSelectedProjectId(row.id)}
                    >
                      Open
                    </Link>
                    <Link
                      href={`/projects/${row.id}/dashboard`}
                      className="text-xs text-primary hover:underline"
                      onClick={() => setSelectedProjectId(row.id)}
                    >
                      SOC Dashboard
                    </Link>
                    <Link
                      href={`/projects/${row.id}/compliance`}
                      className="text-xs text-primary hover:underline"
                      onClick={() => setSelectedProjectId(row.id)}
                    >
                      Compliance
                    </Link>
                    <button
                      type="button"
                      className="text-xs text-danger hover:underline"
                      onClick={() => {
                        setActionError("");
                        setDeleteTarget(row);
                      }}
                    >
                      Delete
                    </button>
                  </div>
                ),
              },
            ]}
            rows={filtered}
          />
        </>
      ) : null}

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        title="Delete project"
        description={
          deleteTarget
            ? `Delete “${deleteTarget.name}”? This cannot be undone. Projects with targets cannot be deleted until those targets are removed.`
            : ""
        }
        confirmLabel={deleting ? "Deleting..." : "Delete project"}
        confirmDisabled={deleting}
        onCancel={() => setDeleteTarget(null)}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
