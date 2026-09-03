"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import AddTargetForm from "@/components/projects/AddTargetForm";
import ProjectTabs from "@/components/projects/ProjectTabs";
import ConfirmDialog from "@/components/ui/ConfirmDialog";
import DataTable from "@/components/ui/DataTable";
import EmptyState from "@/components/ui/EmptyState";
import ErrorState from "@/components/ui/ErrorState";
import FilterBar from "@/components/ui/FilterBar";
import LoadingState from "@/components/ui/LoadingState";
import PageHeader from "@/components/ui/PageHeader";
import SearchInput from "@/components/ui/SearchInput";
import StatusBadge from "@/components/ui/StatusBadge";
import { getProject } from "@/lib/api/projects";
import { listScans } from "@/lib/api/scans";
import { deleteTarget, listTargets } from "@/lib/api/targets";
import { ApiError } from "@/lib/api/client";
import { useProjectContext } from "@/lib/project-context";

function scanItems(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  return [];
}

function formatWhen(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not available";
  return date.toLocaleString();
}

function latestScanForTarget(scans, targetId) {
  return scans
    .filter((scan) => scan.target_id === targetId)
    .sort(
      (left, right) =>
        (Date.parse(right.created_at || "") || 0) -
        (Date.parse(left.created_at || "") || 0)
    )[0];
}

function ProjectDetailPage() {
  const params = useParams();
  const searchParams = useSearchParams();
  const projectId = params.project_id;
  const tab = searchParams.get("tab") === "targets" ? "targets" : "overview";
  const { setSelectedProjectId, refreshProjects } = useProjectContext();

  const [project, setProject] = useState(null);
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState("");
  const [notFound, setNotFound] = useState(false);
  const [search, setSearch] = useState("");
  const [showAddTarget, setShowAddTarget] = useState(false);
  const [deleteCandidate, setDeleteCandidate] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [actionError, setActionError] = useState("");

  async function loadWorkspace() {
    setStatus("loading");
    setError("");
    setNotFound(false);
    try {
      const [projectData, allTargets, scansData] = await Promise.all([
        getProject(projectId),
        listTargets(),
        listScans({ page: 1, page_size: 100 }),
      ]);
      if (!projectData?.id) {
        setNotFound(true);
        setStatus("ready");
        return;
      }
      if (allTargets != null && !Array.isArray(allTargets)) {
        throw new Error("Unable to load security data.");
      }
      const projectTargets = (Array.isArray(allTargets) ? allTargets : []).filter(
        (target) => target.project_id === projectId
      );
      const targetIds = new Set(projectTargets.map((target) => target.id));
      setProject(projectData);
      setTargets(projectTargets);
      setScans(
        scanItems(scansData).filter((scan) => targetIds.has(scan.target_id))
      );
      setStatus("ready");
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setNotFound(true);
        setStatus("ready");
        return;
      }
      setError(err.message || "Unable to load security data.");
      setStatus("error");
    }
  }

  useEffect(() => {
    if (!projectId) return undefined;
    setSelectedProjectId(projectId);
    const id = window.setTimeout(() => {
      loadWorkspace();
    }, 0);
    return () => window.clearTimeout(id);
  }, [projectId, setSelectedProjectId]);

  const filteredTargets = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return targets;
    return targets.filter(
      (target) =>
        target.value?.toLowerCase().includes(query) ||
        target.target_type?.toLowerCase().includes(query)
    );
  }, [targets, search]);

  async function confirmDeleteTarget() {
    if (!deleteCandidate) return;
    setDeleting(true);
    setActionError("");
    try {
      await deleteTarget(deleteCandidate.id);
      setDeleteCandidate(null);
      await loadWorkspace();
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err.message
          : "Unable to delete the target."
      );
    } finally {
      setDeleting(false);
    }
  }

  if (status === "loading") {
    return <LoadingState message="Loading security data..." />;
  }

  if (notFound) {
    return (
      <EmptyState
        title="Project not found."
        description="This project does not exist or is not available to your organization."
        action={
          <Link
            href="/projects"
            className="rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground"
          >
            Back to projects
          </Link>
        }
      />
    );
  }

  if (status === "error") {
    return (
      <ErrorState
        title="Unable to load security data."
        message={error}
        onRetry={loadWorkspace}
      />
    );
  }

  return (
    <div>
      <PageHeader
        title={project.name}
        description={
          project.description ||
          "Add targets and start a scan to assess this project."
        }
        actions={
          <>
            <button
              type="button"
              onClick={() => setShowAddTarget(true)}
              className="rounded-sm border border-border px-3 py-1.5 text-sm text-text hover:bg-surface-hover"
            >
              Add Target
            </button>
            <Link
              href={
                targets[0]
                  ? `/scans?project_id=${projectId}&target_id=${targets[0].id}`
                  : `/projects/${projectId}?tab=targets`
              }
              className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground"
            >
              Start Scan
            </Link>
          </>
        }
      />

      <ProjectTabs projectId={projectId} active={tab} />

      {actionError ? (
        <p className="mb-4 text-sm text-danger" role="alert">
          {actionError}
        </p>
      ) : null}

      {showAddTarget ? (
        <div className="mb-6">
          <AddTargetForm
            projectId={projectId}
            onCancel={() => setShowAddTarget(false)}
            onCreated={async () => {
              setShowAddTarget(false);
              await loadWorkspace();
              await refreshProjects({ silent: true });
            }}
          />
        </div>
      ) : null}

      {tab === "overview" ? (
        <section className="grid gap-3 sm:grid-cols-3">
          <article className="rounded-md border border-border bg-surface p-4">
            <p className="text-xs uppercase tracking-wide text-muted">Targets</p>
            <p className="mt-2 text-2xl font-semibold tabular-nums">
              {targets.length}
            </p>
          </article>
          <article className="rounded-md border border-border bg-surface p-4">
            <p className="text-xs uppercase tracking-wide text-muted">Scans</p>
            <p className="mt-2 text-2xl font-semibold tabular-nums">
              {scans.length}
            </p>
          </article>
          <article className="rounded-md border border-border bg-surface p-4">
            <p className="text-xs uppercase tracking-wide text-muted">Next step</p>
            <p className="mt-2 text-sm text-text">
              {targets.length === 0
                ? "Add a target, then start a scan."
                : "Start a scan against a target."}
            </p>
          </article>
        </section>
      ) : null}

      {tab === "targets" ? (
        <>
          {targets.length === 0 && !showAddTarget ? (
            <EmptyState
              title="No targets added yet."
              description="Add a domain, URL, or supported target to begin security scanning."
              action={
                <button
                  type="button"
                  onClick={() => setShowAddTarget(true)}
                  className="rounded-sm bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground"
                >
                  Add Target
                </button>
              }
            />
          ) : null}

          {targets.length > 0 ? (
            <>
              <FilterBar>
                <SearchInput
                  id="target-search"
                  label="Search targets"
                  placeholder="Search targets"
                  value={search}
                  onChange={setSearch}
                />
              </FilterBar>
              <DataTable
                rowKey={(row) => row.id}
                empty={<EmptyState title="No targets match this search." />}
                columns={[
                  { key: "value", header: "Target" },
                  {
                    key: "target_type",
                    header: "Type",
                    render: (row) => row.target_type,
                  },
                  {
                    key: "is_active",
                    header: "Status",
                    render: (row) => (
                      <StatusBadge
                        status={row.is_active ? "active" : "inactive"}
                      />
                    ),
                  },
                  {
                    key: "last_scan",
                    header: "Last scan",
                    render: (row) => {
                      const scan = latestScanForTarget(scans, row.id);
                      return scan ? formatWhen(scan.created_at) : "Not available";
                    },
                  },
                  {
                    key: "actions",
                    header: "Actions",
                    render: (row) => (
                      <div className="flex flex-wrap gap-2">
                        <Link
                          href={`/scans?project_id=${projectId}&target_id=${row.id}`}
                          className="text-xs font-medium text-primary hover:underline"
                        >
                          Start Scan
                        </Link>
                        <button
                          type="button"
                          className="text-xs text-danger hover:underline"
                          onClick={() => {
                            setActionError("");
                            setDeleteCandidate(row);
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    ),
                  },
                ]}
                rows={filteredTargets}
              />
            </>
          ) : null}
        </>
      ) : null}

      <ConfirmDialog
        open={Boolean(deleteCandidate)}
        title="Delete target"
        description={
          deleteCandidate
            ? `Delete target “${deleteCandidate.value}”? This cannot be undone.`
            : ""
        }
        confirmLabel={deleting ? "Deleting..." : "Delete target"}
        confirmDisabled={deleting}
        onCancel={() => setDeleteCandidate(null)}
        onConfirm={confirmDeleteTarget}
      />
    </div>
  );
}

export default function ProjectDetailRoute() {
  return (
    <Suspense fallback={<LoadingState message="Loading security data..." />}>
      <ProjectDetailPage />
    </Suspense>
  );
}
