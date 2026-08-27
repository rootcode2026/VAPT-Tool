"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import AppShell from "@/components/layout/AppShell";

const API_URL = "http://localhost:8000";

export default function TargetsPage() {
  const searchParams = useSearchParams();

  const projectIdFromUrl =
    searchParams.get("project_id") || "";

  const [targets, setTargets] = useState([]);
  const [projects, setProjects] = useState([]);

  const [selectedProject, setSelectedProject] =
    useState(projectIdFromUrl);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [showCreateForm, setShowCreateForm] =
    useState(false);

  const [value, setValue] = useState("");
  const [targetType, setTargetType] =
    useState("domain");

  const [creating, setCreating] = useState(false);
  const [deletingId, setDeletingId] = useState(null);

  /*
   * ---------------------------------------------------------
   * Load projects and targets
   * ---------------------------------------------------------
   */

  async function loadData() {
    try {
      setLoading(true);
      setError("");

      const [
        projectsResponse,
        targetsResponse,
      ] = await Promise.all([
        fetch(`${API_URL}/api/v1/projects`),
        fetch(`${API_URL}/api/v1/targets`),
      ]);

      if (!projectsResponse.ok) {
        throw new Error(
          "Failed to load projects"
        );
      }

      if (!targetsResponse.ok) {
        throw new Error(
          "Failed to load targets"
        );
      }

      const projectsData =
        await projectsResponse.json();

      const targetsData =
        await targetsResponse.json();

      setProjects(projectsData);
      setTargets(targetsData);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to load targets"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  /*
   * ---------------------------------------------------------
   * Filter targets
   * ---------------------------------------------------------
   */

  const filteredTargets =
    selectedProject
      ? targets.filter(
          (target) =>
            target.project_id ===
            selectedProject
        )
      : targets;

  /*
   * ---------------------------------------------------------
   * Create target
   * ---------------------------------------------------------
   */

  async function createTarget(event) {
    event.preventDefault();

    if (!selectedProject) {
      setError(
        "Please select a project."
      );
      return;
    }

    if (!value.trim()) {
      setError(
        "Please enter a target."
      );
      return;
    }

    try {
      setCreating(true);
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/targets`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            project_id: selectedProject,
            value: value.trim(),
            target_type: targetType,
          }),
        }
      );

      if (!response.ok) {
        const errorData =
          await response.json().catch(
            () => null
          );

        throw new Error(
          errorData?.detail ||
            "Failed to create target"
        );
      }

      const newTarget =
        await response.json();

      setTargets((current) => [
        newTarget,
        ...current,
      ]);

      setValue("");
      setTargetType("domain");
      setShowCreateForm(false);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to create target"
      );
    } finally {
      setCreating(false);
    }
  }

  /*
   * ---------------------------------------------------------
   * Delete target
   * ---------------------------------------------------------
   */

  async function deleteTarget(targetId) {
    const confirmed =
      window.confirm(
        "Are you sure you want to delete this target?"
      );

    if (!confirmed) {
      return;
    }

    try {
      setDeletingId(targetId);
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/targets/${targetId}`,
        {
          method: "DELETE",
        }
      );

      if (!response.ok) {
        const errorData =
          await response.json().catch(
            () => null
          );

        throw new Error(
          errorData?.detail ||
            "Failed to delete target"
        );
      }

      setTargets((current) =>
        current.filter(
          (target) =>
            target.id !== targetId
        )
      );
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to delete target"
      );
    } finally {
      setDeletingId(null);
    }
  }

  /*
   * ---------------------------------------------------------
   * Helpers
   * ---------------------------------------------------------
   */

  function getProjectName(projectId) {
    const project =
      projects.find(
        (item) =>
          item.id === projectId
      );

    return (
      project?.name ||
      projectId
    );
  }

  /*
   * ---------------------------------------------------------
   * Loading
   * ---------------------------------------------------------
   */

  if (loading) {
    return (
      <AppShell>
        <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
          <div className="text-center">
            <div className="text-xl font-semibold">
              Loading targets...
            </div>

            <p className="mt-2 text-sm text-slate-400">
              Fetching target information
            </p>
          </div>
        </main>
      </AppShell>
    );
  }

  /*
   * ---------------------------------------------------------
   * Main
   * ---------------------------------------------------------
   */

  return (
    <AppShell>
      <main className="min-h-screen bg-slate-950 text-white">

        {/* Header */}
        <header className="border-b border-slate-800">
          <div className="mx-auto max-w-7xl px-6 py-6">

            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">

              <div>
                <h1 className="text-2xl font-bold">
                  Targets
                </h1>

                <p className="mt-1 text-sm text-slate-400">
                  Manage domains, IP addresses,
                  and URLs for security testing.
                </p>
              </div>

              <button
                type="button"
                onClick={() =>
                  setShowCreateForm(
                    (current) => !current
                  )
                }
                className="rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-slate-200"
              >
                {showCreateForm
                  ? "Cancel"
                  : "+ New Target"}
              </button>

            </div>

          </div>
        </header>

        {/* Content */}
        <div className="mx-auto max-w-7xl px-6 py-8">

          {/* Error */}
          {error && (
            <div className="mb-6 rounded-lg border border-red-900 bg-red-950/40 p-4 text-sm text-red-300">
              {error}
            </div>
          )}

          {/* -------------------------------------------------
              Project Filter
          -------------------------------------------------- */}

          <section className="mb-6 rounded-xl border border-slate-800 bg-slate-900 p-5">

            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">

              <div className="flex-1">

                <label
                  htmlFor="project-filter"
                  className="mb-2 block text-sm font-medium text-slate-300"
                >
                  Project
                </label>

                <select
                  id="project-filter"
                  value={selectedProject}
                  onChange={(event) =>
                    setSelectedProject(
                      event.target.value
                    )
                  }
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
                >

                  <option value="">
                    All Projects
                  </option>

                  {projects.map(
                    (project) => (
                      <option
                        key={project.id}
                        value={project.id}
                      >
                        {project.name}
                      </option>
                    )
                  )}

                </select>

              </div>

              <div className="sm:pt-7">

                <span className="inline-flex rounded-lg bg-slate-800 px-4 py-3 text-sm text-slate-300">
                  {filteredTargets.length}{" "}
                  {filteredTargets.length === 1
                    ? "target"
                    : "targets"}
                </span>

              </div>

            </div>

          </section>

          {/* -------------------------------------------------
              Create Target
          -------------------------------------------------- */}

          {showCreateForm && (
            <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-6">

                <h2 className="text-lg font-semibold">
                  Add Target
                </h2>

                <p className="mt-1 text-sm text-slate-400">
                  Add a domain, IP address, or URL
                  to a project.
                </p>

              </div>

              <form
                onSubmit={createTarget}
                className="space-y-5"
              >

                {/* Project */}
                <div>

                  <label
                    htmlFor="target-project"
                    className="mb-2 block text-sm font-medium text-slate-300"
                  >
                    Project
                  </label>

                  <select
                    id="target-project"
                    value={selectedProject}
                    onChange={(event) =>
                      setSelectedProject(
                        event.target.value
                      )
                    }
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
                  >

                    <option value="">
                      Select a project
                    </option>

                    {projects.map(
                      (project) => (
                        <option
                          key={project.id}
                          value={project.id}
                        >
                          {project.name}
                        </option>
                      )
                    )}

                  </select>

                </div>

                {/* Target */}
                <div>

                  <label
                    htmlFor="target-value"
                    className="mb-2 block text-sm font-medium text-slate-300"
                  >
                    Target
                  </label>

                  <input
                    id="target-value"
                    type="text"
                    value={value}
                    onChange={(event) =>
                      setValue(
                        event.target.value
                      )
                    }
                    placeholder="example.com"
                    maxLength={255}
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-slate-500"
                  />

                </div>

                {/* Type */}
                <div>

                  <label
                    htmlFor="target-type"
                    className="mb-2 block text-sm font-medium text-slate-300"
                  >
                    Target Type
                  </label>

                  <select
                    id="target-type"
                    value={targetType}
                    onChange={(event) =>
                      setTargetType(
                        event.target.value
                      )
                    }
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
                  >

                    <option value="domain">
                      Domain
                    </option>

                    <option value="ip">
                      IP Address
                    </option>

                    <option value="url">
                      URL
                    </option>

                  </select>

                </div>

                {/* Buttons */}
                <div className="flex justify-end gap-3">

                  <button
                    type="button"
                    onClick={() => {
                      setShowCreateForm(
                        false
                      );
                      setValue("");
                    }}
                    className="rounded-lg border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800"
                  >
                    Cancel
                  </button>

                  <button
                    type="submit"
                    disabled={
                      creating ||
                      !selectedProject ||
                      !value.trim()
                    }
                    className="rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {creating
                      ? "Adding..."
                      : "Add Target"}
                  </button>

                </div>

              </form>

            </section>
          )}

          {/* -------------------------------------------------
              Targets Table
          -------------------------------------------------- */}

          {filteredTargets.length === 0 ? (

            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-12 text-center">

              <h2 className="text-lg font-semibold">
                No targets found
              </h2>

              <p className="mx-auto mt-2 max-w-md text-sm text-slate-400">
                Add a domain, IP address, or URL
                to start scanning.
              </p>

              <button
                type="button"
                onClick={() =>
                  setShowCreateForm(true)
                }
                className="mt-6 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950"
              >
                Add Target
              </button>

            </div>

          ) : (

            <section>

              <div className="mb-4">

                <h2 className="text-lg font-semibold">
                  Target List
                </h2>

                <p className="mt-1 text-sm text-slate-400">
                  Targets available for security
                  assessment.
                </p>

              </div>

              <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">

                <div className="overflow-x-auto">

                  <table className="w-full text-left text-sm">

                    <thead className="border-b border-slate-800 bg-slate-950">

                      <tr>

                        <th className="px-6 py-4">
                          Target
                        </th>

                        <th className="px-6 py-4">
                          Type
                        </th>

                        <th className="px-6 py-4">
                          Project
                        </th>

                        <th className="px-6 py-4">
                          Status
                        </th>

                        <th className="px-6 py-4">
                          Actions
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {filteredTargets.map(
                        (target) => (

                          <tr
                            key={target.id}
                            className="border-b border-slate-800 last:border-0"
                          >

                            <td className="px-6 py-5">

                              <div className="font-medium">
                                {target.value}
                              </div>

                              <div className="mt-1 font-mono text-xs text-slate-600">
                                {target.id}
                              </div>

                            </td>

                            <td className="px-6 py-5">

                              <span className="rounded-md bg-slate-800 px-2.5 py-1 text-xs text-slate-300">
                                {target.target_type}
                              </span>

                            </td>

                            <td className="px-6 py-5">

                              <Link
                                href={`/projects/${target.project_id}`}
                                className="text-slate-300 hover:text-white"
                              >
                                {getProjectName(
                                  target.project_id
                                )}
                              </Link>

                            </td>

                            <td className="px-6 py-5">

                              {target.is_active ? (

                                <span className="inline-flex rounded-full bg-green-950 px-3 py-1 text-xs font-medium text-green-400">
                                  Active
                                </span>

                              ) : (

                                <span className="inline-flex rounded-full bg-slate-800 px-3 py-1 text-xs font-medium text-slate-400">
                                  Inactive
                                </span>

                              )}

                            </td>

                            <td className="px-6 py-5">

                              <button
                                type="button"
                                onClick={() =>
                                  deleteTarget(
                                    target.id
                                  )
                                }
                                disabled={
                                  deletingId ===
                                  target.id
                                }
                                className="text-sm text-red-400 transition hover:text-red-300 disabled:opacity-50"
                              >
                                {deletingId ===
                                target.id
                                  ? "Deleting..."
                                  : "Delete"}
                              </button>

                            </td>

                          </tr>

                        )
                      )}

                    </tbody>

                  </table>

                </div>

              </div>

            </section>

          )}

        </div>

      </main>
    </AppShell>
  );
}