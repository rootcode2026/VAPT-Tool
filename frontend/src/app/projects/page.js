"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import AppShell from "@/components/layout/AppShell";

const API_URL = "http://localhost:8000";

// Temporary organization ID.
// We will replace this with authenticated organization
// information when authentication is implemented.
const ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001";

export default function ProjectsPage() {
  const [projects, setProjects] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [showCreateForm, setShowCreateForm] = useState(false);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const [creating, setCreating] = useState(false);
  const [deletingId, setDeletingId] = useState(null);

  async function loadProjects() {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/projects`
      );

      if (!response.ok) {
        throw new Error("Failed to load projects");
      }

      const data = await response.json();

      setProjects(data);
    } catch (err) {
      console.error(err);

      setError(
        err.message || "Failed to load projects"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadProjects();
  }, []);

  async function createProject(event) {
    event.preventDefault();

    if (!name.trim()) {
      return;
    }

    try {
      setCreating(true);
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/projects`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            organization_id: ORGANIZATION_ID,
            name: name.trim(),
            description: description.trim() || null,
          }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(
          () => null
        );

        throw new Error(
          errorData?.detail ||
            "Failed to create project"
        );
      }

      const project = await response.json();

      setProjects((current) => [
        project,
        ...current,
      ]);

      setName("");
      setDescription("");
      setShowCreateForm(false);
    } catch (err) {
      console.error(err);

      setError(
        err.message || "Failed to create project"
      );
    } finally {
      setCreating(false);
    }
  }

  async function deleteProject(projectId) {
    const confirmed = window.confirm(
      "Are you sure you want to delete this project?"
    );

    if (!confirmed) {
      return;
    }

    try {
      setDeletingId(projectId);
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/projects/${projectId}`,
        {
          method: "DELETE",
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(
          () => null
        );

        throw new Error(
          errorData?.detail ||
            "Failed to delete project"
        );
      }

      setProjects((current) =>
        current.filter(
          (project) => project.id !== projectId
        )
      );
    } catch (err) {
      console.error(err);

      setError(
        err.message || "Failed to delete project"
      );
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <AppShell>
      <main className="min-h-screen bg-slate-950 text-white">

        {/* Header */}
        <header className="border-b border-slate-800">
          <div className="mx-auto max-w-7xl px-6 py-6">

            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">

              <div>
                <h1 className="text-2xl font-bold">
                  Projects
                </h1>

                <p className="mt-1 text-sm text-slate-400">
                  Manage your security assessment projects.
                </p>
              </div>

              <button
                type="button"
                onClick={() =>
                  setShowCreateForm((value) => !value)
                }
                className="rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-slate-200"
              >
                {showCreateForm
                  ? "Cancel"
                  : "+ New Project"}
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

          {/* Create Project */}
          {showCreateForm && (
            <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-6">
                <h2 className="text-lg font-semibold">
                  Create Project
                </h2>

                <p className="mt-1 text-sm text-slate-400">
                  Create a project to organize your
                  security assessments.
                </p>
              </div>

              <form
                onSubmit={createProject}
                className="space-y-5"
              >

                <div>
                  <label
                    htmlFor="project-name"
                    className="mb-2 block text-sm font-medium text-slate-300"
                  >
                    Project Name
                  </label>

                  <input
                    id="project-name"
                    type="text"
                    value={name}
                    onChange={(event) =>
                      setName(event.target.value)
                    }
                    placeholder="My Security Project"
                    maxLength={255}
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-slate-500"
                  />
                </div>

                <div>
                  <label
                    htmlFor="project-description"
                    className="mb-2 block text-sm font-medium text-slate-300"
                  >
                    Description
                  </label>

                  <textarea
                    id="project-description"
                    value={description}
                    onChange={(event) =>
                      setDescription(
                        event.target.value
                      )
                    }
                    placeholder="Describe this project..."
                    maxLength={1000}
                    rows={4}
                    className="w-full resize-none rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-slate-500"
                  />
                </div>

                <div className="flex justify-end gap-3">

                  <button
                    type="button"
                    onClick={() => {
                      setShowCreateForm(false);
                      setName("");
                      setDescription("");
                    }}
                    className="rounded-lg border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800"
                  >
                    Cancel
                  </button>

                  <button
                    type="submit"
                    disabled={
                      creating || !name.trim()
                    }
                    className="rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {creating
                      ? "Creating..."
                      : "Create Project"}
                  </button>

                </div>

              </form>

            </section>
          )}

          {/* Loading */}
          {loading && (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-12 text-center">

              <div className="text-lg font-semibold">
                Loading projects...
              </div>

              <p className="mt-2 text-sm text-slate-400">
                Fetching project data
              </p>

            </div>
          )}

          {/* Empty */}
          {!loading && projects.length === 0 && (
            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-12 text-center">

              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-slate-800 text-xl">
                □
              </div>

              <h2 className="mt-4 text-lg font-semibold">
                No projects yet
              </h2>

              <p className="mx-auto mt-2 max-w-md text-sm text-slate-400">
                Create your first project to start
                organizing targets and security scans.
              </p>

              <button
                type="button"
                onClick={() =>
                  setShowCreateForm(true)
                }
                className="mt-6 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-slate-200"
              >
                Create Your First Project
              </button>

            </div>
          )}

          {/* Projects */}
          {!loading && projects.length > 0 && (
            <section>

              <div className="mb-4 flex items-center justify-between">

                <h2 className="text-lg font-semibold">
                  All Projects
                </h2>

                <span className="text-sm text-slate-400">
                  {projects.length}{" "}
                  {projects.length === 1
                    ? "project"
                    : "projects"}
                </span>

              </div>

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">

                {projects.map((project) => (

                  <div
                    key={project.id}
                    className="group rounded-xl border border-slate-800 bg-slate-900 p-6 transition hover:border-slate-700"
                  >

                    {/* Project header */}
                    <div className="flex items-start justify-between gap-4">

                      <div className="flex min-w-0 items-center gap-3">

                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-800 font-semibold">
                          {project.name
                            ?.charAt(0)
                            ?.toUpperCase() || "P"}
                        </div>

                        <div className="min-w-0">
                          <h3 className="truncate font-semibold">
                            {project.name}
                          </h3>

                          <p className="mt-1 font-mono text-xs text-slate-600">
                            {project.id}
                          </p>
                        </div>

                      </div>

                    </div>

                    {/* Description */}
                    <p className="mt-5 min-h-12 text-sm leading-6 text-slate-400">
                      {project.description ||
                        "No description provided."}
                    </p>

                    {/* Actions */}
                    <div className="mt-6 flex items-center justify-between border-t border-slate-800 pt-4">

                      <Link
                        href={`/projects/${project.id}`}
                        className="text-sm font-medium text-slate-300 transition hover:text-white"
                      >
                        View Project →
                      </Link>

                      <button
                        type="button"
                        onClick={() =>
                          deleteProject(project.id)
                        }
                        disabled={
                          deletingId === project.id
                        }
                        className="text-sm text-red-400 transition hover:text-red-300 disabled:opacity-50"
                      >
                        {deletingId === project.id
                          ? "Deleting..."
                          : "Delete"}
                      </button>

                    </div>

                  </div>

                ))}

              </div>

            </section>
          )}

        </div>

      </main>
    </AppShell>
  );
}