"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

import AppShell from "@/components/layout/AppShell";

const API_URL = "http://localhost:8000";

export default function ProjectDetailsPage() {
  const params = useParams();

  const projectId = params.project_id;

  const [project, setProject] = useState(null);
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!projectId) {
      return;
    }

    async function loadProject() {
      try {
        setLoading(true);
        setError("");

        /*
         * -----------------------------------------------------
         * Load project
         * -----------------------------------------------------
         */

        const projectResponse = await fetch(
          `${API_URL}/api/v1/projects/${projectId}`
        );

        if (!projectResponse.ok) {
          throw new Error(
            "Failed to load project"
          );
        }

        const projectData =
          await projectResponse.json();

        /*
         * -----------------------------------------------------
         * Load targets
         * -----------------------------------------------------
         */

        const targetsResponse = await fetch(
          `${API_URL}/api/v1/targets`
        );

        if (!targetsResponse.ok) {
          throw new Error(
            "Failed to load targets"
          );
        }

        const targetsData =
          await targetsResponse.json();

        /*
         * Only targets belonging to this project
         */

        const projectTargets =
          targetsData.filter(
            (target) =>
              target.project_id === projectId
          );

        /*
         * -----------------------------------------------------
         * Load scans
         * -----------------------------------------------------
         */

        const scansResponse = await fetch(
          `${API_URL}/api/v1/scans`
        );

        if (!scansResponse.ok) {
          throw new Error(
            "Failed to load scans"
          );
        }

        const scansData =
          await scansResponse.json();

        /*
         * Only scans belonging to this project's targets
         */

        const targetIds = new Set(
          projectTargets.map(
            (target) => target.id
          )
        );

        const projectScans =
          scansData.filter(
            (scan) =>
              targetIds.has(scan.target_id)
          );

        setProject(projectData);
        setTargets(projectTargets);
        setScans(projectScans);
      } catch (err) {
        console.error(err);

        setError(
          err.message ||
            "Failed to load project"
        );
      } finally {
        setLoading(false);
      }
    }

    loadProject();
  }, [projectId]);

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
              Loading project...
            </div>

            <p className="mt-2 text-sm text-slate-400">
              Fetching project information
            </p>
          </div>
        </main>
      </AppShell>
    );
  }

  /*
   * ---------------------------------------------------------
   * Error
   * ---------------------------------------------------------
   */

  if (error) {
    return (
      <AppShell>
        <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center p-6">
          <div className="w-full max-w-lg rounded-xl border border-red-900 bg-red-950/40 p-6">
            <h1 className="text-xl font-semibold text-red-400">
              Project Error
            </h1>

            <p className="mt-2 text-sm text-slate-300">
              {error}
            </p>

            <Link
              href="/projects"
              className="mt-6 inline-block rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950"
            >
              ← Back to Projects
            </Link>
          </div>
        </main>
      </AppShell>
    );
  }

  if (!project) {
    return null;
  }

  /*
   * ---------------------------------------------------------
   * Project statistics
   * ---------------------------------------------------------
   */

  const totalTargets = targets.length;

  const totalScans = scans.length;

  const completedScans = scans.filter(
    (scan) =>
      scan.status?.toLowerCase() ===
      "completed"
  ).length;

  const runningScans = scans.filter(
    (scan) =>
      scan.status?.toLowerCase() ===
        "running" ||
      scan.status?.toLowerCase() ===
        "queued"
  ).length;

  /*
   * ---------------------------------------------------------
   * Main page
   * ---------------------------------------------------------
   */

  return (
    <AppShell>
      <main className="min-h-screen bg-slate-950 text-white">

        {/* -------------------------------------------------
            Header
        -------------------------------------------------- */}

        <header className="border-b border-slate-800">
          <div className="mx-auto max-w-7xl px-6 py-6">

            <Link
              href="/projects"
              className="text-sm text-slate-400 transition hover:text-white"
            >
              ← Back to Projects
            </Link>

            <div className="mt-5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">

              <div className="flex items-start gap-4">

                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-slate-800 text-lg font-bold">
                  {project.name
                    ?.charAt(0)
                    ?.toUpperCase() || "P"}
                </div>

                <div>

                  <h1 className="text-2xl font-bold">
                    {project.name}
                  </h1>

                  <p className="mt-1 text-sm text-slate-400">
                    {project.description ||
                      "No description provided."}
                  </p>

                </div>

              </div>

              <div className="rounded-lg border border-green-900 bg-green-950/30 px-4 py-2 text-sm text-green-400">
                Active Project
              </div>

            </div>

          </div>
        </header>

        {/* -------------------------------------------------
            Content
        -------------------------------------------------- */}

        <div className="mx-auto max-w-7xl px-6 py-8">

          {/* -------------------------------------------------
              Overview
          -------------------------------------------------- */}

          <section>

            <h2 className="mb-4 text-lg font-semibold">
              Project Overview
            </h2>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">

              <OverviewCard
                title="Targets"
                value={totalTargets}
              />

              <OverviewCard
                title="Total Scans"
                value={totalScans}
              />

              <OverviewCard
                title="Completed"
                value={completedScans}
              />

              <OverviewCard
                title="Running"
                value={runningScans}
              />

            </div>

          </section>

          {/* -------------------------------------------------
              Targets
          -------------------------------------------------- */}

          <section className="mt-8">

            <div className="mb-4 flex items-center justify-between">

              <div>
                <h2 className="text-lg font-semibold">
                  Targets
                </h2>

                <p className="mt-1 text-sm text-slate-400">
                  Targets associated with this project.
                </p>
              </div>

              <Link
                href={`/targets?project_id=${projectId}`}
                className="rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-slate-200"
              >
                Manage Targets
              </Link>

            </div>

            {targets.length === 0 ? (

              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-10 text-center">

                <h3 className="font-semibold">
                  No targets
                </h3>

                <p className="mt-2 text-sm text-slate-400">
                  This project does not have any
                  targets yet.
                </p>

              </div>

            ) : (

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
                          Status
                        </th>

                        <th className="px-6 py-4">
                          Target ID
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {targets.map(
                        (target) => (
                          <tr
                            key={target.id}
                            className="border-b border-slate-800 last:border-0"
                          >

                            <td className="px-6 py-4">

                              <div className="font-medium">
                                {target.value}
                              </div>

                            </td>

                            <td className="px-6 py-4 text-slate-400">
                              {target.target_type}
                            </td>

                            <td className="px-6 py-4">

                              <TargetStatus
                                active={
                                  target.is_active
                                }
                              />

                            </td>

                            <td className="px-6 py-4 font-mono text-xs text-slate-500">
                              {target.id}
                            </td>

                          </tr>
                        )
                      )}

                    </tbody>

                  </table>

                </div>

              </div>

            )}

          </section>

          {/* -------------------------------------------------
              Recent Scans
          -------------------------------------------------- */}

          <section className="mt-8">

            <div className="mb-4">

              <h2 className="text-lg font-semibold">
                Recent Scans
              </h2>

              <p className="mt-1 text-sm text-slate-400">
                Security scans performed against
                this project's targets.
              </p>

            </div>

            {scans.length === 0 ? (

              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-10 text-center">

                <h3 className="font-semibold">
                  No scans
                </h3>

                <p className="mt-2 text-sm text-slate-400">
                  No scans have been performed
                  against this project's targets.
                </p>

              </div>

            ) : (

              <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">

                <div className="overflow-x-auto">

                  <table className="w-full text-left text-sm">

                    <thead className="border-b border-slate-800 bg-slate-950">

                      <tr>

                        <th className="px-6 py-4">
                          Scan ID
                        </th>

                        <th className="px-6 py-4">
                          Target
                        </th>

                        <th className="px-6 py-4">
                          Profile
                        </th>

                        <th className="px-6 py-4">
                          Status
                        </th>

                        <th className="px-6 py-4">
                          Risk
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {scans.map(
                        (scan) => {

                          const target =
                            targets.find(
                              (item) =>
                                item.id ===
                                scan.target_id
                            );

                          return (
                            <tr
                              key={scan.id}
                              className="border-b border-slate-800 last:border-0"
                            >

                              <td className="px-6 py-4 font-mono text-xs text-slate-500">
                                {scan.id}
                              </td>

                              <td className="px-6 py-4">
                                {target?.value ||
                                  scan.target_id}
                              </td>

                              <td className="px-6 py-4">

                                <span className="rounded-md bg-slate-800 px-2.5 py-1 text-xs text-slate-300">
                                  {scan.profile}
                                </span>

                              </td>

                              <td className="px-6 py-4">

                                <ScanStatus
                                  status={
                                    scan.status
                                  }
                                />

                              </td>

                              <td className="px-6 py-4">

                                {scan.risk_score ??
                                  "—"}

                              </td>

                            </tr>
                          );
                        }
                      )}

                    </tbody>

                  </table>

                </div>

              </div>

            )}

          </section>

          {/* -------------------------------------------------
              Project Information
          -------------------------------------------------- */}

          <section className="mt-8">

            <h2 className="mb-4 text-lg font-semibold">
              Project Information
            </h2>

            <div className="rounded-xl border border-slate-800 bg-slate-900">

              <div className="grid gap-6 p-6 md:grid-cols-2">

                <InfoItem
                  label="Project ID"
                  value={project.id}
                />

                <InfoItem
                  label="Organization ID"
                  value={
                    project.organization_id
                  }
                />

                <InfoItem
                  label="Project Name"
                  value={project.name}
                />

                <InfoItem
                  label="Description"
                  value={
                    project.description ||
                    "No description provided."
                  }
                />

              </div>

            </div>

          </section>

        </div>

      </main>
    </AppShell>
  );
}


/*
 * ---------------------------------------------------------
 * Overview Card
 * ---------------------------------------------------------
 */

function OverviewCard({
  title,
  value,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

      <p className="text-sm text-slate-400">
        {title}
      </p>

      <p className="mt-3 text-3xl font-bold">
        {value}
      </p>

    </div>
  );
}


/*
 * ---------------------------------------------------------
 * Target Status
 * ---------------------------------------------------------
 */

function TargetStatus({
  active,
}) {
  if (active) {
    return (
      <span className="inline-flex rounded-full bg-green-950 px-3 py-1 text-xs font-medium text-green-400">
        Active
      </span>
    );
  }

  return (
    <span className="inline-flex rounded-full bg-slate-800 px-3 py-1 text-xs font-medium text-slate-400">
      Inactive
    </span>
  );
}


/*
 * ---------------------------------------------------------
 * Scan Status
 * ---------------------------------------------------------
 */

function ScanStatus({
  status,
}) {
  const normalized =
    status?.toLowerCase();

  let classes =
    "bg-slate-800 text-slate-300";

  if (normalized === "completed") {
    classes =
      "bg-green-950 text-green-400";
  }

  if (normalized === "running") {
    classes =
      "bg-blue-950 text-blue-400";
  }

  if (normalized === "queued") {
    classes =
      "bg-yellow-950 text-yellow-400";
  }

  if (normalized === "failed") {
    classes =
      "bg-red-950 text-red-400";
  }

  return (
    <span
      className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${classes}`}
    >
      {status}
    </span>
  );
}


/*
 * ---------------------------------------------------------
 * Information Item
 * ---------------------------------------------------------
 */

function InfoItem({
  label,
  value,
}) {
  return (
    <div>

      <p className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </p>

      <p className="mt-2 break-all text-sm text-slate-300">
        {value}
      </p>

    </div>
  );
}