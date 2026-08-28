"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

const API_URL = "http://localhost:8000";

const PROFILES = [
  {
    value: "quick",
    name: "Quick Scan",
    description: "Fast security assessment",
  },
  {
    value: "web",
    name: "Web Scan",
    description: "Web vulnerability assessment",
  },
  {
    value: "full",
    name: "Full Scan",
    description: "Comprehensive security assessment",
  },
];

export default function ScansPage() {
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);

  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedProfile, setSelectedProfile] =
    useState("quick");

  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  /*
   * ---------------------------------------------------------
   * Load targets
   * ---------------------------------------------------------
   */

  async function loadTargets() {
    const response = await fetch(
      `${API_URL}/api/v1/targets`
    );

    if (!response.ok) {
      throw new Error("Failed to load targets");
    }

    const data = await response.json();

    setTargets(data);

    if (!selectedTarget && data.length > 0) {
      setSelectedTarget(data[0].id);
    }
  }

  /*
   * ---------------------------------------------------------
   * Load scans
   * ---------------------------------------------------------
   */

  async function loadScans() {
    const response = await fetch(
      `${API_URL}/api/v1/scans`
    );

    if (!response.ok) {
      throw new Error("Failed to load scans");
    }

    const data = await response.json();

    setScans(data);
  }

  /*
   * ---------------------------------------------------------
   * Load page
   * ---------------------------------------------------------
   */

  async function loadData() {
    try {
      setLoading(true);
      setError("");

      await Promise.all([
        loadTargets(),
        loadScans(),
      ]);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to load scan information"
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
   * Auto refresh scans
   *
   * This allows queued/running scans to update
   * automatically without manually refreshing.
   * ---------------------------------------------------------
   */

  useEffect(() => {
    const hasActiveScans = scans.some(
      (scan) =>
        scan.status === "queued" ||
        scan.status === "running"
    );

    if (!hasActiveScans) {
      return;
    }

    const interval = setInterval(() => {
      loadScans().catch((err) => {
        console.error(
          "Failed to refresh scans:",
          err
        );
      });
    }, 3000);

    return () => clearInterval(interval);
  }, [scans]);

  /*
   * ---------------------------------------------------------
   * Start scan
   * ---------------------------------------------------------
   */

  async function startScan(event) {
    event.preventDefault();

    if (!selectedTarget) {
      setError("Please select a target.");
      return;
    }

    if (!selectedProfile) {
      setError("Please select a scan profile.");
      return;
    }

    try {
      setStarting(true);
      setError("");

      const response = await fetch(
        `${API_URL}/api/v1/scans`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            target_id: selectedTarget,
            profile: selectedProfile,
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
            "Failed to start scan"
        );
      }

      const newScan =
        await response.json();

      setScans((current) => [
        newScan,
        ...current,
      ]);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to start scan"
      );
    } finally {
      setStarting(false);
    }
  }

  /*
   * ---------------------------------------------------------
   * Helpers
   * ---------------------------------------------------------
   */

  function getTarget(targetId) {
    return targets.find(
      (target) => target.id === targetId
    );
  }

  function getStatusClasses(status) {
    switch (status) {
      case "completed":
        return "bg-green-950 text-green-400";

      case "running":
        return "bg-blue-950 text-blue-400";

      case "queued":
        return "bg-yellow-950 text-yellow-400";

      case "failed":
        return "bg-red-950 text-red-400";

      default:
        return "bg-slate-800 text-slate-400";
    }
  }

  function getProfileName(profile) {
    const item = PROFILES.find(
      (item) => item.value === profile
    );

    return item?.name || profile;
  }

  /*
   * ---------------------------------------------------------
   * Statistics
   * ---------------------------------------------------------
   */

  const totalScans = scans.length;

  const runningScans = scans.filter(
    (scan) =>
      scan.status === "running"
  ).length;

  const queuedScans = scans.filter(
    (scan) =>
      scan.status === "queued"
  ).length;

  const completedScans = scans.filter(
    (scan) =>
      scan.status === "completed"
  ).length;

  /*
   * ---------------------------------------------------------
   * Loading
   * ---------------------------------------------------------
   */

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
        <div className="text-center">
          <div className="text-xl font-semibold">
            Loading scans...
          </div>

          <p className="mt-2 text-sm text-slate-400">
            Fetching scan information
          </p>
        </div>
      </main>
    );
  }

  /*
   * ---------------------------------------------------------
   * Main UI
   * ---------------------------------------------------------
   */

  return (
    <main className="min-h-screen bg-slate-950 text-white">

      {/* Header */}
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-6">

          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">

            <div>
              <h1 className="text-2xl font-bold">
                Security Scans
              </h1>

              <p className="mt-1 text-sm text-slate-400">
                Run and monitor security assessments.
              </p>
            </div>

            <Link
              href="/dashboard"
              className="text-sm text-slate-400 transition hover:text-white"
            >
              ← Dashboard
            </Link>

          </div>

        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">

        {/* Error */}
        {error && (
          <div className="mb-6 rounded-lg border border-red-900 bg-red-950/40 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {/* ---------------------------------------------------
            Statistics
        ---------------------------------------------------- */}

        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <p className="text-sm text-slate-400">
              Total Scans
            </p>

            <p className="mt-2 text-3xl font-bold">
              {totalScans}
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <p className="text-sm text-slate-400">
              Running
            </p>

            <p className="mt-2 text-3xl font-bold text-blue-400">
              {runningScans}
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <p className="text-sm text-slate-400">
              Queued
            </p>

            <p className="mt-2 text-3xl font-bold text-yellow-400">
              {queuedScans}
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
            <p className="text-sm text-slate-400">
              Completed
            </p>

            <p className="mt-2 text-3xl font-bold text-green-400">
              {completedScans}
            </p>
          </div>

        </section>

        {/* ---------------------------------------------------
            Start Scan
        ---------------------------------------------------- */}

        <section className="mb-8 rounded-xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-6">

            <h2 className="text-lg font-semibold">
              Start New Scan
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Select a target and scan profile.
            </p>

          </div>

          <form
            onSubmit={startScan}
            className="space-y-6"
          >

            {/* Target */}
            <div>

              <label
                htmlFor="target"
                className="mb-2 block text-sm font-medium text-slate-300"
              >
                Target
              </label>

              {targets.length === 0 ? (

                <div className="rounded-lg border border-yellow-900 bg-yellow-950/30 p-4 text-sm text-yellow-400">
                  No active targets available.
                  Create a target before starting
                  a scan.
                </div>

              ) : (

                <select
                  id="target"
                  value={selectedTarget}
                  onChange={(event) =>
                    setSelectedTarget(
                      event.target.value
                    )
                  }
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none focus:border-slate-500"
                >

                  {targets
                    .filter(
                      (target) =>
                        target.is_active
                    )
                    .map((target) => (

                      <option
                        key={target.id}
                        value={target.id}
                      >
                        {target.value} —{" "}
                        {target.target_type}
                      </option>

                    ))}

                </select>

              )}

            </div>

            {/* Profile */}
            <div>

              <label className="mb-3 block text-sm font-medium text-slate-300">
                Scan Profile
              </label>

              <div className="grid gap-4 md:grid-cols-3">

                {PROFILES.map(
                  (profile) => (

                    <button
                      key={profile.value}
                      type="button"
                      onClick={() =>
                        setSelectedProfile(
                          profile.value
                        )
                      }
                      className={`rounded-xl border p-5 text-left transition ${
                        selectedProfile ===
                        profile.value
                          ? "border-white bg-slate-800"
                          : "border-slate-700 bg-slate-950 hover:border-slate-500"
                      }`}
                    >

                      <div className="font-semibold">
                        {profile.name}
                      </div>

                      <p className="mt-2 text-sm text-slate-400">
                        {profile.description}
                      </p>

                    </button>

                  )
                )}

              </div>

            </div>

            {/* Start */}
            <div className="flex justify-end">

              <button
                type="submit"
                disabled={
                  starting ||
                  targets.filter(
                    (target) =>
                      target.is_active
                  ).length === 0
                }
                className="rounded-lg bg-white px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {starting
                  ? "Starting Scan..."
                  : "Start Scan"}
              </button>

            </div>

          </form>

        </section>

        {/* ---------------------------------------------------
            Scan List
        ---------------------------------------------------- */}

        <section>

          <div className="mb-4">

            <h2 className="text-lg font-semibold">
              Scan History
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              View previous and active security
              assessments.
            </p>

          </div>

          {scans.length === 0 ? (

            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-12 text-center">

              <h3 className="text-lg font-semibold">
                No scans yet
              </h3>

              <p className="mt-2 text-sm text-slate-400">
                Start your first security scan
                above.
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
                        Profile
                      </th>

                      <th className="px-6 py-4">
                        Status
                      </th>

                      <th className="px-6 py-4">
                        Risk
                      </th>

                      <th className="px-6 py-4">
                        Actions
                      </th>

                    </tr>

                  </thead>

                  <tbody>

                    {scans.map(
                      (scan) => {

                        const target =
                          getTarget(
                            scan.target_id
                          );

                        return (

                          <tr
                            key={scan.id}
                            className="border-b border-slate-800 last:border-0"
                          >

                            {/* Target */}
                            <td className="px-6 py-5">

                              <div className="font-medium">
                                {target?.value ||
                                  "Unknown target"}
                              </div>

                              <div className="mt-1 text-xs text-slate-500">
                                {target?.target_type ||
                                  "unknown"}
                              </div>

                            </td>

                            {/* Profile */}
                            <td className="px-6 py-5">

                              <span className="rounded-md bg-slate-800 px-2.5 py-1 text-xs text-slate-300">
                                {getProfileName(
                                  scan.profile
                                )}
                              </span>

                            </td>

                            {/* Status */}
                            <td className="px-6 py-5">

                              <span
                                className={`inline-flex rounded-full px-3 py-1 text-xs font-medium capitalize ${getStatusClasses(
                                  scan.status
                                )}`}
                              >
                                {scan.status}
                              </span>

                            </td>

                            {/* Risk */}
                            <td className="px-6 py-5">

                              {scan.risk_score !==
                              null &&
                              scan.risk_score !==
                              undefined ? (

                                <div>

                                  <div className="font-semibold">
                                    {
                                      scan.risk_score
                                    }
                                  </div>

                                  <div className="text-xs text-slate-500">
                                    Grade{" "}
                                    {
                                      scan.risk_grade
                                    }
                                  </div>

                                </div>

                              ) : (

                                <span className="text-slate-600">
                                  —
                                </span>

                              )}

                            </td>

                            {/* Actions */}
                            <td className="px-6 py-5">

                              <Link
                                href={`/scans/${scan.id}`}
                                className="text-sm text-slate-300 hover:text-white"
                              >
                                View Details →
                              </Link>

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

      </div>

    </main>
  );
}