"use client";

import { useState } from "react";
import { createProject } from "@/lib/api/projects";
import { useAuth } from "@/lib/auth/AuthProvider";
import { ApiError } from "@/lib/api/client";

export default function ProjectCreateForm({ onCreated, onCancel }) {
  const { user } = useAuth();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) {
      setError("Enter a project name.");
      return;
    }
    if (!user?.organization_id) {
      setError("Unable to create a project without an organization.");
      return;
    }

    setSubmitting(true);
    setError("");
    try {
      const project = await createProject({
        organization_id: user.organization_id,
        name: trimmedName,
        description: description.trim() || null,
      });
      if (!project?.id) {
        setError("Unable to create the project.");
        return;
      }
      await onCreated(project);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Unable to create the project."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="rounded-md border border-border bg-surface p-4 sm:p-5"
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label htmlFor="project-name" className="mb-1 block text-sm text-muted">
            Name
          </label>
          <input
            id="project-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            maxLength={255}
            className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text"
          />
        </div>
        <div className="sm:col-span-2">
          <label
            htmlFor="project-description"
            className="mb-1 block text-sm text-muted"
          >
            Description
          </label>
          <textarea
            id="project-description"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            maxLength={1000}
            rows={3}
            className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text"
          />
        </div>
      </div>
      {error ? (
        <p className="mt-3 text-sm text-danger" role="alert">
          {error}
        </p>
      ) : null}
      <div className="mt-4 flex justify-end gap-2">
        {onCancel ? (
          <button
            type="button"
            onClick={onCancel}
            className="rounded-sm border border-border px-3 py-1.5 text-sm text-text hover:bg-surface-hover"
          >
            Cancel
          </button>
        ) : null}
        <button
          type="submit"
          disabled={submitting}
          className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground disabled:opacity-60"
        >
          {submitting ? "Creating..." : "Create Project"}
        </button>
      </div>
    </form>
  );
}
