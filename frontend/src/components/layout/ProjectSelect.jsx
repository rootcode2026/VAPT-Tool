"use client";

import { useProjectContext } from "@/lib/project-context";

export default function ProjectSelect({ id = "project-context", className = "" }) {
  const { projects, selectedProjectId, setSelectedProjectId, status } =
    useProjectContext();

  if (status === "loading") {
    return (
      <select
        id={id}
        disabled
        aria-label="Project context"
        className={`rounded-sm border border-border bg-surface px-2 py-1.5 text-sm text-muted ${className}`}
      >
        <option>Loading projects...</option>
      </select>
    );
  }

  if (!projects.length) {
    return (
      <select
        id={id}
        disabled
        aria-label="Project context"
        className={`rounded-sm border border-border bg-surface px-2 py-1.5 text-sm text-muted ${className}`}
      >
        <option>No projects yet</option>
      </select>
    );
  }

  return (
    <select
      id={id}
      value={selectedProjectId}
      aria-label="Project context"
      onChange={(event) => setSelectedProjectId(event.target.value)}
      className={`max-w-[16rem] rounded-sm border border-border bg-surface px-2 py-1.5 text-sm text-text ${className}`}
    >
      {projects.map((project) => (
        <option key={project.id} value={project.id}>
          {project.name}
        </option>
      ))}
    </select>
  );
}
