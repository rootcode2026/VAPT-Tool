"use client";

import Link from "next/link";

export default function ProjectTabs({ projectId, active }) {
  const items = [
    { id: "overview", href: `/projects/${projectId}`, label: "Overview" },
    {
      id: "targets",
      href: `/projects/${projectId}?tab=targets`,
      label: "Targets",
    },
    { id: "scans", href: `/scans?project_id=${projectId}`, label: "Scans" },
    { id: "findings", href: "/findings", label: "Findings" },
    { id: "assets", href: "/assets", label: "Assets" },
  ];

  return (
    <nav
      aria-label="Project sections"
      className="mb-6 flex gap-1 overflow-x-auto border-b border-border"
    >
      {items.map((item) => {
        const isActive = item.id === active;
        return (
          <Link
            key={item.id}
            href={item.href}
            aria-current={isActive ? "page" : undefined}
            className={[
              "whitespace-nowrap px-3 py-2 text-sm transition-colors",
              isActive
                ? "border-b-2 border-primary font-medium text-text"
                : "text-muted hover:text-text",
            ].join(" ")}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
