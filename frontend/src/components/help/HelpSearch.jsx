"use client";

import { useState, useMemo } from "react";
import { HELP_SECTIONS } from "@/lib/helpContent";

export default function HelpSearch({ onSelect }) {
  const [q, setQ] = useState("");
  const results = useMemo(() => {
    const term = q.trim().toLowerCase();
    if (!term) return HELP_SECTIONS;
    return HELP_SECTIONS.filter((s) => s.title.toLowerCase().includes(term) || s.content.toLowerCase().includes(term));
  }, [q]);

  return (
    <div>
      <input
        type="search"
        placeholder="Search documentation..."
        value={q}
        onChange={(e) => setQ(e.target.value)}
        className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm"
        aria-label="Search documentation"
      />
      <ul className="mt-3 space-y-1">
        {results.map((s) => (
          <li key={s.id}>
            <button type="button" onClick={() => onSelect(s.id)} className="w-full text-left rounded-sm px-2 py-1.5 text-sm hover:bg-surface-hover">
              {s.title}
            </button>
          </li>
        ))}
        {results.length === 0 ? <li className="text-sm text-muted">No results for &quot;{q}&quot;</li> : null}
      </ul>
    </div>
  );
}
