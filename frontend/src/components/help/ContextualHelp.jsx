"use client";

import { useState } from "react";

export default function ContextualHelp({ title, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-4">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="text-sm text-primary underline"
        aria-expanded={open}
        aria-label={`Help: ${title}`}
      >
        What is {title}?
      </button>
      {open ? <div className="mt-2 rounded-md border border-border bg-surface p-3 text-sm text-muted">{children}</div> : null}
    </div>
  );
}
