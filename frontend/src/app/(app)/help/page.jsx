"use client";

import { useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import { HELP_SECTIONS } from "@/lib/helpContent";
import HelpSearch from "@/components/help/HelpSearch";

export default function HelpPage() {
  const [selected, setSelected] = useState(HELP_SECTIONS[0].id);
  const current = HELP_SECTIONS.find((s) => s.id === selected) || HELP_SECTIONS[0];

  return (
    <div>
      <PageHeader title="Help Center" description="Searchable guides for the VAPT platform." />
      <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
        <aside className="rounded-md border border-border bg-surface p-4">
          <h2 className="text-sm font-semibold">Documentation</h2>
          <div className="mt-3">
            <HelpSearch onSelect={setSelected} />
          </div>
          <nav className="mt-4 space-y-0.5" aria-label="Help navigation">
            {HELP_SECTIONS.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => setSelected(s.id)}
                aria-current={selected === s.id ? "page" : undefined}
                className={`w-full text-left rounded-sm px-2 py-1.5 text-sm ${selected === s.id ? "bg-surface-hover text-text" : "text-muted hover:bg-surface-hover"}`}
              >
                {s.title}
              </button>
            ))}
          </nav>
        </aside>
        <article className="rounded-md border border-border bg-surface p-6" data-tour="help-content">
          <h1 className="text-xl font-semibold">{current.title}</h1>
          <div className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-muted">{current.content}</div>
          <div className="mt-6 flex gap-2">
            {(() => {
              const idx = HELP_SECTIONS.findIndex((s) => s.id === selected);
              const prev = HELP_SECTIONS[idx - 1];
              const next = HELP_SECTIONS[idx + 1];
              return (
                <>
                  {prev ? (
                    <button type="button" onClick={() => setSelected(prev.id)} className="rounded-sm border border-border px-3 py-1.5 text-sm">
                      ← {prev.title}
                    </button>
                  ) : null}
                  {next ? (
                    <button type="button" onClick={() => setSelected(next.id)} className="ml-auto rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground">
                      {next.title} →
                    </button>
                  ) : null}
                </>
              );
            })()}
          </div>
          <p className="mt-6 text-xs text-muted">
            Need a tour? <a href="/settings" className="underline">Restart Product Tour</a> in Settings → Help.
          </p>
        </article>
      </div>
    </div>
  );
}
