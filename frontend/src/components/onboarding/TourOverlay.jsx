"use client";

/* eslint-disable */
import { useEffect, useState } from "react";
import { useTour } from "./TourProvider";

export default function TourOverlay() {
  const { active, currentStep, stepIndex, steps, next, back, close, skip } = useTour();
  const [rect, setRect] = useState(null);

  useEffect(() => {
    if (!active || !currentStep?.target) {
      setRect(null);
      return;
    }
    const el = document.querySelector(`[data-tour="${currentStep.target}"]`);
    if (!el) {
      setRect(null);
      return;
    }
    const r = el.getBoundingClientRect();
    setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
  }, [active, currentStep]);

  if (!active || !currentStep) return null;

  const isWelcome = currentStep.id === "welcome";

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Product tour">
      <div className="absolute inset-0 bg-black/50" onClick={close} />
      {/* Highlight */}
      {rect ? (
        <div
          className="absolute rounded-md border-2 border-primary bg-transparent pointer-events-none"
          style={{ top: rect.top - 4, left: rect.left - 4, width: rect.width + 8, height: rect.height + 8 }}
        />
      ) : null}
      <div className="relative max-w-md w-full rounded-md border border-border bg-surface p-6 shadow-lg">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-text">{currentStep.title}</h2>
          <span className="text-xs text-muted">
            {stepIndex + 1} / {steps.length}
          </span>
        </div>
        <p className="mt-2 text-sm text-muted">{currentStep.content}</p>
        <div className="mt-4 h-1 w-full rounded bg-border">
          <div className="h-1 rounded bg-primary transition-all" style={{ width: `${((stepIndex + 1) / steps.length) * 100}%` }} />
        </div>
        <div className="mt-6 flex items-center justify-between gap-2">
          <button type="button" onClick={skip} className="text-sm text-muted underline">
            Skip tour
          </button>
          <div className="flex gap-2">
            {stepIndex > 0 ? (
              <button type="button" onClick={back} className="rounded-sm border border-border px-3 py-1.5 text-sm">
                Back
              </button>
            ) : null}
            <button
              type="button"
              onClick={next}
              className="rounded-sm bg-primary px-4 py-1.5 text-sm font-semibold text-primary-foreground"
              autoFocus
            >
              {stepIndex === steps.length - 1 ? "Finish" : "Next"}
            </button>
          </div>
        </div>
        <button type="button" onClick={close} aria-label="Close tour" className="absolute right-2 top-2 text-muted">
          ×
        </button>
      </div>
    </div>
  );
}
