"use client";

import { useTour } from "./TourProvider";

export default function WelcomeModal() {
  const { showWelcome, start, skip, setShowWelcome } = useTour();
  if (!showWelcome) return null;
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Welcome">
      <div className="absolute inset-0 bg-black/50" onClick={() => setShowWelcome(false)} />
      <div className="relative max-w-md w-full rounded-md border border-border bg-surface p-6 shadow-lg">
        <h2 className="text-xl font-semibold text-text">Welcome to VAPT Platform</h2>
        <p className="mt-2 text-sm text-muted">Let&apos;s take a quick tour so you know where everything is.</p>
        <div className="mt-6 flex gap-3">
          <button type="button" onClick={start} className="flex-1 rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">
            Start Tour
          </button>
          <button type="button" onClick={skip} className="flex-1 rounded-sm border border-border px-4 py-2 text-sm">
            Skip for Now
          </button>
        </div>
      </div>
    </div>
  );
}
