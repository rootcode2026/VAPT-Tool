"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import Sidebar from "@/components/layout/Sidebar";
import TopBar from "@/components/layout/TopBar";
import { IconClose } from "@/components/icons";

export default function AppShell({ children }) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (!mobileOpen) return undefined;
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        setMobileOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [mobileOpen]);

  return (
    <div className="min-h-screen bg-canvas text-text">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-60 border-r border-border bg-canvas lg:block">
        <Sidebar pathname={pathname} />
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-canvas/70"
            aria-label="Close navigation"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="relative h-full w-64 max-w-[85vw] border-r border-border bg-canvas transition-transform">
            <div className="absolute right-2 top-2 z-10">
              <button
                type="button"
                className="inline-flex h-8 w-8 items-center justify-center rounded-sm border border-border"
                aria-label="Close navigation"
                onClick={() => setMobileOpen(false)}
              >
                <IconClose className="h-4 w-4" />
              </button>
            </div>
            <Sidebar pathname={pathname} onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      ) : null}

      <div className="min-w-0 lg:pl-60">
        <TopBar pathname={pathname} onMenuClick={() => setMobileOpen(true)} />
        <main className="min-w-0 overflow-x-hidden px-3 py-5 sm:px-5">{children}</main>
      </div>
    </div>
  );
}
