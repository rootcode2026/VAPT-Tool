"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navigation = [
  {
    name: "Dashboard",
    href: "/",
    icon: "▦",
  },
  {
    name: "Projects",
    href: "/projects",
    icon: "□",
  },
  {
    name: "Targets",
    href: "/targets",
    icon: "◎",
  },
  {
    name: "Scans",
    href: "/scans",
    icon: "⌁",
  },
  {
    name: "Findings",
    href: "/findings",
    icon: "!",
  },
  {
    name: "Scanners",
    href: "/scanners",
    icon: "◇",
  },
];

export default function AppShell({ children }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-slate-950">

      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 border-r border-slate-800 bg-slate-950 lg:block">

        <div className="flex h-full flex-col">

          {/* Logo */}
          <div className="flex h-16 items-center border-b border-slate-800 px-6">
            <Link
              href="/"
              className="flex items-center gap-3"
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white text-sm font-bold text-slate-950">
                V
              </div>

              <div>
                <div className="font-semibold">
                  VAPT Platform
                </div>

                <div className="text-xs text-slate-500">
                  Security Operations
                </div>
              </div>
            </Link>
          </div>

          {/* Navigation */}
          <nav className="flex-1 space-y-1 px-3 py-6">

            <div className="mb-3 px-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Workspace
            </div>

            {navigation.map((item) => {
              const isActive =
                item.href === "/"
                  ? pathname === "/"
                  : pathname.startsWith(item.href);

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={[
                    "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition",
                    isActive
                      ? "bg-slate-800 text-white"
                      : "text-slate-400 hover:bg-slate-900 hover:text-white",
                  ].join(" ")}
                >
                  <span className="flex h-5 w-5 items-center justify-center text-sm">
                    {item.icon}
                  </span>

                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>

          {/* Bottom */}
          <div className="border-t border-slate-800 p-4">

            <div className="rounded-lg bg-slate-900 p-3">
              <div className="text-xs text-slate-500">
                System
              </div>

              <div className="mt-1 flex items-center gap-2 text-sm">
                <span className="h-2 w-2 rounded-full bg-green-400" />

                <span className="text-slate-300">
                  All systems operational
                </span>
              </div>
            </div>

          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="lg:pl-64">

        {/* Top bar */}
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/95 px-6 backdrop-blur">

          <div>
            <p className="text-sm text-slate-400">
              Security Operations
            </p>
          </div>

          <div className="flex items-center gap-3">

            <div className="hidden text-right sm:block">
              <div className="text-sm font-medium">
                Security Admin
              </div>

              <div className="text-xs text-slate-500">
                Administrator
              </div>
            </div>

            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-slate-800 text-sm font-semibold">
              SA
            </div>

          </div>
        </header>

        {/* Page */}
        <main>
          {children}
        </main>

      </div>
    </div>
  );
}