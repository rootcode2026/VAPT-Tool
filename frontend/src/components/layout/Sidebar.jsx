"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { ADMIN_NAV, isNavActive, PRIMARY_NAV, SECONDARY_NAV } from "@/lib/navigation";
import { useAuth } from "@/lib/auth/AuthProvider";

function NavLinks({ pathname, onNavigate }) {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const isOrgAdmin = (() => {
    // Fallback check: org_admin role is not in user.role directly, but we can infer via API; for now show Audit for all authenticated and gate via backend
    // Keep simple: show Audit for everyone, gate via 403
    return false;
  })();

  return (
    <>
      <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">
        Workspace
      </div>
      {PRIMARY_NAV.map((item) => {
        const Icon = item.icon;
        const active = isNavActive(pathname, item.href);
        const tourId = item.href.replace(/^\//, "").replace(/\//g, "-") || "dashboard";
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            aria-current={active ? "page" : undefined}
            data-tour={tourId}
            className={[
              "flex items-center gap-3 rounded-sm px-3 py-2 text-sm transition-colors",
              active
                ? "bg-surface-hover text-text"
                : "text-muted hover:bg-surface-hover hover:text-text",
            ].join(" ")}
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span>{item.name}</span>
          </Link>
        );
      })}

      {isSuperAdmin ? (
        <>
          <div className="my-4 border-t border-border" role="separator" />
          <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">
            Administration
          </div>
          {ADMIN_NAV.map((item) => {
            const Icon = item.icon;
            const active = isNavActive(pathname, item.href);
            const tourId = item.href.replace(/^\//, "").replace(/\//g, "-") || "admin";
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={onNavigate}
                aria-current={active ? "page" : undefined}
                data-tour={tourId}
                className={[
                  "flex items-center gap-3 rounded-sm px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-surface-hover text-text"
                    : "text-muted hover:bg-surface-hover hover:text-text",
                ].join(" ")}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </>
      ) : null}

      <div className="my-4 border-t border-border" role="separator" />

      {SECONDARY_NAV.map((item) => {
        const Icon = item.icon;
        const active = isNavActive(pathname, item.href);
        const tourId = item.href.replace(/^\//, "").replace(/\//g, "-") || "help";
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            aria-current={active ? "page" : undefined}
            data-tour={tourId}
            className={[
              "flex items-center gap-3 rounded-sm px-3 py-2 text-sm transition-colors",
              active
                ? "bg-surface-hover text-text"
                : "text-muted hover:bg-surface-hover hover:text-text",
            ].join(" ")}
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span>{item.name}</span>
          </Link>
        );
      })}
    </>
  );
}

export default function Sidebar({ pathname, onNavigate, className = "" }) {
  const router = useRouter();
  const { user, logout } = useAuth();
  const displayName = user?.email || "Signed in";
  const organization = user?.organization_name || "Organization";

  return (
    <div className={`flex h-full flex-col bg-canvas ${className}`}>
      <div className="flex h-14 items-center border-b border-border px-4">
        <Link href="/dashboard" onClick={onNavigate} className="flex min-w-0 items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-sm border border-border bg-surface text-xs font-semibold">
            V
          </div>
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-text">VAPT Platform</div>
            <div className="truncate text-xs text-muted">Security operations</div>
          </div>
        </Link>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-4" aria-label="Primary">
        <NavLinks pathname={pathname} onNavigate={onNavigate} />
      </nav>

      <div className="border-t border-border p-3">
        <div className="rounded-sm border border-border bg-surface p-3">
          <p className="truncate text-sm font-medium text-text" title={displayName}>
            {displayName}
          </p>
          <p className="truncate text-xs text-muted" title={organization}>
            {organization}
          </p>
          <button
            type="button"
            className="mt-3 w-full rounded-sm border border-border px-2 py-1.5 text-left text-xs text-muted transition-colors hover:bg-surface-hover hover:text-text"
            onClick={async () => {
              await logout();
              router.replace("/login");
            }}
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  );
}
