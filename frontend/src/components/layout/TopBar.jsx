"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { IconBell, IconMenu } from "@/components/icons";
import ProjectSelect from "@/components/layout/ProjectSelect";
import { getPageTitle } from "@/lib/navigation";
import { useAuth } from "@/lib/auth/AuthProvider";

function initialsFromEmail(email) {
  if (!email) {
    return "U";
  }
  return email.trim().charAt(0).toUpperCase();
}

export default function TopBar({ pathname, onMenuClick }) {
  const [profileOpen, setProfileOpen] = useState(false);
  const router = useRouter();
  const { user, logout } = useAuth();
  const title = getPageTitle(pathname);
  const email = user?.email || "Signed in";
  const organization = user?.organization_name || "Organization";

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-canvas/95 px-3 backdrop-blur sm:px-5">
      <button
        type="button"
        className="inline-flex h-9 w-9 items-center justify-center rounded-sm border border-border text-text lg:hidden"
        onClick={onMenuClick}
        aria-label="Open navigation"
      >
        <IconMenu className="h-4 w-4" />
      </button>

      <div className="min-w-0 flex-1">
        <p className="truncate text-xs text-muted">Security operations</p>
        <p className="truncate text-sm font-semibold text-text">{title}</p>
      </div>

      <div className="hidden min-w-0 md:block">
        <ProjectSelect id="topbar-project-context" />
      </div>

      <button
        type="button"
        className="inline-flex h-9 w-9 items-center justify-center rounded-sm border border-border text-muted"
        aria-label="Notifications unavailable"
        title="Notifications will be available in a later module"
        disabled
      >
        <IconBell className="h-4 w-4" />
      </button>

      <div className="relative">
        <button
          type="button"
          className="inline-flex h-9 items-center gap-2 rounded-sm border border-border bg-surface px-2 text-sm"
          aria-expanded={profileOpen}
          aria-haspopup="menu"
          onClick={() => setProfileOpen((open) => !open)}
        >
          <span className="flex h-6 w-6 items-center justify-center rounded-sm bg-surface-hover text-xs font-semibold">
            {initialsFromEmail(user?.email)}
          </span>
          <span className="hidden max-w-[10rem] truncate sm:inline">{email}</span>
        </button>
        {profileOpen ? (
          <div
            role="menu"
            className="absolute right-0 mt-2 w-56 rounded-md border border-border bg-surface p-2 shadow-lg"
          >
            <p className="truncate px-2 py-1 text-xs text-muted">{email}</p>
            <p className="truncate px-2 pb-2 text-sm text-text">{organization}</p>
            <button
              type="button"
              role="menuitem"
              className="w-full rounded-sm px-2 py-1.5 text-left text-sm text-muted hover:bg-surface-hover hover:text-text"
              onClick={async () => {
                setProfileOpen(false);
                await logout();
                router.replace("/login");
              }}
            >
              Sign out
            </button>
          </div>
        ) : null}
      </div>
    </header>
  );
}
