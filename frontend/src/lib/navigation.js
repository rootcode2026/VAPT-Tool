import {
  IconAssets,
  IconAttackSurface,
  IconDashboard,
  IconFindings,
  IconProjects,
  IconScans,
  IconSettings,
} from "@/components/icons";

export const PRIMARY_NAV = [
  { name: "Dashboard", href: "/dashboard", icon: IconDashboard },
  { name: "Projects", href: "/projects", icon: IconProjects },
  { name: "Scans", href: "/scans", icon: IconScans },
  { name: "Findings", href: "/findings", icon: IconFindings },
  { name: "Assets", href: "/assets", icon: IconAssets },
  { name: "Attack Surface", href: "/attack-surface", icon: IconAttackSurface },
];

export const SECONDARY_NAV = [
  { name: "Settings", href: "/settings", icon: IconSettings },
];

export const PAGE_TITLES = {
  "/dashboard": "Dashboard",
  "/projects": "Projects",
  "/scans": "Scans",
  "/findings": "Findings",
  "/assets": "Assets",
  "/attack-surface": "Attack Surface",
  "/settings": "Settings",
  "/targets": "Targets",
};

export function getPageTitle(pathname) {
  if (!pathname) return "Workspace";
  const exact = PAGE_TITLES[pathname];
  if (exact) return exact;

  const match = Object.keys(PAGE_TITLES)
    .sort((a, b) => b.length - a.length)
    .find((href) => href !== "/dashboard" && pathname.startsWith(href));

  return match ? PAGE_TITLES[match] : "Workspace";
}

export function isNavActive(pathname, href) {
  if (href === "/dashboard") {
    return pathname === "/dashboard" || pathname === "/";
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}
