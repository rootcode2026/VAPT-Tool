import {
  IconAssets,
  IconAttackSurface,
  IconAudit,
  IconDashboard,
  IconFindings,
  IconProjects,
  IconScans,
  IconSettings,
  IconShield,
  IconUsers,
} from "@/components/icons";

export const PRIMARY_NAV = [
  { name: "Dashboard", href: "/dashboard", icon: IconDashboard },
  { name: "Projects", href: "/projects", icon: IconProjects },
  { name: "Scans", href: "/scans", icon: IconScans },
  { name: "Findings", href: "/findings", icon: IconFindings },
  { name: "Assets", href: "/assets", icon: IconAssets },
  { name: "Attack Surface", href: "/attack-surface", icon: IconAttackSurface },
  { name: "Code Security", href: "/code-security", icon: IconShield },
  { name: "Cloud Security", href: "/cloud-security", icon: IconScans },
  { name: "DAST", href: "/dast", icon: IconScans },
  { name: "API Security", href: "/api-security", icon: IconShield },
  { name: "Reports", href: "/reports", icon: IconAudit },
  { name: "Compliance", href: "/compliance", icon: IconShield },
  { name: "AI Analyst", href: "/ai", icon: IconShield },
  { name: "Audit", href: "/audit", icon: IconAudit },
];

export const SECONDARY_NAV = [
  { name: "Help", href: "/help", icon: IconShield },
  { name: "Settings", href: "/settings", icon: IconSettings },
];

export const ADMIN_NAV = [
  { name: "Admin Dashboard", href: "/admin", icon: IconShield },
  { name: "Organizations", href: "/admin/organizations", icon: IconProjects },
  { name: "Users", href: "/admin/users", icon: IconUsers },
  { name: "Scanner Fleet", href: "/admin/scanners", icon: IconScans },
  { name: "System Health", href: "/admin/system", icon: IconDashboard },
  { name: "Audit", href: "/audit", icon: IconAudit },
];

export const PAGE_TITLES = {
  "/dashboard": "Dashboard",
  "/projects": "Projects",
  "/scans": "Scans",
  "/findings": "Findings",
  "/assets": "Assets",
  "/attack-surface": "Attack Surface",
  "/code-security": "Code Security",
  "/cloud-security": "Cloud Security",
  "/dast": "DAST",
  "/api-security": "API Security",
  "/reports": "Reports",
  "/compliance": "Compliance",
  "/ai": "AI Analyst",
  "/audit": "Audit",
  "/admin": "Admin",
  "/admin/organizations": "Organizations",
  "/admin/users": "Users",
  "/admin/scanners": "Scanner Fleet",
  "/admin/system": "System Health",
  "/settings": "Settings",
  "/help": "Help",
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
