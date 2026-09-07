// Role-aware tour steps. Each step targets a data-tour attribute.
// The tour filters steps based on the authenticated user's actual permissions.

export function getTourSteps(user) {
  const role = user?.role;
  const isSuperAdmin = role === "super_admin";

  // Base steps visible to all authenticated users
  const base = [
    {
      id: "welcome",
      title: "Welcome to VAPT Platform",
      content: "Let's take a quick tour so you know where everything is.",
      target: null,
    },
    {
      id: "dashboard",
      title: "Dashboard",
      content: "Your security posture at a glance — risk, findings, assets, and recent activity.",
      target: "dashboard",
      href: "/dashboard",
    },
    {
      id: "projects",
      title: "Projects",
      content: "Projects are security boundaries for organizing assets, scans, and findings.",
      target: "projects",
      href: "/projects",
    },
    {
      id: "scans",
      title: "Scans",
      content: "Run and review scans across network, web, and application layers.",
      target: "scans",
      href: "/scans",
    },
    {
      id: "findings",
      title: "Findings",
      content: "Findings are prioritized by severity, risk score, and validation state.",
      target: "findings",
      href: "/findings",
    },
    {
      id: "assets",
      title: "Assets",
      content: "Asset intelligence shows what you own and how it's discovered.",
      target: "assets",
      href: "/assets",
    },
    {
      id: "attack-surface",
      title: "Attack Surface",
      content: "See relationships between domains, IPs, services, and cloud resources.",
      target: "attack-surface",
      href: "/attack-surface",
    },
    {
      id: "code-security",
      title: "Code Security",
      content: "SAST, SCA, secrets, container, IaC, and API checks — with evidence and provenance.",
      target: "code-security",
      href: "/code-security",
    },
    {
      id: "cloud-security",
      title: "Cloud Security",
      content: "Provider-neutral cloud discovery, resources, and security checks (mock in dev).",
      target: "cloud-security",
      href: "/cloud-security",
    },
    {
      id: "dast",
      title: "DAST",
      content: "Safe scanning by default; advanced tests are bounded and authorized.",
      target: "dast",
      href: "/dast",
    },
    {
      id: "reports",
      title: "Reports",
      content: "Generate executive, technical, posture, and compliance reports.",
      target: "reports",
      href: "/reports",
    },
    {
      id: "compliance",
      title: "Compliance",
      content: "Map findings to frameworks — coverage is assessment support, not certification.",
      target: "compliance",
      href: "/compliance",
    },
    {
      id: "ai",
      title: "AI Analyst",
      content: "Bounded AI helper — citations, known/inferred/unknown, respects tenant isolation.",
      target: "ai",
      href: "/ai",
    },
    {
      id: "settings",
      title: "Settings & Security",
      content: "Manage MFA, password, and account security. Restart tour from Help.",
      target: "settings",
      href: "/settings",
    },
    {
      id: "help",
      title: "Help Center",
      content: "Searchable guides, Getting Started, troubleshooting, FAQ, and glossary.",
      target: "help",
      href: "/help",
    },
  ];

  if (isSuperAdmin) {
    // Add admin steps for super_admin
    const adminSteps = [
      {
        id: "admin",
        title: "Administration",
        content: "Manage organizations, users, scanner fleet, and system health.",
        target: "admin",
        href: "/admin",
      },
    ];
    // Insert admin after settings
    const idx = base.findIndex((s) => s.id === "settings");
    base.splice(idx, 0, ...adminSteps);
  }

  return base;
}
