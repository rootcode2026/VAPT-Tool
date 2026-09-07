// Structured help content for Help Center and contextual help.
// Keep content practical, derived from actual implementation.

export const HELP_SECTIONS = [
  {
    id: "getting-started",
    title: "Getting Started",
    content: `1. Secure your account — set a strong password and enable MFA in Settings → Security. 2. Understand your organization and project — organization is the tenant, project is the security boundary. 3. Create or select a project. 4. Add targets you are authorized to scan. 5. Run a scan (quick for fast, full for deep). 6. Review findings (severity, risk, evidence). 7. Explore assets and attack surface. 8. Review code/cloud/API security. 9. Generate reports. 10. Review compliance. 11. Use AI Analyst where enabled. 12. Configure monitoring.`,
  },
  {
    id: "dashboard",
    title: "Dashboard",
    content: `Shows posture — open findings by severity, risk distribution, assets, recent scans, audit. Use it to triage. What to expect: grades A–D, levels critical/high/medium/low/info.`,
  },
  {
    id: "projects",
    title: "Projects",
    content: `Organization vs project: org is tenant, project is isolation boundary. Membership via OrganizationMembership/ProjectMembership, RBAC org_admin/project_admin/analyst/viewer. Create project: name, description, org. Project boundaries are security boundaries — cross-tenant access returns 404.`,
  },
  {
    id: "targets",
    title: "Targets",
    content: `Types: domain, ip, url, repository, cloud account. Add only systems you are authorized to assess. Validation: format, size limits (2 MB request), no traversal. Scan profiles: quick (fast), full (deep), web.`,
  },
  {
    id: "scans",
    title: "Scans",
    content: `Create scan via project → target → profile. Families: network (nmap), web (nuclei, zap, nikto, http_fingerprint, tls, dns, subdomain), SAST/SCA/secrets (Semgrep/OSV/Gitleaks), container (Trivy), IaC (Checkov), API (vapt-api), cloud (mock). Async via Celery, status queued/running/completed/failed, progress, ` + "`overall_scan_status`" + `. On failure: check scanner health, retry, inspect audit.`,
  },
  {
    id: "findings",
    title: "Findings",
    content: `Fields: severity (critical/high/medium/low/info), confidence, scanner, title, CVE/CWE, evidence, remediation, risk score 0–100 grade. States: detected → corroborated → needs_review → confirmed → false_positive / accepted_risk → remediated → reopened. Risk via RiskAssessmentEngine, asset context, SLA, retest.`,
  },
  {
    id: "assets",
    title: "Assets",
    content: `Types: dns, webapp, host, service, technology, repository, source_file, package, container_image, iac_resource, cloud_resource, api_endpoint. Discovery via scans + ingestion, dedup by (project, type, value), relationships via contains/uses/observed_on.`,
  },
  {
    id: "attack-surface",
    title: "Attack Surface",
    content: `Graph of assets + relationships (domains→subdomains→IPs→services). Change detection via asset_change_events, relationships discovered via cloud/ingestion. Interpret: internet-exposed vs internal, stale vs active.`,
  },
  {
    id: "code-security",
    title: "Code Security",
    content: `Six areas: SAST (Semgrep 1.75), SCA (OSV 1.9.2), secrets (Gitleaks 8.30.1, redacted), container (Trivy 0.66), IaC (Checkov 3.3.16), API (vapt-api 1.0). Evidence provenance, ` + "`execution_engine`" + `, no plaintext secrets.`,
  },
  {
    id: "cloud-security",
    title: "Cloud Security",
    content: `Provider-neutral aws/gcp/azure via worker/app/cloud, MockCloudDiscoveryAdapter in dev, real SDK future. Resources: cloud_account/cloud_resource, checks → findings. Production needs connector credentials via CONNECTOR_ENCRYPTION_KEY. Mock 100 resources max.`,
  },
  {
    id: "dast",
    title: "DAST",
    content: `Profiles: quick/full, bounded requests (1000), rate limits (100/min), SSRF protections, safe by default. Advanced tests require authorization. View via /dast.`,
  },
  {
    id: "api-security",
    title: "API Security",
    content: `OpenAPI workflows: upload spec, validate, ` + "`python /app/api_scan.py`" + `, SARIF, checks for http vs https, missing security, operationId. Workspace read-only.`,
  },
  {
    id: "reports",
    title: "Reports",
    content: `Types: executive_security, technical_vapt, posture, attack_surface, risk, remediation_sla, code_security, cloud_security, compliance. Registry via app/models/report, status completed/failed, download via /reports, evidence traceability.`,
  },
  {
    id: "compliance",
    title: "Compliance",
    content: `Frameworks: via compliance tables, controls, mappings, coverage: supported/partially_supported/needs_review/not_applicable/not_assessed. Not certification — assessment support.`,
  },
  {
    id: "ai-analyst",
    title: "AI Analyst",
    content: `Bounded context: findings/assets, citations, known/inferred/unknown. Mock provider default, no unrestricted DB or command execution. Disabled state shows message.`,
  },
  {
    id: "authentication-mfa",
    title: "Authentication & MFA",
    content: `Login → MFA if enabled (TOTP 6-digit 30s ±1 or recovery code). Enrollment: Settings → Enable MFA → scan QR → verify → 10 recovery codes (single-use, hashed). Recovery: use code at login. Reset: Forgot password → email generic (no enumeration) → 15 min token → reset (Argon2id, does not disable MFA). Change password in Settings. Super_admin MFA required, org can enforce via PATCH /organizations/{id}/security/mfa. Session revocation via password_changed_at. Rate limited, audited. See docs/AUTHENTICATION_SECURITY.md.`,
  },
  {
    id: "roles-permissions",
    title: "User Roles & Permissions",
    content: `Org: member/org_admin, Project: viewer/analyst/project_admin, Platform: super_admin. Permissions via ORG_ROLE_PERMISSIONS/PROJECT_ROLE_PERMISSIONS. Tenant isolation via organization_id/project_id, 404 for cross-tenant.`,
  },
  {
    id: "administration",
    title: "Administration",
    content: `Super_admin: /admin — organizations, users, scanner fleet, system health, audit. Org admin: members, project members, MFA policy. Audit logs via /audit, tenant-isolated, redacted.`,
  },
  {
    id: "troubleshooting",
    title: "Troubleshooting",
    content: `Cannot log in: check email/password, MFA code (time drift ±1), recovery code used? Project inaccessible: 404 means not member or wrong org. Scan stuck: check scanner health, Celery, Docker socket proxy. Findings not appearing: scan completed? Check risk engine. Report delayed: Celery. AI unavailable: AI_ENABLED=false default. Cloud/repo unavailable: connector not configured. Never disable security controls as fix.`,
  },
  {
    id: "faq",
    title: "FAQ",
    content: `What is a project? Security boundary for assets/scans/findings. What can I scan? Only authorized systems. Why can't I access a project? Not a member or wrong org (404). Why MFA? Required for super_admin, org can enforce. Lost authenticator? Use recovery code, or admin reset via _debug (dev). What is a finding? Scanner result with severity/risk/evidence. Risk? 0–100 via RiskAssessmentEngine. Accepted risk? Acknowledged but not remediated. Retest? Verify fix. Attack surface? Graph of assets/relationships. DAST/SAST/SCA? Dynamic/static/composition analysis. Compliance coverage? Assessment support, not cert. AI knowledge? Bounded findings/assets, cited.`,
  },
  {
    id: "glossary",
    title: "Glossary",
    content: `Asset: discovered entity. Target: scope for scan. Finding: vulnerability. Severity: critical/high/medium/low/info. Confidence: scanner certainty. Corroboration: multiple scanners agree. Risk: score/grade. CVE/CWE: identifiers. SAST/SCA/DAST/API: code/composition/dynamic/API testing. Attack Surface: exposed assets. RBAC: role-based. Tenant: organization isolation. SLA: remediation timeline. Retest: verify fix. Accepted Risk: acknowledged. False Positive: not real. MFA/TOTP/Recovery: second factor. Compliance Control: framework requirement.`,
  },
];
