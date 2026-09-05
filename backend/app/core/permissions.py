"""
Centralized permission model for enterprise multi-tenancy + RBAC.

Roles are separated:
- Platform role: User.role (super_admin, admin, member) — legacy field, super_admin is platform
- Organization role: organization_memberships.role (member, org_admin)
- Project role: project_memberships.role (viewer, analyst, project_admin)

Permissions are the authoritative check; roles map to permission sets.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

PLATFORM_ROLES = {"super_admin", "admin", "member"}
ORG_ROLES = {"member", "org_admin"}
PROJECT_ROLES = {"viewer", "analyst", "project_admin"}

# ---------------------------------------------------------------------------
# Permission constants — minimal coherent set covering existing API inventory
# ---------------------------------------------------------------------------

# Organization
PERM_ORG_READ = "organization.read"
PERM_ORG_UPDATE = "organization.update"
PERM_ORG_MANAGE_MEMBERS = "organization.manage_members"

# Project
PERM_PROJECT_READ = "project.read"
PERM_PROJECT_CREATE = "project.create"
PERM_PROJECT_UPDATE = "project.update"
PERM_PROJECT_DELETE = "project.delete"
PERM_PROJECT_MANAGE_MEMBERS = "project.manage_members"

# Targets
PERM_TARGET_READ = "target.read"
PERM_TARGET_CREATE = "target.create"
PERM_TARGET_DELETE = "target.delete"

# Scans
PERM_SCAN_READ = "scan.read"
PERM_SCAN_EXECUTE = "scan.execute"

# Findings / Assets / Cloud / Dashboard
PERM_FINDING_READ = "finding.read"
PERM_FINDING_TRIAGE = "finding.triage"
PERM_ASSET_READ = "asset.read"
PERM_CLOUD_READ = "cloud.read"
PERM_CLOUD_MANAGE = "cloud.manage"
PERM_INGESTION_CREATE = "ingestion.create"
PERM_DASHBOARD_READ = "dashboard.read"
PERM_REPORT_READ = "report.read"

# Administration
PERM_SCANNER_MANAGE = "scanner.manage"
PERM_AUDIT_READ = "audit.read"

ALL_PERMISSIONS = {
    PERM_ORG_READ,
    PERM_ORG_UPDATE,
    PERM_ORG_MANAGE_MEMBERS,
    PERM_PROJECT_READ,
    PERM_PROJECT_CREATE,
    PERM_PROJECT_UPDATE,
    PERM_PROJECT_DELETE,
    PERM_PROJECT_MANAGE_MEMBERS,
    PERM_TARGET_READ,
    PERM_TARGET_CREATE,
    PERM_TARGET_DELETE,
    PERM_SCAN_READ,
    PERM_SCAN_EXECUTE,
    PERM_FINDING_READ,
    PERM_FINDING_TRIAGE,
    PERM_ASSET_READ,
    PERM_CLOUD_READ,
    PERM_CLOUD_MANAGE,
    PERM_INGESTION_CREATE,
    PERM_DASHBOARD_READ,
    PERM_REPORT_READ,
    PERM_SCANNER_MANAGE,
    PERM_AUDIT_READ,
}

# ---------------------------------------------------------------------------
# Role -> permissions mapping
# ---------------------------------------------------------------------------

# Organization role permissions
ORG_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "member": {
        PERM_ORG_READ,
        PERM_PROJECT_READ,
        PERM_TARGET_READ,
        PERM_SCAN_READ,
        PERM_FINDING_READ,
        PERM_ASSET_READ,
        PERM_CLOUD_READ,
        PERM_DASHBOARD_READ,
        PERM_REPORT_READ,
    },
    "org_admin": {
        # org_admin gets all member perms plus management
        PERM_ORG_READ,
        PERM_ORG_UPDATE,
        PERM_ORG_MANAGE_MEMBERS,
        PERM_PROJECT_READ,
        PERM_PROJECT_CREATE,
        PERM_PROJECT_UPDATE,
        PERM_PROJECT_DELETE,
        PERM_PROJECT_MANAGE_MEMBERS,
        PERM_TARGET_READ,
        PERM_TARGET_CREATE,
        PERM_TARGET_DELETE,
        PERM_SCAN_READ,
        PERM_SCAN_EXECUTE,
        PERM_FINDING_READ,
        PERM_FINDING_TRIAGE,
        PERM_ASSET_READ,
        PERM_CLOUD_READ,
        PERM_CLOUD_MANAGE,
        PERM_INGESTION_CREATE,
        PERM_DASHBOARD_READ,
        PERM_REPORT_READ,
        PERM_SCANNER_MANAGE,
        PERM_AUDIT_READ,
    },
}

# Project role permissions
PROJECT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {
        PERM_PROJECT_READ,
        PERM_TARGET_READ,
        PERM_SCAN_READ,
        PERM_FINDING_READ,
        PERM_ASSET_READ,
        PERM_CLOUD_READ,
        PERM_DASHBOARD_READ,
        PERM_REPORT_READ,
    },
    "analyst": {
        PERM_PROJECT_READ,
        PERM_TARGET_READ,
        PERM_TARGET_CREATE,
        PERM_SCAN_READ,
        PERM_SCAN_EXECUTE,
        PERM_FINDING_READ,
        PERM_FINDING_TRIAGE,
        PERM_ASSET_READ,
        PERM_CLOUD_READ,
        PERM_CLOUD_MANAGE,
        PERM_INGESTION_CREATE,
        PERM_DASHBOARD_READ,
        PERM_REPORT_READ,
    },
    "project_admin": {
        PERM_PROJECT_READ,
        PERM_PROJECT_UPDATE,
        PERM_PROJECT_DELETE,
        PERM_PROJECT_MANAGE_MEMBERS,
        PERM_TARGET_READ,
        PERM_TARGET_CREATE,
        PERM_TARGET_DELETE,
        PERM_SCAN_READ,
        PERM_SCAN_EXECUTE,
        PERM_FINDING_READ,
        PERM_FINDING_TRIAGE,
        PERM_ASSET_READ,
        PERM_CLOUD_READ,
        PERM_CLOUD_MANAGE,
        PERM_INGESTION_CREATE,
        PERM_DASHBOARD_READ,
        PERM_REPORT_READ,
    },
}

# Platform super_admin has all permissions
SUPER_ADMIN_PERMISSIONS = set(ALL_PERMISSIONS)


def permissions_for_org_role(role: str) -> set[str]:
    return set(ORG_ROLE_PERMISSIONS.get(role, set()))


def permissions_for_project_role(role: str) -> set[str]:
    return set(PROJECT_ROLE_PERMISSIONS.get(role, set()))


def is_valid_org_role(role: str) -> bool:
    return role in ORG_ROLES


def is_valid_project_role(role: str) -> bool:
    return role in PROJECT_ROLES
