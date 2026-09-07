# Projects

Organization vs project: org is tenant, project is isolation boundary. Membership via OrganizationMembership/ProjectMembership, RBAC org_admin/project_admin/analyst/viewer. Create project: name, description, org. Project boundaries are security boundaries — cross-tenant access returns 404.
