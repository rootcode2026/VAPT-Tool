"""Compliance mapping — 6 frameworks, extensible."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.compliance import ComplianceControl, ComplianceFramework, ComplianceMapping

FRAMEWORKS = [
    {"framework": "owasp_asvs", "version": "4.0", "display_name": "OWASP ASVS 4.0", "description": "Application Security Verification Standard"},
    {"framework": "owasp_top10", "version": "2021", "display_name": "OWASP Top 10 2021", "description": "Top 10 Web Application Security Risks"},
    {"framework": "cis", "version": "8.0", "display_name": "CIS Controls v8", "description": "Center for Internet Security Controls"},
    {"framework": "iso27001", "version": "2022", "display_name": "ISO 27001:2022", "description": "Information Security Management"},
    {"framework": "nist_csf", "version": "2.0", "display_name": "NIST CSF 2.0", "description": "Cybersecurity Framework"},
    {"framework": "pci_dss", "version": "4.0", "display_name": "PCI DSS 4.0", "description": "Payment Card Industry Data Security Standard"},
]

# Minimal controls per framework (2 each for demo)
CONTROLS = {
    "owasp_asvs": [
        {"control_id": "2.1.1", "title": "Verify that passwords are stored securely", "category": "Authentication"},
        {"control_id": "2.2.1", "title": "Verify anti-automation controls", "category": "Authentication"},
    ],
    "owasp_top10": [
        {"control_id": "A01", "title": "Broken Access Control", "category": "Access Control"},
        {"control_id": "A03", "title": "Injection", "category": "Injection"},
    ],
    "cis": [
        {"control_id": "CIS-1", "title": "Inventory and Control of Assets", "category": "Asset Management"},
        {"control_id": "CIS-4", "title": "Secure Configuration", "category": "Configuration"},
    ],
    "iso27001": [
        {"control_id": "A.5.1", "title": "Information Security Policies", "category": "Governance"},
        {"control_id": "A.8.1", "title": "User Endpoint Devices", "category": "Asset"},
    ],
    "nist_csf": [
        {"control_id": "ID.AM-1", "title": "Physical devices inventoried", "category": "Identify"},
        {"control_id": "PR.AC-1", "title": "Identities managed", "category": "Protect"},
    ],
    "pci_dss": [
        {"control_id": "Req-1", "title": "Install and maintain network security controls", "category": "Network"},
        {"control_id": "Req-8", "title": "Identify users and authenticate access", "category": "Access"},
    ],
}

def seed_frameworks(db: Session) -> int:
    created = 0
    for fw in FRAMEWORKS:
        existing = db.query(ComplianceFramework).filter(ComplianceFramework.framework == fw["framework"], ComplianceFramework.version == fw["version"]).first()
        if existing:
            continue
        fr = ComplianceFramework(framework=fw["framework"], version=fw["version"], display_name=fw["display_name"], description=fw["description"])
        db.add(fr)
        db.flush()
        for ctrl in CONTROLS.get(fw["framework"], []):
            cc = ComplianceControl(framework_id=fr.id, control_id=ctrl["control_id"], title=ctrl["title"], category=ctrl["category"], status="not_assessed")
            db.add(cc)
        created += 1
    if created:
        db.commit()
    return created

def list_frameworks(db: Session):
    seed_frameworks(db)
    return db.query(ComplianceFramework).all()

def get_framework(db: Session, framework_id: str):
    return db.query(ComplianceFramework).filter(ComplianceFramework.id == framework_id).first()

def get_controls(db: Session, framework_id: str):
    return db.query(ComplianceControl).filter(ComplianceControl.framework_id == framework_id).all()

def get_control_coverage(db: Session, framework_id: str, organization_id: str, project_id: str | None):
    controls = get_controls(db, framework_id)
    total = len(controls)
    # Map via compliance_mappings
    cov = {}
    for c in controls:
        mappings = db.query(ComplianceMapping).filter(ComplianceMapping.control_id == c.id)
        if organization_id:
            mappings = mappings.filter(ComplianceMapping.organization_id == organization_id)
        if project_id:
            mappings = mappings.filter(ComplianceMapping.project_id == project_id)
        count = mappings.count()
        if count == 0:
            cov[c.status] = cov.get(c.status, 0) + 1
        else:
            # If has evidence, mark supported
            cov["supported"] = cov.get("supported", 0) + 1
    return {
        "total": total,
        "supported": cov.get("supported", 0),
        "partially_supported": cov.get("partially_supported", 0),
        "needs_review": cov.get("needs_review", 0),
        "not_assessed": cov.get("not_assessed", total - cov.get("supported", 0)),
        "coverage_percent": round(cov.get("supported", 0) / max(total, 1) * 100, 1) if total else 0,
    }
