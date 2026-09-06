import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    framework: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # owasp_asvs, owasp_top10, cis, iso27001, nist_csf, pci_dss
    version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    framework_id: Mapped[str] = mapped_column(String(36), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    parent_control: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="not_assessed")  # not_assessed, supported, partially_supported, not_applicable, needs_review
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    control_id: Mapped[str] = mapped_column(String(36), ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # finding, asset, scan, check
    source_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
