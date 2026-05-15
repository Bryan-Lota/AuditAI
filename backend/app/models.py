from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, Integer, LargeBinary, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class AuditStatus(str, Enum):
    queued = "queued"
    analyzing = "analyzing"
    explaining = "explaining"
    reporting = "reporting"
    complete = "complete"
    failed = "failed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    audit_sessions: Mapped[list["AuditSession"]] = relationship(back_populates="user")


class AuditSession(Base):
    __tablename__ = "audit_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    contract_name: Mapped[str] = mapped_column(String(255))
    source_code: Mapped[str] = mapped_column(Text)
    pragma_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[AuditStatus] = mapped_column(SqlEnum(AuditStatus), default=AuditStatus.queued)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user: Mapped[User | None] = relationship(back_populates="audit_sessions")
    findings: Mapped[list["Finding"]] = relationship(back_populates="audit_session", cascade="all, delete-orphan")
    report: Mapped["Report | None"] = relationship(back_populates="audit_session", cascade="all, delete-orphan", uselist=False)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_session_id: Mapped[str] = mapped_column(ForeignKey("audit_sessions.id"), index=True)
    vulnerability_type: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    function_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_mapping: Mapped[str | None] = mapped_column(Text, nullable=True)
    slither_description: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploitability: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    audit_session: Mapped[AuditSession] = relationship(back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_session_id: Mapped[str] = mapped_column(ForeignKey("audit_sessions.id"), unique=True, index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    pdf_bytes: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    audit_session: Mapped[AuditSession] = relationship(back_populates="report")
