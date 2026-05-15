from datetime import datetime

from pydantic import BaseModel, ConfigDict

from .models import AuditStatus


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    vulnerability_type: str
    severity: str
    function_name: str | None
    line_number: int | None
    detector: str | None
    slither_description: str
    explanation: str | None
    exploitability: str | None
    remediation_snippet: str | None


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    file_name: str
    created_at: datetime


class AuditSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    contract_name: str
    pragma_version: str | None
    status: AuditStatus
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    findings: list[FindingRead]
    report: ReportRead | None
