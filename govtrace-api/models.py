from typing import Optional

from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    profile: str = Field(default="General", max_length=50)


class Finding(BaseModel):
    type: str
    reason_code: str
    reason_label: str
    severity: str
    confidence: float
    confidence_label: str
    example: str
    rationale: str
    recommended_action: str


class AuditResponse(BaseModel):
    profile: str
    status: str
    message: str
    overall_severity: str
    overall_confidence: float
    overall_confidence_label: str
    redacted_preview: Optional[str] = None
    findings: list[Finding]
