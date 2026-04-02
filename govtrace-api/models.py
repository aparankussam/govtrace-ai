from typing import Optional

from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    profile: str = Field(default="General", max_length=50)


class Finding(BaseModel):
    type: str
    reason_code: str
    reason_label: str
    rule_id: str
    rule_label: str
    severity: str
    confidence: float
    confidence_label: str
    confidence_explanation: str
    signal: str
    location: str
    example: str
    rationale: str
    recommended_action: str


class AuditSummary(BaseModel):
    timestamp: str
    profile_used: str
    verdict: str
    finding_count: int


class AuditResponse(BaseModel):
    run_id: str
    timestamp: str
    profile: str
    status: str
    message: str
    overall_severity: str
    overall_confidence: float
    overall_confidence_label: str
    overall_confidence_explanation: str
    safe_for_use: bool
    audit_summary: AuditSummary
    redacted_preview: Optional[str] = None
    findings: list[Finding]
