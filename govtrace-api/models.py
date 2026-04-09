from typing import Optional

from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    profile: str = Field(default="General", max_length=50)


class RegulatoryReference(BaseModel):
    citation: str
    body: str
    url: str


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
    regulatory_references: list[RegulatoryReference] = Field(default_factory=list)


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
    safe_after_redaction: bool
    audit_summary: AuditSummary
    redacted_preview: Optional[str] = None
    findings: list[Finding]


# ---------------------------------------------------------------------------
# Audit history models
# ---------------------------------------------------------------------------

class HistoryEntry(BaseModel):
    """Lightweight summary row returned by GET /audit/history."""
    run_id: str
    timestamp: str
    profile: str
    status: str
    overall_severity: str
    overall_confidence: float
    safe_after_redaction: bool
    input_hash: str       # SHA-256 of original input — for correlation, not reconstruction
    input_length: int     # Character count of original input
    finding_count: int


class HistoryResponse(BaseModel):
    total: int            # Total matching runs (before pagination)
    limit: int
    offset: int
    runs: list[HistoryEntry]
