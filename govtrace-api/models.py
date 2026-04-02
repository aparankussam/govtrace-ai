from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)


class Finding(BaseModel):
    type: str
    severity: str
    confidence: float
    example: str
    rationale: str
    recommended_action: str


class AuditResponse(BaseModel):
    status: str
    message: str
    findings: list[Finding]
