from pydantic import BaseModel


class AuditRequest(BaseModel):
    text: str


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
