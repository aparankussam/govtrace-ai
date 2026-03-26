import re
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="GovTrace AI Guardrail")

# --- CORS ---
FRONTEND_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://your-vercel-app.vercel.app",  # replace after Vercel deploy
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Precompiled patterns ---
_PII_PATTERNS = [
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "ssn",
        re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b"),
    ),
]

_INJECTION_PHRASES = re.compile(
    r"ignore previous|ignore all previous|forget previous|"
    r"override instructions|jailbreak|dan mode|developer mode|"
    r"reveal system prompt|bypass safety",
    re.IGNORECASE,
)

_OVERCLAIM_WORDS = re.compile(
    r"\b(?:guaranteed|proven fact|always|never|no doubt|unquestionably)\b",
    re.IGNORECASE,
)

# --- Models ---
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


def _redact_ssn(value: str) -> str:
    return value[:-4] + "****"


def _redact_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return local[0] + "****@" + domain if local else "****@" + domain


@app.get("/")
def root():
    return {"status": "ok", "service": "GovTrace AI Guardrail API"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/audit", response_model=AuditResponse)
def audit(req: AuditRequest) -> AuditResponse:
    text = req.text[:10_000]
    findings: list[Finding] = []

    # --- PII checks ---
    for label, pattern in _PII_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group()
            if label == "ssn":
                example = _redact_ssn(raw)
                rationale = "Matches SSN pattern"
                action = "Redact before sending"
            else:
                example = _redact_email(raw)
                rationale = "Matches email address pattern"
                action = "Remove or mask PII before sending"

            findings.append(
                Finding(
                    type="PII",
                    severity="high",
                    confidence=0.95,
                    example=example,
                    rationale=rationale,
                    recommended_action=action,
                )
            )

    # --- Injection checks ---
    for match in _INJECTION_PHRASES.finditer(text):
        findings.append(
            Finding(
                type="INJECTION",
                severity="high",
                confidence=0.99,
                example=match.group(),
                rationale="Matches prompt-injection phrase",
                recommended_action="Block request",
            )
        )

    # --- Overclaim checks ---
    for match in _OVERCLAIM_WORDS.finditer(text):
        findings.append(
            Finding(
                type="OVERCLAIM",
                severity="medium",
                confidence=0.80,
                example=match.group(),
                rationale="Certainty/overclaim language detected",
                recommended_action="Review and qualify the statement",
            )
        )

    # --- Verdict ---
    has_high = any(f.severity == "high" for f in findings)
    if has_high:
        status = "BLOCK"
    elif findings:
        status = "WARNING"
    else:
        status = "SAFE"

    count = len(findings)
    message = (
        f"{count} finding{'s' if count != 1 else ''} detected"
        if findings
        else "No findings detected"
    )

    return AuditResponse(status=status, message=message, findings=findings)