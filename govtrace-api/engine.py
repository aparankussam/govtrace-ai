import re

try:
    from .models import Finding
except ImportError:
    from models import Finding

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b")
_INJECTION = re.compile(
    r"ignore previous|ignore all previous|forget previous|"
    r"override instructions|jailbreak|dan mode|developer mode|"
    r"reveal system prompt|bypass safety",
    re.IGNORECASE,
)
_OVERCLAIM = re.compile(
    r"\b(?:guaranteed|proven fact|always|never|no doubt|unquestionably)\b",
    re.IGNORECASE,
)

INPUT_LIMIT = 10_000


def _mask_ssn(v: str) -> str:
    return v[:-4] + "****"


def _mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    return local[0] + "****@" + domain


def analyze(text: str) -> list[Finding]:
    text = text[:INPUT_LIMIT]
    findings: list[Finding] = []

    for match in _EMAIL.finditer(text):
        findings.append(Finding(
            type="PII",
            severity="high",
            confidence=0.95,
            example=_mask_email(match.group()),
            rationale="Matches email address pattern",
            recommended_action="Remove or mask PII before sending",
        ))

    for match in _SSN.finditer(text):
        findings.append(Finding(
            type="PII",
            severity="high",
            confidence=0.95,
            example=_mask_ssn(match.group()),
            rationale="Matches SSN pattern",
            recommended_action="Redact before sending",
        ))

    for match in _INJECTION.finditer(text):
        findings.append(Finding(
            type="INJECTION",
            severity="high",
            confidence=0.99,
            example=match.group(),
            rationale="Matches prompt-injection phrase",
            recommended_action="Block request",
        ))

    for match in _OVERCLAIM.finditer(text):
        findings.append(Finding(
            type="OVERCLAIM",
            severity="medium",
            confidence=0.80,
            example=match.group(),
            rationale="Certainty/overclaim language detected",
            recommended_action="Review and qualify the statement",
        ))

    return findings


def verdict(findings: list[Finding]) -> tuple[str, str]:
    if any(f.severity == "high" for f in findings):
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
    return status, message
