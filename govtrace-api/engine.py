import re

try:
    from .models import Finding
except ImportError:
    from models import Finding

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b")
_PHONE = re.compile(r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
_DOB = re.compile(
    r"\b(?:dob|date of birth|born)\s*[:\-]?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b",
    re.IGNORECASE,
)
_NAME = re.compile(
    r"\b(?:name|customer|patient|employee|resident|applicant)\s*[:\-]?\s*"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
)
_PERSON_NAME = re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b")
_STREET_ADDRESS = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s+"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b",
    re.IGNORECASE,
)
_CITY_STATE_ZIP = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b")
_INJECTION = re.compile(
    r"ignore previous|ignore all previous|forget previous|"
    r"override instructions|jailbreak|dan mode|developer mode|"
    r"reveal system prompt|bypass safety",
    re.IGNORECASE,
)
_OVERCLAIM = re.compile(
    r"\b(?:guaranteed|proven fact|always|never|no doubt|unquestionably|certainly compliant|risk free)\b",
    re.IGNORECASE,
)

INPUT_LIMIT = 10_000


def _snippet(text: str, start: int, end: int, padding: int = 18) -> str:
    left = max(0, start - padding)
    right = min(len(text), end + padding)
    return text[left:right].strip()


def _mask_ssn(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "***-**-****"
    return f"***-**-{digits[-4:]}"


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:1]}****@{domain}"


def _mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"***-***-{digits[-4:]}"
    return "***-***-****"


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []

    for finding in findings:
        key = (finding.type, finding.example)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    return unique


def analyze(text: str) -> list[Finding]:
    text = text[:INPUT_LIMIT]
    findings: list[Finding] = []

    for match in _EMAIL.finditer(text):
        findings.append(Finding(
            type="EMAIL ADDRESS",
            severity="high",
            confidence=0.96,
            example=_mask_email(match.group()),
            rationale="A direct email address was detected, which is treated as sensitive contact information.",
            recommended_action="Remove or mask the email address before sending the content downstream.",
        ))

    for match in _SSN.finditer(text):
        findings.append(Finding(
            type="SOCIAL SECURITY NUMBER",
            severity="high",
            confidence=0.99,
            example=_mask_ssn(match.group()),
            rationale="The content matches a Social Security number pattern.",
            recommended_action="Block the payload until the SSN is fully redacted.",
        ))

    for match in _PHONE.finditer(text):
        findings.append(Finding(
            type="PHONE NUMBER",
            severity="medium",
            confidence=0.90,
            example=_mask_phone(match.group()),
            rationale="A phone number was detected and should be reviewed before production use.",
            recommended_action="Verify the number is necessary, or redact it before sharing.",
        ))

    for match in _STREET_ADDRESS.finditer(text):
        findings.append(Finding(
            type="STREET ADDRESS",
            severity="medium",
            confidence=0.88,
            example=_snippet(text, match.start(), match.end()),
            rationale="A physical mailing or street address was detected.",
            recommended_action="Remove the address unless the workflow explicitly requires it.",
        ))

    for match in _CITY_STATE_ZIP.finditer(text):
        findings.append(Finding(
            type="LOCATION DETAIL",
            severity="medium",
            confidence=0.82,
            example=match.group(),
            rationale="A city, state, and ZIP combination was detected.",
            recommended_action="Review whether this location detail should remain in the prompt or payload.",
        ))

    dob_match = _DOB.search(text)
    name_match = _NAME.search(text)
    if not name_match and dob_match:
        window_start = max(0, dob_match.start() - 80)
        window_end = min(len(text), dob_match.end() + 80)
        window = text[window_start:window_end]
        person_match = _PERSON_NAME.search(window)
        if person_match:
            name_match = person_match

    if dob_match and name_match:
        findings.append(Finding(
            type="NAME + DOB COMBINATION",
            severity="high",
            confidence=0.97,
            example=f"{name_match.group(1)} / {dob_match.group().strip()}",
            rationale="A named individual appears alongside a date-of-birth reference, which raises the sensitivity level of the payload.",
            recommended_action="Block or heavily redact personal identity details before proceeding.",
        ))
    elif dob_match:
        findings.append(Finding(
            type="DATE OF BIRTH",
            severity="medium",
            confidence=0.91,
            example=dob_match.group().strip(),
            rationale="A date-of-birth reference was detected and should be reviewed as personal information.",
            recommended_action="Redact or confirm that DOB data is approved for this workflow.",
        ))

    for match in _INJECTION.finditer(text):
        findings.append(Finding(
            type="PROMPT INJECTION",
            severity="high",
            confidence=0.99,
            example=match.group(),
            rationale="The text contains language associated with attempts to override or expose model instructions.",
            recommended_action="Block the request and remove the adversarial instruction before retrying.",
        ))

    for match in _OVERCLAIM.finditer(text):
        findings.append(Finding(
            type="OVERCLAIM LANGUAGE",
            severity="medium",
            confidence=0.83,
            example=match.group(),
            rationale="Absolute certainty language can create policy or trust risk and should be qualified.",
            recommended_action="Route to review and replace absolute claims with evidence-backed wording.",
        ))

    return _dedupe(findings)


def verdict(findings: list[Finding]) -> tuple[str, str]:
    if any(f.severity == "high" for f in findings):
        return (
            "POLICY VIOLATION",
            "High-confidence policy violations were detected. Remove the flagged content before using it in a live AI workflow.",
        )

    if findings:
        return (
            "NEEDS REVIEW",
            "Potentially sensitive or unsupported content was detected. Review and resolve the flagged items before proceeding.",
        )

    return (
        "COMPLIANT",
        "No sensitive data, prompt injection, or unsupported claims were detected in this policy check.",
    )
