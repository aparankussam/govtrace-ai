import re
from typing import Iterable, Optional

try:
    from .models import Finding, RegulatoryReference
except ImportError:
    from models import Finding, RegulatoryReference

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)")
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
_UNVERIFIED = re.compile(
    r"\b(?:tbd|to be confirmed|not yet verified|unverified|awaiting confirmation|"
    r"pending documentation|documentation unavailable|evidence pending|source not confirmed|"
    r"preliminary only|based on limited data)\b",
    re.IGNORECASE,
)
_EXTERNAL_SHARING = re.compile(
    r"\b(?:share(?:d)? with external partners|send to vendors?|distribute broadly|share with all staff|"
    r"training purposes outside controlled use|external sharing|share externally)\b",
    re.IGNORECASE,
)
_CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
_BANK_ACCOUNT = re.compile(r"\b(?:account number|acct(?:ount)?|routing)\s*[:#-]?\s*\d{6,17}\b", re.IGNORECASE)
_HEALTH_DATA = re.compile(
    r"\b(?:patient|diagnosis|diagnosed|treatment|medication|prescription|mrn|medical record|phi|hipaa)\b",
    re.IGNORECASE,
)

INPUT_LIMIT = 10_000

PROFILE_ALIASES = {
    "general": "General",
    "public sector": "Public Sector",
    "public_sector": "Public Sector",
    "healthcare": "Healthcare",
    "finance": "Finance",
}

REASON_LABELS = {
    "PII": "PII detected",
    "FINANCIAL": "Financial data detected",
    "HEALTH": "Health data detected",
    "EXTERNAL_SHARING": "Unsafe external sharing",
    "PROMPT_INJECTION": "Prompt injection attempt",
    "UNSUPPORTED_CLAIM": "Unsupported claim",
    "INCOMPLETE_EVIDENCE": "Incomplete or unverified information",
}

RULE_LABELS = {
    "PHI-01": "Protected health information exposure",
    "PII-01": "Personally identifiable information exposure",
    "PII-02": "Contact information detected",
    "PII-03": "Identity record exposure",
    "FIN-02": "Financial account disclosure",
    "SEC-01": "Prompt injection or instruction override attempt",
    "GEN-03": "Unsafe external sharing",
    "GEN-04": "Unsupported claim",
    "GEN-05": "Incomplete or unverified support",
}

# Regulatory citation registry — keyed by rule_id.
# Each entry maps to one or more real regulatory frameworks.
# This is the foundation for the configurable rule engine (rules are
# currently hardcoded but this registry is the extraction point).
REGULATORY_CITATIONS: dict[str, list[dict[str, str]]] = {
    "PII-01": [
        {
            "citation": "GDPR Art. 4(1) — Definition of personal data",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-4-gdpr/",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
    ],
    "PII-02": [
        {
            "citation": "GDPR Art. 4(1) — Definition of personal data",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-4-gdpr/",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
    ],
    "PII-03": [
        {
            "citation": "GDPR Art. 9 — Processing of special categories of personal data",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-9-gdpr/",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
        {
            "citation": "Privacy Act of 1974, 5 U.S.C. §552a — Records maintained on individuals",
            "body": "US Federal",
            "url": "https://www.govinfo.gov/content/pkg/USCODE-2010-title5/pdf/USCODE-2010-title5-partI-chap5-subchapII-sec552a.pdf",
        },
    ],
    "PHI-01": [
        {
            "citation": "HIPAA §164.514 — De-identification of protected health information",
            "body": "HHS / HIPAA Privacy Rule",
            "url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514",
        },
        {
            "citation": "HIPAA §164.502 — Uses and disclosures of protected health information",
            "body": "HHS / HIPAA Privacy Rule",
            "url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.502",
        },
        {
            "citation": "HITECH Act §13402 — Notification in the case of breach",
            "body": "HHS / HITECH",
            "url": "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html",
        },
    ],
    "FIN-02": [
        {
            "citation": "PCI DSS v4.0 Requirement 3 — Protect stored account data",
            "body": "PCI Security Standards Council",
            "url": "https://www.pcisecuritystandards.org/document_library/",
        },
        {
            "citation": "GLBA §6802 — Obligations regarding disclosure of personal information",
            "body": "US Federal / Gramm-Leach-Bliley Act",
            "url": "https://www.govinfo.gov/content/pkg/USCODE-2018-title15/pdf/USCODE-2018-title15-chap94-subchapI-sec6802.pdf",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
    ],
    "SEC-01": [
        {
            "citation": "NIST AI RMF — GOVERN 1.1 (AI risk policies and procedures)",
            "body": "NIST AI Risk Management Framework",
            "url": "https://airc.nist.gov/Docs/1",
        },
        {
            "citation": "OWASP LLM Top 10 — LLM01: Prompt Injection",
            "body": "OWASP",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "citation": "EU AI Act Art. 9 — Risk management system",
            "body": "EU AI Act",
            "url": "https://artificialintelligenceact.eu/article/9/",
        },
    ],
    "GEN-03": [
        {
            "citation": "GDPR Art. 28 — Processor obligations and sub-processor controls",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-28-gdpr/",
        },
        {
            "citation": "HIPAA §164.314 — Business associate contracts and other arrangements",
            "body": "HHS / HIPAA Security Rule",
            "url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314",
        },
    ],
    "GEN-04": [
        {
            "citation": "FTC Act §5 — Unfair or deceptive acts or practices",
            "body": "US Federal Trade Commission",
            "url": "https://www.ftc.gov/legal-library/browse/statutes/federal-trade-commission-act",
        },
        {
            "citation": "EU AI Act Art. 13 — Transparency and provision of information to deployers",
            "body": "EU AI Act",
            "url": "https://artificialintelligenceact.eu/article/13/",
        },
    ],
    "GEN-05": [
        {
            "citation": "EU AI Act Art. 9 — Risk management system",
            "body": "EU AI Act",
            "url": "https://artificialintelligenceact.eu/article/9/",
        },
        {
            "citation": "ISO/IEC 42001:2023 §6.1 — Actions to address risks and opportunities",
            "body": "ISO/IEC",
            "url": "https://www.iso.org/standard/81230.html",
        },
    ],
}

PROFILE_RULES = {
    "General": {"health_confidence_boost": 0.0, "financial_confidence_boost": 0.0},
    "Public Sector": {"health_confidence_boost": 0.0, "financial_confidence_boost": 0.0},
    "Healthcare": {"health_confidence_boost": 0.06, "financial_confidence_boost": 0.0},
    "Finance": {"health_confidence_boost": 0.0, "financial_confidence_boost": 0.06},
}


def normalize_profile(profile: Optional[str]) -> str:
    if not profile:
        return "General"

    cleaned = profile.strip().lower()
    return PROFILE_ALIASES.get(cleaned, "General")


def _clip_confidence(value: float) -> float:
    return max(0.0, min(0.99, round(value, 2)))


def _confidence_label(value: float) -> str:
    if value >= 0.93:
        return "High"
    if value >= 0.8:
        return "Medium"
    return "Low"


def _severity_rank(value: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(value, 0)


def _overall_severity(findings: list[Finding]) -> str:
    if any(f.severity == "high" for f in findings):
        return "high"
    if any(f.severity == "medium" for f in findings):
        return "medium"
    return "low"


def _snippet(text: str, start: int, end: int, padding: int = 18) -> str:
    left = max(0, start - padding)
    right = min(len(text), end + padding)
    return text[left:right].strip()


def _location(text: str, start: int) -> str:
    line = text.count("\n", 0, start) + 1
    line_start = text.rfind("\n", 0, start)
    column = start + 1 if line_start == -1 else start - line_start
    return f"Line {line}, char {column}"


def _confidence_explanation(value: float, signal: str) -> str:
    label = _confidence_label(value)
    if label == "High":
        return f"High confidence because the content matched a strong {signal.lower()} signal."
    if label == "Medium":
        return f"Medium confidence because the content matched a likely {signal.lower()} signal that should be reviewed."
    return f"Low confidence because the signal is weaker and needs human validation."


def _mask_ssn(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "***-**-****"
    return f"***-**-{digits[-4:]}"


def _mask_email(value: str) -> str:
    return "[email redacted]"


def _mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"***-***-{digits[-4:]}"
    return "***-***-****"


def _mask_address(value: str) -> str:
    return "[street address redacted]"


def _mask_credit_card(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "****"
    return f"**** **** **** {digits[-4:]}"


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []

    for finding in findings:
        key = (finding.type, finding.reason_code, finding.example)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    return sorted(unique, key=lambda finding: (-_severity_rank(finding.severity), -finding.confidence, finding.type))


def _has_clinical_context(text: str, start: int, end: int) -> bool:
    window_start = max(0, start - 80)
    window_end = min(len(text), end + 80)
    window = text[window_start:window_end]
    return bool(re.search(r"\b(?:patient|diagnosis|diagnosed|treatment|medication|prescription|mrn|medical record|phi|hipaa)\b", window, re.IGNORECASE))


def _make_finding(
    *,
    type: str,
    reason_code: str,
    rule_id: str,
    severity: str,
    confidence: float,
    signal: str,
    location: str,
    example: str,
    rationale: str,
    recommended_action: str,
) -> Finding:
    confidence = _clip_confidence(confidence)
    regulatory_references = [
        RegulatoryReference(**ref)
        for ref in REGULATORY_CITATIONS.get(rule_id, [])
    ]
    return Finding(
        type=type,
        reason_code=reason_code,
        reason_label=REASON_LABELS[reason_code],
        rule_id=rule_id,
        rule_label=RULE_LABELS[rule_id],
        severity=severity,
        confidence=confidence,
        confidence_label=_confidence_label(confidence),
        confidence_explanation=_confidence_explanation(confidence, signal),
        signal=signal,
        location=location,
        example=example,
        rationale=rationale,
        recommended_action=recommended_action,
        regulatory_references=regulatory_references,
    )


def analyze(text: str, profile: str = "General") -> list[Finding]:
    text = text[:INPUT_LIMIT]
    profile = normalize_profile(profile)
    profile_rules = PROFILE_RULES[profile]
    findings: list[Finding] = []

    for match in _EMAIL.finditer(text):
        findings.append(_make_finding(
            type="EMAIL ADDRESS",
            reason_code="PII",
            rule_id="PII-02",
            severity="medium",
            confidence=0.96,
            signal="Email pattern",
            location=_location(text, match.start()),
            example=_mask_email(match.group()),
            rationale="A direct email address was detected, which is treated as sensitive contact information.",
            recommended_action="Remove or mask the email address before sending the content downstream.",
        ))

    for match in _SSN.finditer(text):
        findings.append(_make_finding(
            type="SOCIAL SECURITY NUMBER",
            reason_code="PII",
            rule_id="PII-03",
            severity="high",
            confidence=0.99,
            signal="SSN pattern",
            location=_location(text, match.start()),
            example=_mask_ssn(match.group()),
            rationale="The content matches a Social Security number pattern.",
            recommended_action="Block the payload until the SSN is fully redacted.",
        ))

    for match in _PHONE.finditer(text):
        findings.append(_make_finding(
            type="PHONE NUMBER",
            reason_code="PII",
            rule_id="PII-02",
            severity="medium",
            confidence=0.90,
            signal="Phone number pattern",
            location=_location(text, match.start()),
            example=_mask_phone(match.group()),
            rationale="A phone number was detected and should be reviewed before production use.",
            recommended_action="Verify the number is necessary, or redact it before sharing.",
        ))

    for match in _STREET_ADDRESS.finditer(text):
        findings.append(_make_finding(
            type="STREET ADDRESS",
            reason_code="PII",
            rule_id="PII-01",
            severity="medium",
            confidence=0.88,
            signal="Street address pattern",
            location=_location(text, match.start()),
            example=_snippet(text, match.start(), match.end()),
            rationale="A physical mailing or street address was detected.",
            recommended_action="Remove the address unless the workflow explicitly requires it.",
        ))

    for match in _CITY_STATE_ZIP.finditer(text):
        findings.append(_make_finding(
            type="LOCATION DETAIL",
            reason_code="PII",
            rule_id="PII-01",
            severity="medium",
            confidence=0.82,
            signal="City/state/ZIP pattern",
            location=_location(text, match.start()),
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
        rule_id = "PHI-01" if _has_clinical_context(text, name_match.start(1), dob_match.end()) else "PII-03"
        findings.append(_make_finding(
            type="NAME + DOB COMBINATION",
            reason_code="HEALTH" if rule_id == "PHI-01" else "PII",
            rule_id=rule_id,
            severity="high",
            confidence=0.98 if rule_id == "PHI-01" else 0.97,
            signal="Patient identity and date-of-birth pattern" if rule_id == "PHI-01" else "Name and date-of-birth pattern",
            location=_location(text, min(name_match.start(1), dob_match.start())),
            example=f"{name_match.group(1)} / {dob_match.group().strip()}",
            rationale="A named individual appears alongside a date-of-birth reference, which creates a direct identifying record." if rule_id == "PII-03" else "A patient identity marker appears alongside a date-of-birth reference in clinical context, which raises PHI exposure risk.",
            recommended_action="Block or heavily redact personal identity details before proceeding." if rule_id == "PII-03" else "Block the payload and remove patient-linked clinical identity details before proceeding.",
        ))
    elif dob_match:
        findings.append(_make_finding(
            type="DATE OF BIRTH",
            reason_code="PII",
            rule_id="PII-03",
            severity="medium",
            confidence=0.91,
            signal="Date-of-birth pattern",
            location=_location(text, dob_match.start()),
            example=dob_match.group().strip(),
            rationale="A date-of-birth reference was detected and should be reviewed as personal information.",
            recommended_action="Redact or confirm that DOB data is approved for this workflow.",
        ))

    for match in _INJECTION.finditer(text):
        findings.append(_make_finding(
            type="PROMPT INJECTION",
            reason_code="PROMPT_INJECTION",
            rule_id="SEC-01",
            severity="high",
            confidence=0.99,
            signal="Prompt injection phrase",
            location=_location(text, match.start()),
            example=match.group(),
            rationale="The text contains language associated with attempts to override or expose model instructions.",
            recommended_action="Block the request and remove the adversarial instruction before retrying.",
        ))

    for match in _OVERCLAIM.finditer(text):
        findings.append(_make_finding(
            type="OVERCLAIM LANGUAGE",
            reason_code="UNSUPPORTED_CLAIM",
            rule_id="GEN-04",
            severity="medium",
            confidence=0.83,
            signal="Unsupported certainty language",
            location=_location(text, match.start()),
            example=match.group(),
            rationale="Absolute certainty language can create policy or trust risk and should be qualified.",
            recommended_action="Route to review and replace absolute claims with evidence-backed wording.",
        ))

    for match in _UNVERIFIED.finditer(text):
        findings.append(_make_finding(
            type="UNVERIFIED OR INCOMPLETE CLAIM",
            reason_code="INCOMPLETE_EVIDENCE",
            rule_id="GEN-05",
            severity="medium",
            confidence=0.81,
            signal="Incomplete evidence phrase",
            location=_location(text, match.start()),
            example=match.group(),
            rationale="The content explicitly signals missing verification, documentation, or incomplete evidence and should not be treated as fully cleared.",
            recommended_action="Route to review and confirm the missing support before using this content in a live workflow.",
        ))

    for match in _EXTERNAL_SHARING.finditer(text):
        findings.append(_make_finding(
            type="EXTERNAL SHARING INSTRUCTION",
            reason_code="EXTERNAL_SHARING",
            rule_id="GEN-03",
            severity="high" if any(f.reason_code in {"PII", "HEALTH", "FINANCIAL"} for f in findings) else "medium",
            confidence=0.86,
            signal="External sharing phrase",
            location=_location(text, match.start()),
            example=match.group(),
            rationale="The content includes language suggesting broad or external sharing, which raises governance risk when sensitive material is present.",
            recommended_action="Restrict distribution to approved internal channels and remove external sharing instructions before use.",
        ))

    for match in _CREDIT_CARD.finditer(text):
        findings.append(_make_finding(
            type="CREDIT CARD NUMBER",
            reason_code="FINANCIAL",
            rule_id="FIN-02",
            severity="high",
            confidence=0.95 + profile_rules["financial_confidence_boost"],
            signal="Payment card pattern",
            location=_location(text, match.start()),
            example=_mask_credit_card(match.group()),
            rationale="A payment card pattern was detected in the submitted content.",
            recommended_action="Remove the card number or replace it with a tokenized value.",
        ))

    for match in _BANK_ACCOUNT.finditer(text):
        findings.append(_make_finding(
            type="BANK ACCOUNT DETAIL",
            reason_code="FINANCIAL",
            rule_id="FIN-02",
            severity="high" if profile == "Finance" else "medium",
            confidence=0.89 + profile_rules["financial_confidence_boost"],
            signal="Bank account or routing pattern",
            location=_location(text, match.start()),
            example=match.group(),
            rationale="Banking or routing details were detected and can expose sensitive financial data.",
            recommended_action="Block or redact the account details before this content is shared.",
        ))

    for match in _HEALTH_DATA.finditer(text):
        severity = "high" if profile == "Healthcare" and match.group().lower() in {"phi", "hipaa", "medical record", "mrn"} else "medium"
        findings.append(_make_finding(
            type="HEALTH DATA SIGNAL",
            reason_code="HEALTH",
            rule_id="PHI-01",
            severity=severity,
            confidence=0.84 + profile_rules["health_confidence_boost"],
            signal="Healthcare terminology signal",
            location=_location(text, match.start()),
            example=match.group(),
            rationale="Healthcare-oriented language suggests the content may contain patient or protected health information.",
            recommended_action="Review for PHI exposure and redact medical details before use.",
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


def summarize_risk(findings: list[Finding]) -> tuple[str, float, str]:
    if not findings:
        confidence = 0.98
        return ("low", confidence, _confidence_label(confidence))

    confidence = max(f.confidence for f in findings)
    severity = _overall_severity(findings)
    return (severity, confidence, _confidence_label(confidence))


def safe_for_use_after_redaction(text: str, profile: str = "General") -> bool:
    redacted_preview = build_redacted_preview(text)
    if not redacted_preview:
        return not analyze(text, profile)

    remaining_findings = analyze(redacted_preview, profile)
    return len(remaining_findings) == 0


def build_redacted_preview(text: str) -> Optional[str]:
    redacted = text[:INPUT_LIMIT]

    replacements = [
        (_EMAIL, lambda match: _mask_email(match.group())),
        (_SSN, lambda match: _mask_ssn(match.group())),
        (_PHONE, lambda match: _mask_phone(match.group())),
        (_STREET_ADDRESS, lambda match: _mask_address(match.group())),
        (_CREDIT_CARD, lambda match: _mask_credit_card(match.group())),
        (_BANK_ACCOUNT, lambda match: "[financial account redacted]"),
    ]

    for pattern, repl in replacements:
        redacted = pattern.sub(repl, redacted)

    return redacted if redacted != text[:INPUT_LIMIT] else None
