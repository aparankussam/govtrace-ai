import os
import random
from datetime import datetime
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

try:
    from .engine import analyze, build_redacted_preview, normalize_profile, safe_for_use_after_redaction, summarize_risk, verdict
    from .models import AuditRequest, AuditResponse, AuditSummary
except ImportError:
    from engine import analyze, build_redacted_preview, normalize_profile, safe_for_use_after_redaction, summarize_risk, verdict
    from models import AuditRequest, AuditResponse, AuditSummary


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _normalize_origin(origin: str) -> str | None:
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _default_allowed_origins() -> list[str]:
    if os.getenv("VERCEL_ENV"):
        return []

    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def _load_allowed_origins() -> list[str]:
    configured = _split_csv(os.getenv("GOVTRACE_ALLOWED_ORIGINS", ""))
    normalized: list[str] = []

    for origin in configured:
        cleaned = _normalize_origin(origin)
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)

    return normalized if normalized else _default_allowed_origins()


def _timestamp_utc() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _run_id(now: datetime | None = None) -> str:
    current = now or datetime.utcnow()
    return f"GT-{current.strftime('%Y%m%d')}-{random.randint(0, 9999):04d}"


def _overall_confidence_explanation(label: str, finding_count: int) -> str:
    if finding_count == 0:
        return "High confidence because no configured policy rules were triggered in this pass."
    if label == "High":
        return "High confidence because the strongest triggered rule matched a well-defined pattern."
    if label == "Medium":
        return "Medium confidence because the result includes strong indicators that still benefit from reviewer context."
    return "Low confidence because the result depends on weaker signals and should be validated by a reviewer."


APP_ENV = os.getenv(
    "GOVTRACE_APP_ENV",
    "production" if os.getenv("VERCEL_ENV") else "development",
)
SITE_URL = os.getenv("GOVTRACE_SITE_URL", "").strip().rstrip("/")
ALLOWED_ORIGINS = _load_allowed_origins()

app = FastAPI(title="GovTrace AI Guardrail", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "GovTrace AI Guardrail API",
        "environment": APP_ENV,
        "site_url": SITE_URL or None,
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "environment": APP_ENV,
        "allowed_origins": ALLOWED_ORIGINS,
    }


@app.post("/audit", response_model=AuditResponse)
def audit(req: AuditRequest) -> AuditResponse:
    profile = normalize_profile(req.profile)
    findings = analyze(req.text, profile)
    status, message = verdict(findings)
    overall_severity, overall_confidence, overall_confidence_label = summarize_risk(findings)
    redacted_preview = build_redacted_preview(req.text) if status != "COMPLIANT" else None
    timestamp = _timestamp_utc()
    safe_for_use = safe_for_use_after_redaction(req.text, profile)
    return AuditResponse(
        run_id=_run_id(),
        timestamp=timestamp,
        profile=profile,
        status=status,
        message=message,
        overall_severity=overall_severity,
        overall_confidence=overall_confidence,
        overall_confidence_label=overall_confidence_label,
        overall_confidence_explanation=_overall_confidence_explanation(overall_confidence_label, len(findings)),
        safe_for_use=safe_for_use,
        audit_summary=AuditSummary(
            timestamp=timestamp,
            profile_used=profile,
            verdict=status,
            finding_count=len(findings),
        ),
        redacted_preview=redacted_preview,
        findings=findings,
    )
