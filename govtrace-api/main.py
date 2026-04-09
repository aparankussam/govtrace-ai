import os
import random
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

try:
    from .engine import analyze, build_redacted_preview, normalize_profile, safe_for_use_after_redaction, summarize_risk, verdict
    from .models import AuditRequest, AuditResponse, AuditSummary, HistoryEntry, HistoryResponse
    from . import store
except ImportError:
    from engine import analyze, build_redacted_preview, normalize_profile, safe_for_use_after_redaction, summarize_risk, verdict
    from models import AuditRequest, AuditResponse, AuditSummary, HistoryEntry, HistoryResponse
    import store


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
        return [
            "https://govtrace.gobotsai.com",
            "https://govtrace-ai.vercel.app",
        ]

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

    site_url_origin = _normalize_origin(os.getenv("GOVTRACE_SITE_URL", "").strip())
    if site_url_origin and site_url_origin not in normalized:
        normalized.append(site_url_origin)

    return normalized if normalized else _default_allowed_origins()


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_id(now: datetime | None = None) -> str:
    current = now or datetime.now(timezone.utc)
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

# Initialise audit DB at startup (no-op if storage is disabled).
store.init_db()

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
    safe_after_redaction = safe_for_use_after_redaction(req.text, profile)
    response = AuditResponse(
        run_id=_run_id(),
        timestamp=timestamp,
        profile=profile,
        status=status,
        message=message,
        overall_severity=overall_severity,
        overall_confidence=overall_confidence,
        overall_confidence_label=overall_confidence_label,
        overall_confidence_explanation=_overall_confidence_explanation(overall_confidence_label, len(findings)),
        safe_after_redaction=safe_after_redaction,
        audit_summary=AuditSummary(
            timestamp=timestamp,
            profile_used=profile,
            verdict=status,
            finding_count=len(findings),
        ),
        redacted_preview=redacted_preview,
        findings=findings,
    )

    # Persist the run. Never raises — failures are logged inside store.persist()
    # and do not affect the response returned to the caller.
    store.persist(
        response_dict=response.model_dump(mode="json"),
        raw_input_hash=store.input_hash(req.text),
        input_length=len(req.text),
    )

    return response


@app.get("/audit/history", response_model=HistoryResponse)
def audit_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
    profile: str | None = Query(default=None),
) -> HistoryResponse:
    """
    Return a paginated list of past audit runs (summary rows only, no findings).

    Query params:
      limit   — rows per page (1–200, default 50)
      offset  — rows to skip (default 0)
      status  — filter by status: COMPLIANT | NEEDS REVIEW | POLICY VIOLATION
      profile — filter by profile: General | Healthcare | Finance | Public Sector
    """
    if not store.STORAGE_ENABLED:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "audit_storage_unavailable",
                "message": (
                    "Audit history is not available in this deployment. "
                    "Set GOVTRACE_DB_PATH to a persistent volume path to enable it."
                ),
            },
        )

    total, rows = store.get_history(
        limit=limit,
        offset=offset,
        status_filter=status,
        profile_filter=profile,
    )

    entries = [
        HistoryEntry(
            run_id=r["run_id"],
            timestamp=r["timestamp"],
            profile=r["profile"],
            status=r["status"],
            overall_severity=r["overall_severity"],
            overall_confidence=float(r["overall_confidence"]),
            safe_after_redaction=bool(r["safe_after_redaction"]),
            input_hash=r["input_hash"],
            input_length=int(r["input_length"]),
            finding_count=int(r["finding_count"]),
        )
        for r in rows
    ]

    return HistoryResponse(total=total, limit=limit, offset=offset, runs=entries)


@app.get("/audit/{run_id}", response_model=AuditResponse)
def get_audit_run(run_id: str) -> AuditResponse:
    """
    Retrieve the full stored AuditResponse for a past run by its run_id.

    Returns 404 if the run_id is not found.
    Returns 503 if audit storage is not configured for this deployment.
    """
    if not store.STORAGE_ENABLED:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "audit_storage_unavailable",
                "message": (
                    "Audit history is not available in this deployment. "
                    "Set GOVTRACE_DB_PATH to a persistent volume path to enable it."
                ),
            },
        )

    data = store.get_run(run_id)
    if data is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "run_not_found",
                "message": f"No audit run found with run_id '{run_id}'.",
            },
        )

    return AuditResponse.model_validate(data)
