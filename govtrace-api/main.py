import hashlib
import json
import os
import random
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

try:
    from .engine import (
        INPUT_LIMIT,
        POLICY_BUNDLE_DIGEST,
        RULE_LABELS,
        analyze,
        build_redacted_preview,
        compute_blocking_classes,
        compute_reason_line,
        compute_residual_risk,
        compute_safe_harbor,
        enforcement_decisions,
        input_had_blocking_class,
        normalize_profile,
        safe_for_use_after_redaction,
        summarize_risk,
        verdict,
        verdict_code,
    )
    from .models import (
        AuditRequest,
        AuditResponse,
        AuditSummary,
        DecisionBlock,
        DutyOfCareRecord,
        EnforcementBlock,
        GovernanceBlock,
        HistoryEntry,
        HistoryResponse,
        InputMeta,
        IntegrityBlock,
        PolicyTrace,
        ReceiptBlock,
        ResidualRiskBlock,
        SafeHarborBlock,
        SystemContext,
        UserContext,
    )
    from . import corpus_eval, receipt_pdf, signing, store
except ImportError:
    from engine import (
        INPUT_LIMIT,
        POLICY_BUNDLE_DIGEST,
        RULE_LABELS,
        analyze,
        build_redacted_preview,
        compute_blocking_classes,
        compute_reason_line,
        compute_residual_risk,
        compute_safe_harbor,
        enforcement_decisions,
        input_had_blocking_class,
        normalize_profile,
        safe_for_use_after_redaction,
        summarize_risk,
        verdict,
        verdict_code,
    )
    from models import (
        AuditRequest,
        AuditResponse,
        AuditSummary,
        DecisionBlock,
        DutyOfCareRecord,
        EnforcementBlock,
        GovernanceBlock,
        HistoryEntry,
        HistoryResponse,
        InputMeta,
        IntegrityBlock,
        PolicyTrace,
        ReceiptBlock,
        ResidualRiskBlock,
        SafeHarborBlock,
        SystemContext,
        UserContext,
    )
    import corpus_eval
    import receipt_pdf
    import signing
    import store

DOCR_POLICY_VERSION = "govtrace-policy-v1.1.0"
# Raw-input retention gate. Default OFF — the DoCR itself must not become a
# copy of the sensitive payload it is auditing. Opt in explicitly per-tenant
# only when downstream workflow genuinely requires the original text.
STORE_RAW_INPUT = os.getenv("GOVTRACE_STORE_RAW_INPUT", "false").strip().lower() == "true"
DOCR_DISCLAIMER = (
    "GovTraceAI Duty-of-Care Record. Automated policy intelligence for reviewer workflows. "
    "Not legal, medical, or regulatory advice. Retain with your audit trail."
)
DOCR_RETENTION_POLICY = "Retain for 90 days in reviewer audit trail (demo default)."
DOCR_JURISDICTION: str | None = None
DOCR_HASH_ALGORITHM = "SHA-256"
DOCR_ENGINE = "rules"
DOCR_DETERMINISTIC = True  # Policy decision is deterministic given {input, profile, policy_version}.
SYSTEM_VERSION = "1.0.0"

# Status -> decision_type mapping. Uses existing status vocabulary; does not
# rename anything product-wide.
_DECISION_TYPE_BY_STATUS = {
    "COMPLIANT": "automated",
    "NEEDS REVIEW": "requires_review",
    "POLICY VIOLATION": "blocked",
}


def _canonical_json(payload) -> str:
    """Stable JSON encoding for hashing: sorted keys, compact separators."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _request_fingerprint(input_text: str, profile: str, policy_version: str) -> str:
    return _sha256_hex(_canonical_json({
        "input": input_text,
        "profile": profile,
        "policy_version": policy_version,
    }))


def _current_user_context() -> UserContext:
    """
    Placeholder identity context. GovTraceAI has no auth layer yet, so emit a
    structured stub rather than silently inventing a user. Swap in real
    identity resolution here when auth lands.
    """
    return UserContext(authenticated=False, user_id=None, org_id=None, role=None)


def _distinct_ordered(items) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


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

# Evaluate the labeled corpus once at startup and cache the full result.
# /health surfaces a small summary; /metrics/corpus serves the full report.
# Re-evaluation is cheap (~50 pure-regex passes) but we still cache to keep
# health checks fast and deterministic between deploys.
_CORPUS_METRICS: dict = corpus_eval.evaluate()

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
        "policy_version": DOCR_POLICY_VERSION,
        "policy_digest": POLICY_BUNDLE_DIGEST,
        "corpus": corpus_eval.summary(_CORPUS_METRICS),
    }


@app.get("/.well-known/govtrace-pubkey.json")
def well_known_pubkey() -> dict:
    """
    Publish the Ed25519 public key used to sign every DoCR's `record_hash`.

    Intended for offline verification: a holder of any signed DoCR can fetch
    this once, pin it, and thereafter verify signatures without ever calling
    the GovTraceAI API again. That property — verifiability without vendor
    availability — is the point.
    """
    return signing.public_key_info()


@app.get("/metrics/corpus")
def metrics_corpus(refresh: bool = Query(default=False)):
    """Full labeled-corpus evaluation: per-rule + per-category metrics and
    the list of any failing cases. `?refresh=true` forces re-evaluation
    against the current engine (useful after a rules_override.json edit)."""
    global _CORPUS_METRICS
    if refresh:
        _CORPUS_METRICS = corpus_eval.evaluate()
    return _CORPUS_METRICS


@app.post("/audit", response_model=AuditResponse)
def audit(req: AuditRequest) -> AuditResponse:
    profile = normalize_profile(req.profile)
    findings = analyze(req.text, profile)
    status, message = verdict(findings)
    overall_severity, overall_confidence, overall_confidence_label = summarize_risk(findings)
    redacted_preview = build_redacted_preview(req.text) if status != "COMPLIANT" else None
    timestamp = _timestamp_utc()
    safe_after_redaction = safe_for_use_after_redaction(req.text, profile)

    raw_input_hash = store.input_hash(req.text)
    input_meta = InputMeta(
        input_length=len(req.text),
        byte_length=len(req.text.encode("utf-8")),
        truncated=len(req.text) > INPUT_LIMIT,
        input_hash=raw_input_hash,
    )
    enforcement = EnforcementBlock(**enforcement_decisions(findings))
    had_blocking_class = input_had_blocking_class(findings)
    residual_risk = ResidualRiskBlock(**compute_residual_risk(
        findings,
        had_blocking_class=had_blocking_class,
        safe_after_redaction=safe_after_redaction,
    ))

    verdict_code_value = verdict_code(status)
    reason_line = compute_reason_line(findings, verdict_code_value)
    blocking_classes = compute_blocking_classes(findings)
    # SHA-256 of the exact bytes of `redacted_preview` so downstream systems
    # can hash their egress payload and prove it matches what we approved.
    # Hashed over UTF-8 bytes of the empty string when there's no preview, to
    # avoid branching downstream on `null`.
    redacted_output_hash = hashlib.sha256((redacted_preview or "").encode("utf-8")).hexdigest()

    # HIPAA Safe Harbor attestation is Healthcare-profile only. Computed against
    # the redacted preview when present, falling back to the original input when
    # there was nothing to redact (a truly clean clinical paragraph).
    safe_harbor_block: Optional[SafeHarborBlock] = None
    if profile == "Healthcare":
        safe_harbor_block = compute_safe_harbor(req.text, redacted_preview if redacted_preview is not None else req.text)

    response = AuditResponse(
        run_id=_run_id(),
        timestamp=timestamp,
        profile=profile,
        status=status,
        message=message,
        verdict_code=verdict_code_value,
        overall_severity=overall_severity,
        overall_confidence=overall_confidence,
        overall_confidence_label=overall_confidence_label,
        overall_confidence_explanation=_overall_confidence_explanation(overall_confidence_label, len(findings)),
        safe_after_redaction=safe_after_redaction,
        input_had_blocking_class=had_blocking_class,
        reason_line=reason_line,
        blocking_classes=blocking_classes,
        redacted_output_hash=redacted_output_hash,
        input_meta=input_meta,
        enforcement=enforcement,
        residual_risk=residual_risk,
        safe_harbor=safe_harbor_block,
        audit_summary=AuditSummary(
            timestamp=timestamp,
            profile_used=profile,
            verdict=status,
            finding_count=len(findings),
        ),
        redacted_preview=redacted_preview,
        findings=findings,
    )

    # --- Build Duty-of-Care Record ---------------------------------------
    # Order is load-bearing:
    #   1. assemble the full DoCR WITHOUT the `integrity` block
    #   2. compute record_hash over the canonical JSON of that DoCR
    #   3. attach `integrity`
    #   4. attach to response and persist (so the persisted snapshot
    #      matches the wire response byte-for-byte at the DoCR level)
    policies_evaluated = sorted(RULE_LABELS.keys())
    rules_triggered = _distinct_ordered(f.rule_id for f in findings)
    rules_passed = [rid for rid in policies_evaluated if rid not in set(rules_triggered)]

    decision = DecisionBlock(
        verdict=status,
        decision_type=_DECISION_TYPE_BY_STATUS.get(status, "requires_review"),
        severity=overall_severity,
        confidence=overall_confidence,
        confidence_label=overall_confidence_label,
    )

    governance = GovernanceBlock(
        policy_version=DOCR_POLICY_VERSION,
        disclaimer=DOCR_DISCLAIMER,
        retention_policy=DOCR_RETENTION_POLICY,
        jurisdiction=DOCR_JURISDICTION,
        policy_digest=POLICY_BUNDLE_DIGEST,
    )

    system_ctx = SystemContext(
        system_version=SYSTEM_VERSION,
        environment=APP_ENV,
        engine=DOCR_ENGINE,
    )

    docr = DutyOfCareRecord(
        id=str(uuid.uuid4()),
        timestamp=timestamp,
        # Raw input is stored ONLY when GOVTRACE_STORE_RAW_INPUT=true. Default
        # path keeps the DoCR content-free so the audit trail cannot itself
        # become a copy of the payload it is auditing.
        input=req.text if STORE_RAW_INPUT else None,
        input_hash=raw_input_hash,
        input_length=len(req.text),
        output={
            "run_id": response.run_id,
            "status": status,
            "message": message,
            "verdict_code": verdict_code_value,
            "profile": profile,
            "overall_severity": overall_severity,
            "overall_confidence": overall_confidence,
            "overall_confidence_label": overall_confidence_label,
            "safe_after_redaction": safe_after_redaction,
            "input_had_blocking_class": had_blocking_class,
            "reason_line": reason_line,
            "blocking_classes": blocking_classes,
            "redacted_preview": redacted_preview,
            "redacted_output_hash": redacted_output_hash,
            "safe_harbor": safe_harbor_block.model_dump(mode="json") if safe_harbor_block is not None else None,
        },
        verdict=status,
        findings=findings,
        policy_version=DOCR_POLICY_VERSION,
        disclaimer=DOCR_DISCLAIMER,
        user=_current_user_context(),
        system=system_ctx,
        decision=decision,
        policy_trace=PolicyTrace(
            policies_evaluated=policies_evaluated,
            rules_triggered=rules_triggered,
            rules_passed=rules_passed,
        ),
        governance=governance,
    )

    # Hash the DoCR *without* integrity, then attach integrity. The chain
    # link (previous record_hash) is part of the hashed payload so that
    # tampering with either the DoCR body OR the chain pointer breaks the
    # hash — that's what makes the ledger tamper-evident.
    chain_prev_hash = store.get_latest_record_hash()
    pre_integrity_payload = docr.model_dump(mode="json", exclude={"integrity"})
    pre_integrity_payload["chain_prev_hash"] = chain_prev_hash
    record_hash = _sha256_hex(_canonical_json(pre_integrity_payload))
    # Sign the record_hash. Signature is over the RAW hash bytes, not the hex
    # string — see signing._record_hash_bytes. Including the signature inside
    # integrity (but NOT inside the signed body) is intentional: the signature
    # attests to the record_hash, so it has to sit outside the bytes it signs.
    record_signature = signing.sign_record_hash(record_hash)
    docr.integrity = IntegrityBlock(
        record_hash=record_hash,
        hash_algorithm=DOCR_HASH_ALGORITHM,
        request_fingerprint=_request_fingerprint(req.text, profile, DOCR_POLICY_VERSION),
        deterministic=DOCR_DETERMINISTIC,
        chain_prev_hash=chain_prev_hash,
        signature=record_signature,
        signature_algo=signing.SIGNATURE_ALGO,
        public_key_id=signing.PUBLIC_KEY_ID,
    )

    response.duty_of_care_record = docr

    # --- Build Signed Verdict Receipt ------------------------------------
    # Narrower than the DoCR's record_hash signature: this signs just the six
    # externally-visible fields an auditor quotes. A verifier can check it
    # against /.well-known/govtrace-pubkey.json WITHOUT holding the full DoCR.
    receipt_signed_fields = {
        "run_id": response.run_id,
        "verdict": status,
        "record_hash": record_hash,
        "policy_digest": POLICY_BUNDLE_DIGEST,
        "input_hash": raw_input_hash,
        "timestamp": timestamp,
    }
    # Healthcare-profile PASS attestations bind the Safe Harbor result into the
    # signed receipt so auditors can quote the attestation without the full
    # DoCR. Missing / FAIL is deliberately left out — we sign only what we're
    # willing to stand behind externally.
    if safe_harbor_block is not None and safe_harbor_block.attestation == "PASS":
        receipt_signed_fields["safe_harbor_method"] = safe_harbor_block.method
        receipt_signed_fields["safe_harbor_attestation"] = "PASS"
    canonical_digest, receipt_signature = signing.sign_receipt(receipt_signed_fields)
    response.receipt = ReceiptBlock(
        receipt_id=f"rcpt_{response.run_id}",
        signed_at=timestamp,
        signature_algo=signing.SIGNATURE_ALGO,
        signature=receipt_signature,
        public_key_id=signing.PUBLIC_KEY_ID,
        signed_fields=list(receipt_signed_fields.keys()),
        canonical_digest=canonical_digest,
        pdf_url=f"/audit/{response.run_id}/receipt.pdf",
        verify_url=f"/audit/verify/{response.run_id}",
    )

    # Persist the run. Never raises — failures are logged inside store.persist()
    # and do not affect the response returned to the caller.
    store.persist(
        response_dict=response.model_dump(mode="json"),
        raw_input_hash=raw_input_hash,
        input_length=len(req.text),
        record_hash=record_hash,
        chain_prev_hash=chain_prev_hash,
    )

    return response


def _recompute_record_hash(docr_dict: dict) -> str:
    """Re-derive record_hash from a persisted DoCR exactly as /audit did at
    write time: canonical JSON of (DoCR minus integrity) plus chain_prev_hash."""
    integrity = docr_dict.get("integrity") or {}
    body = {k: v for k, v in docr_dict.items() if k != "integrity"}
    body["chain_prev_hash"] = integrity.get("chain_prev_hash")
    return _sha256_hex(_canonical_json(body))


@app.get("/audit/verify/{run_id}")
def audit_verify(run_id: str) -> dict:
    """
    Walk the hash chain backward from the given run to the genesis record,
    re-computing each record's hash, verifying that each chain_prev_hash
    points to the actual predecessor's record_hash, AND validating each
    record's Ed25519 signature against the server's published public key.

    Signature verification is best-effort backward-compatible: records written
    before signing rolled out have `signature=None` and are reported under
    `signatures_missing` without marking the chain as broken. Records that
    DO carry a signature must verify — any mismatch fails the chain.

    Returns a summary with {verified, chain_length, signatures_verified,
    signatures_missing, failed_at_run_id, failure_reason}.
    """
    if not store.STORAGE_ENABLED:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "audit_storage_unavailable",
                "message": (
                    "Audit verification requires persistent storage. "
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

    chain_length = 0
    signatures_verified = 0
    signatures_missing = 0
    visited: set[str] = set()
    current_run_id = run_id
    current_response = data

    while True:
        docr = (current_response or {}).get("duty_of_care_record")
        if not docr:
            return {
                "verified": False,
                "chain_length": chain_length,
                "signatures_verified": signatures_verified,
                "signatures_missing": signatures_missing,
                "failed_at_run_id": current_run_id,
                "failure_reason": "record has no duty_of_care_record to verify",
            }

        integrity = docr.get("integrity") or {}
        stored_hash = integrity.get("record_hash")
        if not stored_hash:
            return {
                "verified": False,
                "chain_length": chain_length,
                "signatures_verified": signatures_verified,
                "signatures_missing": signatures_missing,
                "failed_at_run_id": current_run_id,
                "failure_reason": "record has no integrity.record_hash",
            }

        recomputed = _recompute_record_hash(docr)
        if recomputed != stored_hash:
            return {
                "verified": False,
                "chain_length": chain_length,
                "signatures_verified": signatures_verified,
                "signatures_missing": signatures_missing,
                "failed_at_run_id": current_run_id,
                "failure_reason": "record_hash mismatch (record or chain pointer tampered)",
            }

        sig = integrity.get("signature")
        if sig:
            if not signing.verify_record_hash_signature(stored_hash, sig):
                return {
                    "verified": False,
                    "chain_length": chain_length,
                    "signatures_verified": signatures_verified,
                    "signatures_missing": signatures_missing,
                    "failed_at_run_id": current_run_id,
                    "failure_reason": "signature invalid (record_hash does not match the published public key)",
                }
            signatures_verified += 1
        else:
            signatures_missing += 1

        chain_length += 1

        prev_hash = integrity.get("chain_prev_hash")
        if prev_hash is None:
            return {
                "verified": True,
                "chain_length": chain_length,
                "signatures_verified": signatures_verified,
                "signatures_missing": signatures_missing,
                "genesis_run_id": current_run_id,
                "tip_run_id": run_id,
                "public_key_id": signing.PUBLIC_KEY_ID,
                "signature_algo": signing.SIGNATURE_ALGO,
            }

        if prev_hash in visited:
            return {
                "verified": False,
                "chain_length": chain_length,
                "signatures_verified": signatures_verified,
                "signatures_missing": signatures_missing,
                "failed_at_run_id": current_run_id,
                "failure_reason": "chain contains a cycle",
            }
        visited.add(prev_hash)

        predecessor = store.get_by_record_hash(prev_hash)
        if predecessor is None:
            return {
                "verified": False,
                "chain_length": chain_length,
                "signatures_verified": signatures_verified,
                "signatures_missing": signatures_missing,
                "failed_at_run_id": current_run_id,
                "failure_reason": f"chain_prev_hash {prev_hash[:12]}… points to a missing predecessor",
            }
        current_response = predecessor
        current_run_id = predecessor.get("run_id", "<unknown>")


@app.get("/audit/{run_id}/receipt.pdf")
def audit_receipt_pdf(run_id: str, request: Request) -> Response:
    """
    Render a one-page signed Verdict Receipt PDF for a past run.

    The cryptographic commitment is the JSON `receipt` on the /audit response;
    this endpoint is the HUMAN artifact for auditors and reviewers. For runs
    written after receipt-signing rolled out, we reuse the stored receipt
    fields verbatim. For legacy runs, we re-derive a receipt from the stored
    DoCR — Ed25519 signatures are deterministic, so a re-signed receipt
    produces the same signature bytes.
    """
    if not store.STORAGE_ENABLED:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "audit_storage_unavailable",
                "message": (
                    "Receipt PDFs require persistent storage. "
                    "Set GOVTRACE_DB_PATH to a persistent volume path."
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

    docr = data.get("duty_of_care_record") or {}
    integrity = docr.get("integrity") or {}
    governance = docr.get("governance") or {}

    record_hash = integrity.get("record_hash")
    if not record_hash:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "record_hash_missing",
                "message": "This run predates integrity hashing and cannot be receipt-signed.",
            },
        )

    policy_digest = governance.get("policy_digest") or POLICY_BUNDLE_DIGEST
    raw_input_hash = docr.get("input_hash") or data.get("input_meta", {}).get("input_hash") or ""
    timestamp = data.get("timestamp") or docr.get("timestamp") or ""
    verdict_value = data.get("status") or docr.get("verdict") or "UNKNOWN"

    receipt = data.get("receipt")
    if not receipt:
        signed_fields_data = {
            "run_id": run_id,
            "verdict": verdict_value,
            "record_hash": record_hash,
            "policy_digest": policy_digest,
            "input_hash": raw_input_hash,
            "timestamp": timestamp,
        }
        canonical_digest, receipt_signature = signing.sign_receipt(signed_fields_data)
        receipt = {
            "receipt_id": f"rcpt_{run_id}",
            "signed_at": timestamp,
            "signature_algo": signing.SIGNATURE_ALGO,
            "signature": receipt_signature,
            "public_key_id": signing.PUBLIC_KEY_ID,
            "signed_fields": list(signed_fields_data.keys()),
            "canonical_digest": canonical_digest,
            "pdf_url": f"/audit/{run_id}/receipt.pdf",
            "verify_url": f"/audit/verify/{run_id}",
        }

    verify_base_url = str(request.base_url).rstrip("/")

    pdf_bytes = receipt_pdf.render_receipt_pdf(
        run_id=run_id,
        timestamp=timestamp,
        profile=data.get("profile") or "General",
        verdict=verdict_value,
        message=data.get("message") or "",
        overall_severity=data.get("overall_severity") or "—",
        overall_confidence=data.get("overall_confidence"),
        finding_count=len(data.get("findings") or []),
        record_hash=record_hash,
        policy_digest=policy_digest,
        input_hash=raw_input_hash,
        chain_prev_hash=integrity.get("chain_prev_hash"),
        receipt=receipt,
        verify_base_url=verify_base_url,
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="govtrace-receipt-{run_id}.pdf"',
            "Cache-Control": "no-store",
        },
    )


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
