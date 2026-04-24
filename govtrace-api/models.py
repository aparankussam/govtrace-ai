from typing import Optional

from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    # Ingress limit is deliberately larger than the engine's single-pass
    # INPUT_LIMIT (10_000) so that oversized payloads are truncated INSIDE
    # the engine and surfaced as a GEN-TRUNCATED finding rather than silently
    # 422'd at the gateway.
    text: str = Field(min_length=1, max_length=100_000)
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
    # `example` is ALWAYS the masked value. It is persisted in the DoCR and the
    # hash chain, so leaking a raw PHI/credential span here would contradict
    # GOVTRACE_STORE_RAW_INPUT=false. The raw matched span is retained in
    # `example_raw` only when GOVTRACE_STORE_RAW_EVIDENCE=true.
    example: str
    example_type: str = ""
    example_raw: Optional[str] = None
    rationale: str
    recommended_action: str
    regulatory_references: list[RegulatoryReference] = Field(default_factory=list)


class AuditSummary(BaseModel):
    timestamp: str
    profile_used: str
    verdict: str
    finding_count: int


class IntegrityBlock(BaseModel):
    record_hash: str
    hash_algorithm: str
    request_fingerprint: str
    deterministic: bool
    # Tamper-evident chain: hash of the previous DoCR's record_hash, or None
    # for the genesis record. Callers verify by walking predecessors and
    # re-computing each record's hash from its DoCR body + chain_prev_hash.
    chain_prev_hash: Optional[str] = None
    # Ed25519 signature over the raw record_hash bytes (base64url, unpadded).
    # Together with `public_key_id` and `signature_algo` this turns the DoCR
    # into an offline-verifiable attestation — a holder can verify with just
    # the published public key and needs no access to the API. Optional so
    # records persisted before signing rolled out still deserialize.
    signature: Optional[str] = None
    signature_algo: Optional[str] = None
    public_key_id: Optional[str] = None


class UserContext(BaseModel):
    authenticated: bool = False
    user_id: Optional[str] = None
    org_id: Optional[str] = None
    role: Optional[str] = None


class SystemContext(BaseModel):
    system_version: str
    environment: str
    engine: str


class DecisionBlock(BaseModel):
    verdict: str
    decision_type: str
    severity: str
    confidence: float
    confidence_label: str


class PolicyTrace(BaseModel):
    policies_evaluated: list[str]
    rules_triggered: list[str]
    rules_passed: list[str]


class GovernanceBlock(BaseModel):
    policy_version: str
    disclaimer: str
    retention_policy: str
    jurisdiction: Optional[str] = None
    # SHA-256 over the canonical JSON of the loaded policy bundle
    # (RULE_LABELS + REGULATORY_CITATIONS + rules_override.json). Auditors
    # pin this value to detect silent rule changes between runs.
    policy_digest: Optional[str] = None


class DutyOfCareRecord(BaseModel):
    id: str
    timestamp: str
    # Raw input is stored ONLY when GOVTRACE_STORE_RAW_INPUT=true. Default is
    # off so the DoCR itself is not a copy of the sensitive payload it audits.
    input: Optional[str] = None
    input_hash: Optional[str] = None
    input_length: Optional[int] = None
    output: dict
    verdict: str
    findings: list[Finding]
    # Transitional top-level fields — duplicated inside `governance` for
    # backward compatibility. Will be deprecated in a future release.
    policy_version: str
    disclaimer: str
    # Upgraded audit-grade blocks
    user: Optional[UserContext] = None
    system: Optional[SystemContext] = None
    decision: Optional[DecisionBlock] = None
    policy_trace: Optional[PolicyTrace] = None
    governance: Optional[GovernanceBlock] = None
    integrity: Optional[IntegrityBlock] = None


class InputMeta(BaseModel):
    input_length: int      # character count of the original (untruncated) input
    byte_length: int       # UTF-8 byte length
    truncated: bool        # True if original length exceeded engine INPUT_LIMIT
    input_hash: str        # SHA-256 of the original input for correlation


class EnforcementBlock(BaseModel):
    # Vocabulary: blocked | review_required | allowed
    external_share: str
    vendor_share: str
    internal_use: str


class ResidualRiskBlock(BaseModel):
    """Continuous risk score in [0, 1] with pre- and post-redaction views.

    - score / band: risk remaining AFTER redaction and blocking-class gating.
    - raw_score / raw_band: risk from the original input, ignoring redaction.
    - components: explains how the score was assembled (base + density ± adjustments).

    Bands are derived from cutoffs defined in engine._RISK_BANDS. Callers should
    gate on (band, input_had_blocking_class) — the band alone is insufficient
    because a blocking class is never below the 0.65 floor even post-redaction.
    """
    score: float
    band: str
    raw_score: float
    raw_band: str
    components: dict


class SafeHarborBlock(BaseModel):
    """HIPAA Safe Harbor (45 CFR § 164.514(b)(2)) de-identification attestation.

    The Safe Harbor method requires 18 specific identifiers to be removed before
    health information is considered de-identified. This block maps each of the
    18 identifiers to a status so auditors can quote it verbatim:

      - "absent"            — not present in the original input
      - "detected"          — present and still present in the redacted preview
      - "detected_redacted" — present in the original, absent from the redacted preview
      - "out_of_scope"      — cannot be assessed from text alone (biometrics, photos)

    `attestation` is "PASS" only when every in-scope identifier is either `absent`
    or `detected_redacted` in the redacted preview. A single `detected` forces FAIL.
    When PASS, `attestation_statement` is a short sentence suitable for pasting
    into a DoCR or an exported receipt — it names the method and cites the rule.
    """
    method: str = "45 CFR § 164.514(b)(2)"
    attestation: str  # "PASS" | "FAIL"
    identifiers: dict[str, str]
    identifiers_detected: list[str] = Field(default_factory=list)
    identifiers_remaining_after_redaction: list[str] = Field(default_factory=list)
    attestation_statement: Optional[str] = None
    disclaimer: str = (
        "Biometrics (identifier 16) and full-face photographs (identifier 17) "
        "cannot be assessed from text input and are marked out_of_scope."
    )


class ReceiptBlock(BaseModel):
    """Compliance-facing signed attestation of a verdict.

    The `integrity` block on the DoCR already carries an Ed25519 signature over
    the record_hash (which commits to the full DoCR body). The receipt is a
    narrower, externally-oriented artifact: it signs a compact canonical JSON
    of just the six fields auditors actually quote — so a verifier can validate
    a receipt WITHOUT possession of the full DoCR. `canonical_digest` is the
    SHA-256 over that canonical JSON; the signature covers those raw digest
    bytes (matching how record_hash is signed). `pdf_url` / `verify_url` are
    relative API paths the client uses to fetch the human-readable PDF and to
    re-validate the chain online.
    """
    receipt_id: str
    signed_at: str
    signature_algo: str = "Ed25519"
    signature: str
    public_key_id: str
    signed_fields: list[str]
    # Actual key->value mapping that was canonicalized + signed. Embedding it
    # here makes the receipt fully self-contained: a verifier can re-canonicalize
    # this dict, hash it, and check the signature against the published public
    # key without ever holding the full DoCR or calling the API. This is what
    # makes "tamper-evident" a property of the receipt itself, not the server.
    signed_fields_data: dict
    canonical_digest: str
    pdf_url: str
    verify_url: str


class AuditResponse(BaseModel):
    run_id: str
    timestamp: str
    profile: str
    status: str
    message: str
    # Enterprise-canonical verdict code alongside the existing `status` string.
    # Values: STOP | NEEDS_REVIEW | SAFE. `status` is preserved for backward
    # compatibility with persisted records and the existing frontend.
    verdict_code: Optional[str] = None
    overall_severity: str
    overall_confidence: float
    overall_confidence_label: str
    overall_confidence_explanation: str
    # True only when BOTH (a) the redacted preview has no remaining policy
    # findings AND (b) the original input contained no blocking class. This
    # field is deliberately conservative: a STOP verdict, or any blocking
    # class in the original, forces it to False. Callers can still use the
    # redacted preview for audit review, but must not treat it as "safe to
    # send downstream" on blocking-class inputs.
    safe_after_redaction: bool
    # True iff the ORIGINAL input contained a blocking category (credential,
    # PHI, prompt injection, legal privilege, commercial-confidential, or any
    # critical finding). This is the field downstream systems should gate on
    # for "do not forward" decisions — `safe_after_redaction` already folds
    # this in, but is consumed by UI callers that want a single bool.
    input_had_blocking_class: Optional[bool] = None
    # One-sentence executive summary of the verdict. Stable shape:
    #   VERDICT: <rule_label> — <signal> (<top_citation>, confidence X.XX).
    # Safe to forward verbatim in emails, ticket titles, audit quotes.
    reason_line: Optional[str] = None
    # Per-class finding rollup for SOC dashboards and procurement questionnaires.
    # Keys are lowercase stable slugs (phi, pci, pii, credential, prompt_injection,
    # legal_privilege, commercial_confidential, ...). Buckets with zero findings
    # are omitted, so an empty dict means nothing triggered.
    blocking_classes: dict[str, int] = Field(default_factory=dict)
    # SHA-256 of `redacted_preview`. Closes the breach-post-mortem question
    # "prove what actually left the building" by letting downstream systems
    # hash their egress payload and compare against this value.
    redacted_output_hash: Optional[str] = None
    input_meta: Optional[InputMeta] = None
    enforcement: Optional[EnforcementBlock] = None
    residual_risk: Optional[ResidualRiskBlock] = None
    # Present only when profile == "Healthcare". When attestation == "PASS" this
    # is safe to quote as a de-identification attestation; callers should still
    # check `input_had_blocking_class` to confirm the original payload did not
    # also contain credentials or prompt injection.
    safe_harbor: Optional[SafeHarborBlock] = None
    audit_summary: AuditSummary
    redacted_preview: Optional[str] = None
    findings: list[Finding]
    duty_of_care_record: Optional[DutyOfCareRecord] = None
    receipt: Optional[ReceiptBlock] = None


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
