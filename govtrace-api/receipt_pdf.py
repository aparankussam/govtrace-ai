"""
Signed Verdict Receipt PDF renderer.

Turns a persisted audit run + its receipt block into a one-page, self-contained
PDF that a Compliance reviewer can hand to an auditor. The PDF is a HUMAN
artifact; the cryptographic commitment lives in the JSON receipt. Everything
printed here (record_hash, policy_digest, signature, canonical_digest) also
appears in the signed JSON so nothing is asserted by the PDF that isn't also
covered by the signature.

A QR code in the bottom-right encodes the verify_url so a phone camera can
pull up the online chain verification page for this run.
"""
from __future__ import annotations

import io

from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Color palette — matches the web UI's verdict accents so the PDF reads as
# from the same product. Amber for NEEDS REVIEW, crimson for violations, green
# for clean.
_ACCENT = colors.HexColor("#f15a29")
_INK = colors.HexColor("#111111")
_MUTED = colors.HexColor("#6b7280")
_SURFACE = colors.HexColor("#F6F1EC")
_OK = colors.HexColor("#059669")
_WARN = colors.HexColor("#B45309")
_STOP = colors.HexColor("#B91C1C")


def _verdict_color(verdict: str):
    v = (verdict or "").upper()
    if v in ("SAFE", "COMPLIANT"):
        return _OK
    if v in ("NEEDS REVIEW", "NEEDS_REVIEW"):
        return _WARN
    return _STOP


def _shorten(value: str | None, head: int = 24) -> str:
    if not value:
        return "—"
    if len(value) <= head:
        return value
    return f"{value[:head]}…"


def _qr_flowable(payload: str, size_pt: float = 1.1 * inch) -> Drawing:
    """Produce a ReportLab Drawing containing a QR code for `payload`."""
    widget = QrCodeWidget(payload)
    bounds = widget.getBounds()
    w = bounds[2] - bounds[0]
    h = bounds[3] - bounds[1]
    drawing = Drawing(size_pt, size_pt, transform=[size_pt / w, 0, 0, size_pt / h, 0, 0])
    drawing.add(widget)
    return drawing


def render_receipt_pdf(
    *,
    run_id: str,
    timestamp: str,
    profile: str,
    verdict: str,
    message: str,
    overall_severity: str,
    overall_confidence: float | None,
    finding_count: int,
    record_hash: str,
    policy_digest: str | None,
    input_hash: str | None,
    chain_prev_hash: str | None,
    receipt: dict,
    verify_base_url: str,
) -> bytes:
    """Render the receipt PDF as bytes. No files are written to disk."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title=f"GovTraceAI Signed Verdict Receipt · {run_id}",
        author="GovTraceAI",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "GTH1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=_INK,
        spaceAfter=2,
    )
    eyebrow = ParagraphStyle(
        "GTEye",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=_ACCENT,
        spaceAfter=4,
    )
    body = ParagraphStyle(
        "GTBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=_INK,
    )
    muted = ParagraphStyle(
        "GTMuted",
        parent=body,
        textColor=_MUTED,
        fontSize=9,
        leading=12,
    )
    verdict_style = ParagraphStyle(
        "GTVerdict",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=28,
        leading=32,
        textColor=_verdict_color(verdict),
        spaceAfter=4,
    )
    mono = ParagraphStyle(
        "GTMono",
        parent=body,
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=_INK,
    )

    story: list = []

    # ------------------------------------------------------------------ Header
    story.append(Paragraph("GOVTRACEAI &middot; SIGNED VERDICT RECEIPT", eyebrow))
    story.append(Paragraph("Duty-of-Care Record attestation", h1))
    story.append(Paragraph(
        f"Run <b>{run_id}</b> &middot; profile <b>{profile}</b> &middot; issued {timestamp}",
        muted,
    ))
    story.append(Spacer(1, 0.18 * inch))

    # ------------------------------------------------------------------ Verdict
    conf_str = f"{float(overall_confidence):.2f}" if overall_confidence is not None else "—"
    verdict_block = [
        [Paragraph(verdict.upper(), verdict_style)],
        [Paragraph(message or "", body)],
        [Paragraph(
            f"<b>Severity</b> {overall_severity or '—'} &nbsp;·&nbsp; "
            f"<b>Confidence</b> {conf_str} &nbsp;·&nbsp; "
            f"<b>Findings</b> {finding_count}",
            muted,
        )],
    ]
    tbl = Table(verdict_block, colWidths=[doc.width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _SURFACE),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E0DA")),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.22 * inch))

    # ---------------------------------------------------------------- Integrity
    story.append(Paragraph("INTEGRITY", eyebrow))
    integrity_rows = [
        ["record_hash", _shorten(record_hash, 44)],
        ["chain_prev_hash", _shorten(chain_prev_hash, 44) if chain_prev_hash else "genesis"],
        ["policy_digest", _shorten(policy_digest, 44)],
        ["input_hash", _shorten(input_hash, 44)],
    ]
    itbl = Table(
        [[Paragraph(k, body), Paragraph(v, mono)] for k, v in integrity_rows],
        colWidths=[1.4 * inch, doc.width - 1.4 * inch],
    )
    itbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#EDE7DF")),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(itbl)
    story.append(Spacer(1, 0.22 * inch))

    # ----------------------------------------------------------------- Receipt
    story.append(Paragraph("SIGNATURE", eyebrow))
    signed_fields = ", ".join(receipt.get("signed_fields") or [])
    sig_rows = [
        ["receipt_id", receipt.get("receipt_id") or "—"],
        ["signature_algo", receipt.get("signature_algo") or "Ed25519"],
        ["public_key_id", receipt.get("public_key_id") or "—"],
        ["canonical_digest", _shorten(receipt.get("canonical_digest"), 44)],
        ["signature", _shorten(receipt.get("signature"), 44)],
        ["signed_fields", signed_fields or "—"],
        ["signed_at", receipt.get("signed_at") or "—"],
    ]
    stbl = Table(
        [[Paragraph(k, body), Paragraph(v, mono)] for k, v in sig_rows],
        colWidths=[1.4 * inch, doc.width - 1.4 * inch],
    )
    stbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#EDE7DF")),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(stbl)
    story.append(Spacer(1, 0.22 * inch))

    # ------------------------------------------------------------------ Verify
    verify_url = f"{verify_base_url.rstrip('/')}{receipt.get('verify_url') or f'/audit/verify/{run_id}'}"
    pubkey_url = f"{verify_base_url.rstrip('/')}/.well-known/govtrace-pubkey.json"
    footer_text = Paragraph(
        "<b>Verify offline.</b> Fetch the public key at "
        f"<font face='Courier' color='#111111'>{pubkey_url}</font> and validate "
        "the Ed25519 signature over the SHA-256 of the canonical JSON of signed_fields. "
        "Online chain walk available at "
        f"<font face='Courier' color='#111111'>{verify_url}</font>.",
        muted,
    )
    qr = _qr_flowable(verify_url)
    vtbl = Table([[footer_text, qr]], colWidths=[doc.width - 1.3 * inch, 1.3 * inch])
    vtbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(vtbl)
    story.append(Spacer(1, 0.2 * inch))

    # ------------------------------------------------------------ Disclaimer
    story.append(Paragraph(
        "GovTraceAI Duty-of-Care Record. Automated policy intelligence for reviewer "
        "workflows. Not legal, medical, or regulatory advice. Retain with your audit trail.",
        muted,
    ))

    doc.build(story)
    return buf.getvalue()
