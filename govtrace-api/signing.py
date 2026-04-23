"""
Ed25519 signing for Duty-of-Care Records.

Every DoCR carries a tamper-evident `record_hash` (SHA-256 of the canonical
DoCR body + chain_prev_hash). This module produces an Ed25519 signature over
that record_hash, turning the DoCR into an offline-verifiable attestation:

    verify(pubkey, record_hash_bytes, signature) == True

means the DoCR was produced by a server holding the matching private key and
neither the DoCR body nor the chain pointer has been tampered with.

Key discovery order (first match wins):
  1. GOVTRACE_SIGNING_KEY_PEM_B64 — base64 of a PEM-encoded Ed25519 private key
  2. GOVTRACE_SIGNING_KEY_PATH    — filesystem path to a PEM private key

If neither is set the module fails fast at import. The previous "auto-generate
on first run" path attempted a filesystem write, which crashes on read-only
serverless filesystems (Vercel, Lambda) and silently rotates the public key
on every cold start. Both behaviors are worse than a clear startup error.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

SIGNATURE_ALGO = "Ed25519"
PUBLIC_KEY_ID = os.getenv("GOVTRACE_SIGNING_KEY_ID", "govtrace-signing-v1")

def _load_from_env_b64() -> Optional[ed25519.Ed25519PrivateKey]:
    b64 = os.getenv("GOVTRACE_SIGNING_KEY_PEM_B64", "").strip()
    if not b64:
        return None
    try:
        pem = base64.b64decode(b64)
        key = serialization.load_pem_private_key(pem, password=None)
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key
    except Exception:
        return None
    return None


def _load_from_env_path() -> Optional[ed25519.Ed25519PrivateKey]:
    path = os.getenv("GOVTRACE_SIGNING_KEY_PATH", "").strip()
    if not path:
        return None
    try:
        pem = Path(path).read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key
    except Exception:
        return None
    return None


def _load_signing_key() -> ed25519.Ed25519PrivateKey:
    key = _load_from_env_b64() or _load_from_env_path()
    if key is None:
        raise RuntimeError(
            "GoVTrace signing key not configured. Set GOVTRACE_SIGNING_KEY_PEM_B64 "
            "(base64-encoded PEM) or GOVTRACE_SIGNING_KEY_PATH (path to PEM file). "
            "Generate a local key with: "
            "python -c \"from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; "
            "from cryptography.hazmat.primitives import serialization; "
            "import sys; sys.stdout.buffer.write(Ed25519PrivateKey.generate().private_bytes("
            "serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, "
            "serialization.NoEncryption()))\" > key.pem"
        )
    return key


_PRIVATE_KEY: ed25519.Ed25519PrivateKey = _load_signing_key()
_PUBLIC_KEY: ed25519.Ed25519PublicKey = _PRIVATE_KEY.public_key()


def _record_hash_bytes(record_hash_hex: str) -> bytes:
    """Signatures cover the RAW record_hash bytes, not the hex string. This
    keeps the signing payload compact and removes any ambiguity about casing
    or encoding when verifiers re-derive the message."""
    return bytes.fromhex(record_hash_hex)


def sign_record_hash(record_hash_hex: str) -> str:
    """Return a base64url-encoded Ed25519 signature over the record_hash."""
    sig = _PRIVATE_KEY.sign(_record_hash_bytes(record_hash_hex))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def verify_record_hash_signature(record_hash_hex: str, signature_b64url: str) -> bool:
    try:
        _PUBLIC_KEY.verify(_b64url_decode(signature_b64url), _record_hash_bytes(record_hash_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


def _canonicalize_receipt_payload(signed_fields_data: dict) -> bytes:
    """Canonical JSON for receipt signing.

    Sorted keys + compact separators so any verifier re-serializing the same
    dict reproduces byte-for-byte the same payload. Signing the SHA-256 digest
    of this payload keeps the signing input a fixed 32 bytes (consistent with
    record_hash signing) and makes the receipt a standalone, offline-verifiable
    artifact independent of the full DoCR.
    """
    return json.dumps(signed_fields_data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_receipt(signed_fields_data: dict) -> tuple[str, str]:
    """Canonicalize + SHA-256 + Ed25519 sign. Returns (canonical_digest_hex, signature_b64url)."""
    canonical = _canonicalize_receipt_payload(signed_fields_data)
    digest_hex = hashlib.sha256(canonical).hexdigest()
    sig = _PRIVATE_KEY.sign(bytes.fromhex(digest_hex))
    return digest_hex, base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def verify_receipt(signed_fields_data: dict, signature_b64url: str) -> bool:
    canonical = _canonicalize_receipt_payload(signed_fields_data)
    digest = hashlib.sha256(canonical).digest()
    try:
        _PUBLIC_KEY.verify(_b64url_decode(signature_b64url), digest)
        return True
    except (InvalidSignature, ValueError):
        return False


def public_key_info() -> dict:
    """Payload for GET /.well-known/govtrace-pubkey.json.

    Exposes both the raw 32-byte Ed25519 public key (base64url) and a PEM
    SubjectPublicKeyInfo so verifiers can use whichever their tooling prefers.
    """
    raw = _PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pem = _PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return {
        "key_id": PUBLIC_KEY_ID,
        "algorithm": SIGNATURE_ALGO,
        "public_key_b64url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
        "public_key_pem": pem,
        "signs": "record_hash (SHA-256 of canonical DoCR body + chain_prev_hash)",
        "signature_encoding": "base64url (unpadded)",
    }
