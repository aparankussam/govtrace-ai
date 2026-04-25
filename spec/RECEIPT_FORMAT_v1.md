# GoVTrace Receipt Format — v1

**Status:** Stable
**Version:** 1.0.0
**Editor:** GoVTraceAI / gobots
**License:** CC BY 4.0

A GoVTrace Receipt is a portable, third-party-verifiable artifact attesting
that an AI action was evaluated by a named policy and produced a named
verdict at a named time. The receipt is signed off-machine with Ed25519 and
verifiable by anyone holding the corresponding public key, without ever
contacting the issuing system.

This document specifies v1 of the receipt format and the verification
procedure. An implementation that follows this specification is interoperable
with any other v1 implementation: a receipt issued by one system can be
verified by any other system that implements this spec.

---

## 1. Design goals

1. **Portable.** A receipt can be detached from the issuing system and
   verified anywhere by anyone with the public key.
2. **Third-party verifiable.** Verification does not require the issuer to
   be online, in business, or cooperative.
3. **Tamper-evident.** Any modification to any signed field invalidates the
   signature.
4. **Compact.** Receipts fit in a single JSON object suitable for embedding
   in logs, contracts, eDiscovery exports, and audit reports.
5. **Stable.** v1 is frozen. Forward-compatible additions arrive as v1.x;
   breaking changes arrive as v2.

---

## 2. Receipt object

A v1 receipt is a JSON object with the following fields:

| Field                | Type                  | Required | Description                                                                 |
|----------------------|-----------------------|----------|-----------------------------------------------------------------------------|
| `receipt_id`         | string                | yes      | Unique identifier for this receipt. Format is issuer-defined.               |
| `signed_at`          | string (RFC 3339 UTC) | yes      | Time the receipt was signed.                                                |
| `signature_algo`     | string                | yes      | MUST be `"Ed25519"` in v1.                                                  |
| `signature`          | string (base64url)    | yes      | Unpadded base64url Ed25519 signature. See §4.                               |
| `public_key_id`      | string                | yes      | Stable identifier for the issuing public key.                               |
| `signed_fields`      | array of strings      | yes      | Ordered list of keys present in `signed_fields_data`.                       |
| `signed_fields_data` | object                | yes      | The actual key->value mapping that was canonicalized and signed.            |
| `canonical_digest`   | string (hex)          | yes      | SHA-256 hex of the canonical JSON of `signed_fields_data`. See §3.          |
| `pdf_url`            | string                | no       | Issuer-served URL to a human-readable PDF rendition.                        |
| `verify_url`         | string                | no       | Issuer-served URL to walk the chain (if the issuer maintains one).          |

### 2.1 Required fields in `signed_fields_data`

A v1-compliant receipt MUST include at least the following six keys in
`signed_fields_data`:

| Key             | Type   | Description                                                          |
|-----------------|--------|----------------------------------------------------------------------|
| `run_id`        | string | Issuer-defined identifier for the AI action being attested.          |
| `verdict`       | string | The decision: `STOP`, `NEEDS_REVIEW`, `SAFE`, or issuer-defined.     |
| `record_hash`   | string | SHA-256 hex of the canonical record (DoCR) the verdict was made on.  |
| `policy_digest` | string | SHA-256 hex of the policy bundle that produced the verdict.          |
| `input_hash`    | string | SHA-256 hex of the AI action's input bytes.                          |
| `timestamp`     | string | RFC 3339 UTC timestamp of the verdict.                               |

Additional issuer-defined keys MAY appear in `signed_fields_data`. They are
covered by the signature exactly the same as the required keys. A verifier
MUST NOT reject a receipt for containing unknown keys. A verifier MAY surface
unknown keys to the user.

---

## 3. Canonicalization

The canonical byte string of `signed_fields_data` is computed as follows:

1. Serialize `signed_fields_data` as JSON with:
   - keys sorted lexicographically at every level
   - separators `","` between entries and `":"` between key and value (no spaces)
   - UTF-8 encoding
   - no leading or trailing whitespace
2. The resulting bytes are the canonical bytes of the receipt.

In Python (reference):

```python
import json
canonical = json.dumps(signed_fields_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

In Node.js:

```js
import { stringify } from 'safe-stable-stringify' // or any RFC8785-style canonicalizer
const canonical = Buffer.from(stringify(signed_fields_data, { sort: true }), 'utf8')
```

The `canonical_digest` field MUST equal `sha256(canonical_bytes)` rendered as
lowercase hex. A verifier MAY recompute `canonical_digest` and reject the
receipt on mismatch.

---

## 4. Signing

The signature covers the **raw 32 bytes** of the SHA-256 digest of the
canonical bytes (not the hex string of the digest, and not the canonical
bytes themselves). This produces a fixed-length signing input independent
of the receipt size.

```
digest_bytes = sha256(canonical_bytes)         # 32 bytes
signature    = ed25519.sign(private_key, digest_bytes)
signature_b64url = base64url_unpadded(signature)
```

The signature is an Ed25519 signature as defined by RFC 8032.

---

## 5. Public key publication

Issuers MUST publish their public key at a stable, HTTPS-served URL. The
RECOMMENDED location is a JSON document at:

```
https://<issuer-domain>/.well-known/govtrace-pubkey.json
```

The document MUST be a JSON object with the following shape:

```json
{
  "key_id": "govtrace-signing-v1",
  "algorithm": "Ed25519",
  "public_key_b64url": "OwOdZ-d9QHwtuRCreEn6SIZ9iTuWxTpJPfeN5pGL-ns",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "signs": "GoVTrace Receipt v1",
  "signature_encoding": "base64url (unpadded)"
}
```

`public_key_b64url` MUST be the unpadded base64url encoding of the raw 32
Ed25519 public key bytes. `public_key_pem` is a SubjectPublicKeyInfo PEM and
is provided for tooling convenience.

The `key_id` in the published document MUST equal the `public_key_id` field
in any receipt the holder of the corresponding private key issues.

Issuers MAY rotate keys. When they do, the rotated public key MUST remain
resolvable for at least the receipt retention period of any system that may
hold receipts signed by it. Rotation guidance is informative; v1 does not
specify a rotation transport.

---

## 6. Verification procedure

Given a receipt object `R`:

1. Validate that `R.signature_algo == "Ed25519"`. Otherwise reject.
2. Resolve the public key for `R.public_key_id`. Implementations MAY pin
   keys, fetch from `/.well-known/govtrace-pubkey.json`, or accept a key
   provided out of band.
3. Recompute the canonical bytes of `R.signed_fields_data` per §3.
4. Compute `digest_bytes = sha256(canonical_bytes)`.
5. (Optional, recommended.) Verify that `R.canonical_digest` equals
   `hex(digest_bytes)`. If unequal, reject.
6. Verify the Ed25519 signature `R.signature` against `digest_bytes` using
   the resolved public key.

If step 6 succeeds, the receipt is **VALID**. The verifier SHOULD report:

- `valid: true`
- the `signed_fields_data` (echoed back, so the user sees exactly what was
  attested),
- the `public_key_id` and the source from which the key was resolved.

If step 6 fails, the receipt is **INVALID**. The verifier SHOULD report
`reason: "signature_invalid"` and SHOULD NOT echo `signed_fields_data` as
trustworthy.

---

## 7. JSON Schema

A machine-readable JSON Schema for the receipt object is published alongside
this document as `receipt.schema.json` at:

```
https://gobotsai.com/spec/receipt.schema.json
```

The schema is normative for field names and types. This document is
normative for canonicalization and signing.

---

## 8. Reference implementations

- **Issuer (Python):** `govtrace-api/signing.py` in
  https://github.com/aparankussam/govtrace-ai
- **Verifier (Node CLI):** `@gobotsai/govtrace` on npm. Source at
  `cli/` in the same repo.
- **Web verifier:** `https://gobotsai.com/verify`

---

## 9. Versioning and stability

- v1 is frozen as of the publication date of this document.
- Additive, backward-compatible changes to issuer-defined keys in
  `signed_fields_data` are allowed at any time and do not require a
  spec revision.
- Changes that affect the signing or canonicalization rules require
  a major version bump (v2). Such a v2 spec MAY introduce a new
  `spec_version` field at the receipt root; v1 verifiers SHOULD reject
  receipts carrying a `spec_version` they do not recognize.

---

## 10. Security considerations

- A verifier MUST resolve the public key from a source the verifier itself
  trusts. Never accept a public key embedded in the same receipt being
  verified.
- A receipt does not attest that the AI action being signed actually
  occurred in the real world. It attests only that the issuer evaluated a
  given input under a given policy and reached the recorded verdict at the
  recorded time. Combine receipts with execution-time evidence (network
  logs, system journals) to reconstruct what happened.
- Receipts are not anonymized. Avoid placing direct identifiers in
  `signed_fields_data`. Use hashes (`record_hash`, `input_hash`) instead.

---

## 11. License

This specification is published under Creative Commons Attribution 4.0
International (CC BY 4.0). You may implement, fork, extend, and embed it
freely with attribution.
