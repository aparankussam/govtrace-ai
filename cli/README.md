# @gobotsai/govtrace

Independent verifier for [GoVTrace Receipt v1](https://gobotsai.com/spec).

Stateless. Offline-capable. No database. No login. Verifies an Ed25519 signed
receipt against the public key published by the issuer at
`/.well-known/govtrace-pubkey.json`.

A GoVTrace Receipt is a portable attestation that an AI action was evaluated
by a named policy and produced a named verdict at a named time. This package
checks that the receipt has not been tampered with and was issued by the
holder of the matching private key.

## Install

```sh
npm install -g @gobotsai/govtrace
```

Requires Node 18 or later. Uses only the Node standard library; no runtime
dependencies.

## Usage

```sh
govtrace verify ./receipt.json
```

By default the verifier resolves the public key from
`https://govtrace-api.vercel.app/.well-known/govtrace-pubkey.json`. To verify
against a different issuer or against a local copy of a pubkey document:

```sh
govtrace verify ./receipt.json --pubkey https://issuer.example.com/.well-known/govtrace-pubkey.json
govtrace verify ./receipt.json --pubkey ./pubkey.json
govtrace verify ./receipt.json --pubkey ./pubkey.pem
```

For machine consumption:

```sh
govtrace verify ./receipt.json --json | jq .
```

Exit codes:

- `0` receipt is valid
- `1` receipt is invalid (signature mismatch, missing fields, unreachable key)
- `2` usage error

## Accepted input shapes

The receipt file can be:

1. The full `/audit` response from a GoVTrace engine.
2. The bare receipt block.
3. `{ "receipt": { ... } }`.

## What gets checked

1. `signature_algo` is `Ed25519`.
2. `signed_fields_data` is canonicalized (sorted keys, compact separators, UTF-8).
3. The canonical bytes are SHA-256 hashed.
4. The 32-byte digest is verified against the receipt's signature using the
   resolved public key.
5. (Optional) `canonical_digest` is recomputed and compared.

If all checks pass, the receipt is **valid** and the printed `signed_fields_data`
is exactly what the issuer attested to.

## Spec

The full specification is at <https://gobotsai.com/spec> and at
[`spec/RECEIPT_FORMAT_v1.md`](https://github.com/aparankussam/govtrace-ai/blob/main/spec/RECEIPT_FORMAT_v1.md)
in the source repo. v1 is frozen: any v1 receipt verifies under any v1
implementation.

## License

MIT.
