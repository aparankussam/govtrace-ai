#!/usr/bin/env node
// @gobotsai/govtrace -- independent verifier for GoVTrace Receipt v1.
// Spec: https://gobotsai.com/spec
// No runtime deps. Uses Node's built-in crypto for Ed25519.

import { readFile } from 'node:fs/promises'
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto'

const VERSION = '0.1.0'
const DEFAULT_PUBKEY_URL = 'https://govtrace-api.vercel.app/.well-known/govtrace-pubkey.json'

function usage(exitCode = 0) {
  const out = exitCode === 0 ? console.log : console.error
  out(`govtrace ${VERSION} -- independent verifier for GoVTrace Receipt v1

USAGE
  govtrace verify <receipt.json> [--pubkey <url-or-path>] [--json]
  govtrace canonicalize <receipt.json>
  govtrace --version
  govtrace --help

FLAGS
  --pubkey <src>   Public key source. Accepts an HTTPS URL to the
                   /.well-known/govtrace-pubkey.json document, a path to a
                   local copy of that document, or a path to a raw PEM file.
                   Default: ${DEFAULT_PUBKEY_URL}
  --json           Emit machine-readable JSON instead of the human report.

EXAMPLES
  govtrace verify receipt.json
  govtrace verify receipt.json --pubkey ./pubkey.json
  govtrace verify receipt.json --json | jq .

EXIT CODES
  0  receipt is valid
  1  receipt is invalid (signature mismatch, missing fields, bad pubkey)
  2  usage error
`)
  process.exit(exitCode)
}

function parseArgs(argv) {
  const args = { _: [], pubkey: null, json: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--help' || a === '-h') return { ...args, help: true }
    if (a === '--version' || a === '-v') return { ...args, version: true }
    if (a === '--json') args.json = true
    else if (a === '--pubkey') {
      args.pubkey = argv[++i]
      if (!args.pubkey) {
        console.error('error: --pubkey requires a value')
        process.exit(2)
      }
    } else args._.push(a)
  }
  return args
}

function canonicalize(value) {
  // Deterministic JSON: sorted keys at every level, compact separators, UTF-8.
  // Matches the Python reference: json.dumps(..., sort_keys=True, separators=(',', ':')).
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']'
  const keys = Object.keys(value).sort()
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}'
}

function b64urlToBytes(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4))
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad
  return Buffer.from(b64, 'base64')
}

async function loadReceipt(path) {
  let raw
  try {
    raw = await readFile(path, 'utf8')
  } catch (err) {
    throw new Error(`could not read receipt file at ${path}: ${err.message}`)
  }
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    throw new Error(`receipt file is not valid JSON: ${err.message}`)
  }
  // Accept full audit response, bare receipt, or { receipt: {...} }.
  if (parsed && typeof parsed === 'object' && parsed.receipt && typeof parsed.receipt === 'object') {
    return parsed.receipt
  }
  return parsed
}

async function loadPubkey(source) {
  const src = source || DEFAULT_PUBKEY_URL

  // Read a JSON pubkey document or raw PEM from a URL or local file.
  let body
  if (/^https?:\/\//i.test(src)) {
    const res = await fetch(src)
    if (!res.ok) throw new Error(`failed to fetch pubkey from ${src}: HTTP ${res.status}`)
    body = await res.text()
  } else {
    try {
      body = await readFile(src, 'utf8')
    } catch (err) {
      throw new Error(`could not read pubkey file at ${src}: ${err.message}`)
    }
  }

  const trimmed = body.trim()
  if (trimmed.startsWith('-----BEGIN')) {
    return { key: createPublicKey(trimmed), keyId: null, source: src }
  }

  let doc
  try {
    doc = JSON.parse(trimmed)
  } catch (err) {
    throw new Error(`pubkey source is neither a PEM nor a JSON document: ${err.message}`)
  }

  if (typeof doc.public_key_pem === 'string' && doc.public_key_pem.includes('BEGIN')) {
    return { key: createPublicKey(doc.public_key_pem), keyId: doc.key_id || null, source: src }
  }
  if (typeof doc.public_key_b64url === 'string') {
    const raw = b64urlToBytes(doc.public_key_b64url)
    if (raw.length !== 32) {
      throw new Error(`pubkey doc has public_key_b64url but it is not 32 bytes (got ${raw.length})`)
    }
    // Wrap raw 32-byte Ed25519 key in a SubjectPublicKeyInfo DER for createPublicKey.
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex')
    const der = Buffer.concat([spkiPrefix, raw])
    return { key: createPublicKey({ key: der, format: 'der', type: 'spki' }), keyId: doc.key_id || null, source: src }
  }
  throw new Error('pubkey document missing both public_key_pem and public_key_b64url')
}

function verifyReceipt(receipt, pubkey) {
  const result = {
    valid: false,
    reason: '',
    public_key_id: receipt?.public_key_id || null,
    signature_algo: receipt?.signature_algo || null,
    signed_fields_data: null,
    canonical_digest: null,
    verifier_version: VERSION,
  }

  if (!receipt || typeof receipt !== 'object') {
    result.reason = 'receipt_not_object'
    return result
  }
  if (receipt.signature_algo && receipt.signature_algo !== 'Ed25519') {
    result.reason = 'unsupported_signature_algo'
    return result
  }
  const sfd = receipt.signed_fields_data
  if (!sfd || typeof sfd !== 'object' || Array.isArray(sfd)) {
    result.reason = 'missing_signed_fields_data'
    return result
  }
  if (typeof receipt.signature !== 'string' || !receipt.signature) {
    result.reason = 'missing_signature'
    return result
  }

  const canonical = Buffer.from(canonicalize(sfd), 'utf8')
  const digest = createHash('sha256').update(canonical).digest()
  const digestHex = digest.toString('hex')
  result.signed_fields_data = sfd
  result.canonical_digest = digestHex

  if (typeof receipt.canonical_digest === 'string' && receipt.canonical_digest.toLowerCase() !== digestHex) {
    result.reason = 'canonical_digest_mismatch'
    return result
  }

  let sigBytes
  try {
    sigBytes = b64urlToBytes(receipt.signature)
  } catch (err) {
    result.reason = 'signature_not_base64url'
    return result
  }
  if (sigBytes.length !== 64) {
    result.reason = 'signature_wrong_length'
    return result
  }

  let ok = false
  try {
    ok = edVerify(null, digest, pubkey, sigBytes)
  } catch (err) {
    result.reason = 'verify_threw:' + (err.message || 'unknown')
    return result
  }

  result.valid = ok
  result.reason = ok ? 'signature_valid' : 'signature_invalid'
  return result
}

function renderHuman(result, source) {
  const lines = []
  const mark = result.valid ? '\u2713' : '\u2717'
  lines.push(`${mark} ${result.valid ? 'VALID' : 'INVALID'}    reason: ${result.reason}`)
  lines.push('')
  lines.push(`  public_key_id    ${result.public_key_id || '(none)'}`)
  lines.push(`  signature_algo   ${result.signature_algo || '(none)'}`)
  lines.push(`  pubkey source    ${source}`)
  lines.push(`  verifier         govtrace ${result.verifier_version}`)
  if (result.signed_fields_data) {
    lines.push('')
    lines.push('  signed fields:')
    for (const [k, v] of Object.entries(result.signed_fields_data)) {
      const val = typeof v === 'string' ? v : JSON.stringify(v)
      lines.push(`    ${k.padEnd(16)} ${val}`)
    }
  }
  if (!result.valid) {
    lines.push('')
    lines.push('  Signature does not match the signed fields. Either the')
    lines.push('  fields were modified after signing, or the receipt was')
    lines.push('  signed by a different key than the one resolved.')
  }
  return lines.join('\n')
}

async function cmdVerify(args) {
  if (args._.length < 2) {
    console.error('usage: govtrace verify <receipt.json> [--pubkey <src>] [--json]')
    process.exit(2)
  }
  const receiptPath = args._[1]

  let receipt, pubkey
  try {
    receipt = await loadReceipt(receiptPath)
    pubkey = await loadPubkey(args.pubkey)
  } catch (err) {
    if (args.json) {
      console.log(JSON.stringify({ valid: false, reason: 'load_failed', error: err.message, verifier_version: VERSION }))
    } else {
      console.error(`error: ${err.message}`)
    }
    process.exit(1)
  }

  const result = verifyReceipt(receipt, pubkey.key)

  if (args.json) {
    console.log(JSON.stringify({ ...result, pubkey_source: pubkey.source }, null, 2))
  } else {
    console.log(renderHuman(result, pubkey.source))
  }
  process.exit(result.valid ? 0 : 1)
}

async function cmdCanonicalize(args) {
  if (args._.length < 2) {
    console.error('usage: govtrace canonicalize <receipt.json>')
    process.exit(2)
  }
  const receipt = await loadReceipt(args._[1])
  const sfd = receipt.signed_fields_data
  if (!sfd || typeof sfd !== 'object') {
    console.error('error: receipt has no signed_fields_data object')
    process.exit(1)
  }
  const canonical = canonicalize(sfd)
  const digest = createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex')
  console.log(canonical)
  console.error(`sha256: ${digest}`)
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.version) { console.log(VERSION); process.exit(0) }
  if (args.help || args._.length === 0) usage(args.help ? 0 : 2)

  const cmd = args._[0]
  if (cmd === 'verify') return cmdVerify(args)
  if (cmd === 'canonicalize') return cmdCanonicalize(args)
  console.error(`error: unknown command "${cmd}"`)
  usage(2)
}

main().catch(err => {
  console.error(`fatal: ${err.message}`)
  process.exit(1)
})
