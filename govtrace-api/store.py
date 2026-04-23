"""
GovTrace persistent audit log — SQLite backend.

DEPLOYMENT CONSTRAINTS
----------------------
SQLite works correctly when the process has a stable, writable filesystem:
  - Local development
  - Docker / self-hosted
  - Railway, Render, Fly.io, or any platform with persistent volumes

On Vercel's serverless runtime (VERCEL_ENV set) the /tmp filesystem is
ephemeral per cold-start and is NOT shared across concurrent instances.
Persistence is therefore disabled on Vercel unless GOVTRACE_DB_PATH is
explicitly set to a path backed by a mounted persistent volume.

To enable persistence set:
  GOVTRACE_DB_PATH=/path/to/govtrace_audit.db

PRIVACY DECISIONS
-----------------
- Raw input text is NEVER stored. Only a SHA-256 hex digest and char count
  are persisted so runs can be correlated without reconstructing the input.
- Findings stored in response_json already contain only masked examples
  (e.g. "***-**-6789", "[email redacted]") — no raw PII is retained.
- redacted_preview follows the same masking as findings; it is stored as-is.
"""

import hashlib
import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_HISTORY_LIMIT_MAX = 200
_HISTORY_LIMIT_DEFAULT = 50

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _resolve_db_path() -> Optional[Path]:
    """Return the SQLite file path, or None if persistence is disabled."""
    explicit = os.getenv("GOVTRACE_DB_PATH", "").strip()
    if explicit:
        return Path(explicit)

    # Vercel serverless: ephemeral filesystem — do not silently create a DB
    # that will vanish on the next invocation.
    if os.getenv("VERCEL_ENV"):
        logger.info(
            "GovTrace audit persistence is DISABLED on Vercel. "
            "Set GOVTRACE_DB_PATH to a mounted persistent volume path to enable it."
        )
        return None

    # Local / self-hosted default: place DB next to this file.
    return Path(__file__).parent / "govtrace_audit.db"


DB_PATH: Optional[Path] = _resolve_db_path()
STORAGE_ENABLED: bool = DB_PATH is not None

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_runs (
    run_id              TEXT    PRIMARY KEY,
    timestamp           TEXT    NOT NULL,
    profile             TEXT    NOT NULL,
    status              TEXT    NOT NULL,
    overall_severity    TEXT    NOT NULL,
    overall_confidence  REAL    NOT NULL,
    safe_after_redaction INTEGER NOT NULL,   -- 0 | 1
    input_hash          TEXT    NOT NULL,    -- SHA-256 hex of raw input (raw text never stored)
    input_length        INTEGER NOT NULL,    -- character count for analytics
    finding_count       INTEGER NOT NULL,
    response_json       TEXT    NOT NULL,    -- full AuditResponse JSON for exact retrieval
    record_hash         TEXT,                -- SHA-256 of DoCR body + chain_prev_hash (hash-chain anchor)
    chain_prev_hash     TEXT                 -- previous record's record_hash; NULL for genesis
)
"""

# Idempotent column backfill for DBs that existed before the hash-chain columns
# were introduced. SQLite ALTER TABLE is limited — we just add columns; existing
# rows land with NULLs in the new columns, which the verifier treats as
# "pre-chain" rather than corrupt.
_ADD_RECORD_HASH = "ALTER TABLE audit_runs ADD COLUMN record_hash TEXT"
_ADD_CHAIN_PREV  = "ALTER TABLE audit_runs ADD COLUMN chain_prev_hash TEXT"

_CREATE_IDX_TIMESTAMP = (
    "CREATE INDEX IF NOT EXISTS idx_audit_runs_timestamp ON audit_runs (timestamp DESC)"
)
_CREATE_IDX_STATUS = (
    "CREATE INDEX IF NOT EXISTS idx_audit_runs_status ON audit_runs (status)"
)
_CREATE_IDX_RECORD_HASH = (
    "CREATE INDEX IF NOT EXISTS idx_audit_runs_record_hash ON audit_runs (record_hash)"
)


def _connect() -> sqlite3.Connection:
    """Open a short-lived connection. Callers are responsible for closing it."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create the table and indexes if they do not exist. Called once at startup."""
    if not STORAGE_ENABLED:
        return
    try:
        conn = _connect()
        with conn:
            conn.execute(_CREATE_TABLE)
            # Backfill hash-chain columns on pre-existing DBs. ALTER TABLE
            # raises "duplicate column" when they already exist — swallow it.
            for stmt in (_ADD_RECORD_HASH, _ADD_CHAIN_PREV):
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    pass
            conn.execute(_CREATE_IDX_TIMESTAMP)
            conn.execute(_CREATE_IDX_STATUS)
            conn.execute(_CREATE_IDX_RECORD_HASH)
        conn.close()
        logger.info("GovTrace audit DB initialised at %s", DB_PATH)
    except Exception:
        logger.exception("Failed to initialise audit DB — persistence will be unavailable")


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def input_hash(text: str) -> str:
    """Return a SHA-256 hex digest of the raw input. Used for correlation only."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_latest_record_hash() -> Optional[str]:
    """Return the most recent record_hash (for hash-chaining the next record),
    or None if no runs exist. Never raises — failures fall back to None which
    is indistinguishable from 'this is the genesis record'.

    Orders by SQLite `rowid` (monotonic insert order). Ordering by timestamp
    would bucket same-second runs together, and our run_id tail is random,
    so neither is a reliable tiebreaker — rowid is."""
    if not STORAGE_ENABLED:
        return None
    try:
        conn = _connect()
        row = conn.execute(
            "SELECT record_hash FROM audit_runs "
            "WHERE record_hash IS NOT NULL "
            "ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return row["record_hash"] if row else None
    except Exception:
        logger.exception("Failed to read latest record_hash — treating as genesis")
        return None


def get_by_record_hash(record_hash: str) -> Optional[dict]:
    """Look up a run by its record_hash. Used by the /verify walker to hop
    from one record to its predecessor."""
    if not STORAGE_ENABLED or not record_hash:
        return None
    try:
        conn = _connect()
        row = conn.execute(
            "SELECT response_json FROM audit_runs WHERE record_hash = ?",
            (record_hash,),
        ).fetchone()
        conn.close()
        return json.loads(row["response_json"]) if row else None
    except Exception:
        logger.exception("Failed to retrieve run by record_hash=%s", record_hash)
        return None


def persist(
    response_dict: dict,
    raw_input_hash: str,
    input_length: int,
    record_hash: Optional[str] = None,
    chain_prev_hash: Optional[str] = None,
) -> None:
    """
    Persist one audit run. Never raises — failures are logged and swallowed
    so they cannot affect the caller's response.

    Args:
        response_dict:    AuditResponse.model_dump() — already serialised.
        raw_input_hash:   SHA-256 hex of the original input text.
        input_length:     Character count of the original input.
        record_hash:      DoCR's integrity.record_hash (hash-chain anchor).
        chain_prev_hash:  Predecessor's record_hash, or None for genesis.
    """
    if not STORAGE_ENABLED:
        return
    try:
        row = (
            response_dict["run_id"],
            response_dict["timestamp"],
            response_dict["profile"],
            response_dict["status"],
            response_dict["overall_severity"],
            float(response_dict["overall_confidence"]),
            int(bool(response_dict.get("safe_after_redaction", False))),
            raw_input_hash,
            input_length,
            int(response_dict.get("audit_summary", {}).get("finding_count", 0)),
            json.dumps(response_dict),
            record_hash,
            chain_prev_hash,
        )
        conn = _connect()
        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO audit_runs (
                    run_id, timestamp, profile, status,
                    overall_severity, overall_confidence, safe_after_redaction,
                    input_hash, input_length, finding_count, response_json,
                    record_hash, chain_prev_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
        conn.close()
    except Exception:
        logger.exception("Audit persistence failed for run_id=%s — run result unaffected", response_dict.get("run_id"))


# ---------------------------------------------------------------------------
# Read — single run
# ---------------------------------------------------------------------------

def get_run(run_id: str) -> Optional[dict]:
    """
    Return the full stored AuditResponse dict for a run_id, or None if not found.

    Returns:
        Parsed dict ready to be passed to AuditResponse.model_validate(), or None.
    """
    if not STORAGE_ENABLED:
        return None
    try:
        conn = _connect()
        row = conn.execute(
            "SELECT response_json FROM audit_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        conn.close()
        if row is None:
            return None
        return json.loads(row["response_json"])
    except Exception:
        logger.exception("Failed to retrieve run_id=%s", run_id)
        return None


# ---------------------------------------------------------------------------
# Read — history list
# ---------------------------------------------------------------------------

def get_history(
    limit: int = _HISTORY_LIMIT_DEFAULT,
    offset: int = 0,
    status_filter: Optional[str] = None,
    profile_filter: Optional[str] = None,
) -> tuple[int, list[dict]]:
    """
    Return (total_matching_count, page_of_summary_rows).

    Summary rows contain scalar columns only — response_json is NOT returned
    here to keep list responses lightweight.

    Args:
        limit:          Max rows to return (capped at HISTORY_LIMIT_MAX).
        offset:         Rows to skip (for pagination).
        status_filter:  Optional exact match on `status` column.
        profile_filter: Optional exact match on `profile` column.

    Returns:
        (total, rows) where rows is a list of dicts.
    """
    if not STORAGE_ENABLED:
        return (0, [])
    try:
        limit = max(1, min(limit, _HISTORY_LIMIT_MAX))
        offset = max(0, offset)

        where_clauses: list[str] = []
        params: list = []
        if status_filter:
            where_clauses.append("status = ?")
            params.append(status_filter)
        if profile_filter:
            where_clauses.append("profile = ?")
            params.append(profile_filter)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        conn = _connect()
        total = conn.execute(
            f"SELECT COUNT(*) FROM audit_runs {where_sql}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""
            SELECT run_id, timestamp, profile, status,
                   overall_severity, overall_confidence,
                   safe_after_redaction, input_hash, input_length, finding_count
            FROM audit_runs
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
        conn.close()

        return (total, [dict(r) for r in rows])
    except Exception:
        logger.exception("Failed to retrieve audit history")
        return (0, [])
