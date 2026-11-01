#!/usr/bin/env python3
"""
Cryptographically Tamper-Evident Audit Vault (v1.3.6)
Appends events to a sequential SHA-256 cryptographic hash-chain ledger
with canonical JSON hashing (versioned, zero delimiter ambiguity, strict key whitelisting,
recursive duplicate key rejection, bounded-depth recursive string-key dictionary validation,
and bounded epoch timestamps),
unified reader-writer advisory locking adhering to a strict global hierarchy (Level 1 Vault -> Level 2 Admin Log),
fail-closed append-time anchor parity gating with rigorous interrupted-commit verification,
mandatory documented justifications for forced trust-root resets,
TOCTOU-immune open file descriptor path collision defense with symbolic link rejection,
granular two-phase administrative write-ahead logging (PREPARED -> COMMITTED),
and automatic crash-recovery reconciliation into a tamper-evident administrative hash-chain.

Each record commits to:
  Hash_n = SHA-256(canonical_json({"version": 1, "index": n, "timestamp": ts, "topic": t, "data": payload, "prev_hash": h_{n-1}}))

Usage:
  python3 audit_vault.py --verify [--vault-file path/to/audit_chain.jsonl] [--require-records] [--anchor-file path]
  python3 audit_vault.py --verify-admin [--admin-log path]
  python3 audit_vault.py --recover-admin [--vault-file path] [--anchor-file path] [--admin-log path]
  python3 audit_vault.py --append '{"event": "probe", "severity": "WARNING"}' [--topic security.alerts.kernel] [--anchor-file path]
  python3 audit_vault.py --init-anchor [--vault-file path/to/audit_chain.jsonl] --anchor-file path [--force --reason "text"] [--admin-log path]
"""

import sys
import os
import time
import json
import math
import hashlib
import argparse
import fcntl

DEFAULT_VAULT_FILE = os.getenv("AUDIT_VAULT_FILE", "./audit_chain.jsonl")
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
RECORD_VERSION = 1
ADMIN_RECORD_VERSION = 1
RECORD_ALLOWED_KEYS = {"version", "index", "timestamp", "topic", "data", "prev_hash", "hash"}
ANCHOR_ALLOWED_KEYS = {"version", "index", "timestamp", "head_hash"}
ADMIN_ALLOWED_KEYS = {
    "action",
    "admin_hash",
    "admin_index",
    "anchor_path",
    "details",
    "new_head_hash",
    "new_index",
    "operator_pid",
    "operator_uid",
    "prev_admin_hash",
    "prior_anchor",
    "reason",
    "timestamp",
    "transaction_id",
    "vault_path",
    "version",
}
ADMIN_VALID_ACTIONS = {
    "TRUST_ROOT_RESET_PREPARED",
    "TRUST_ROOT_RESET_COMMITTED",
    "TRUST_ROOT_RESET_FAILED_BEFORE_REPLACEMENT",
    "TRUST_ROOT_RESET_REPLACEMENT_UNCERTAIN",
    "TRUST_ROOT_RESET_RECONCILED_COMMITTED",
    "TRUST_ROOT_RESET_RECONCILED_ABORTED",
    "TRUST_ROOT_RESET_RECOVERY_REQUIRED",
}
MAX_REALISTIC_EPOCH = 253402300799.0  # 31-Dec-9999 23:59:59 UTC


def rejecting_duplicates_object_pairs_hook(pairs: list[tuple[str, any]]) -> dict:
    """Strict JSON object pairs hook that raises ValueError on duplicate dictionary keys."""
    res = {}
    for key, val in pairs:
        if key in res:
            raise ValueError(f"Duplicate JSON key detected: '{key}'")
        res[key] = val
    return res


def validate_dict_keys_are_strings(obj: any, path: str = "data", depth: int = 0, max_depth: int = 32) -> None:
    """
    Recursively validates that all dictionary keys are strictly strings, preventing implicit coercion or duplicates.
    Enforces a maximum nesting depth to eliminate uncaught RecursionError on hostile or cyclical inputs.
    """
    if depth > max_depth:
        raise ValueError(f"Field '{path}' exceeds maximum allowable nesting depth of {max_depth}")
    if isinstance(obj, dict):
        seen_keys = set()
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"Field '{path}' contains non-string dictionary key: {k!r} ({type(k).__name__}). Strict contract requires string keys.")
            if k in seen_keys:
                raise ValueError(f"Field '{path}' contains duplicate key: {k!r}")
            seen_keys.add(k)
            validate_dict_keys_are_strings(v, f"{path}.{k}", depth=depth + 1, max_depth=max_depth)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            validate_dict_keys_are_strings(item, f"{path}[{i}]", depth=depth + 1, max_depth=max_depth)


def compute_record_hash(index: int, timestamp: float, topic: str, data: dict, prev_hash: str, version: int = RECORD_VERSION) -> str:
    """Computes deterministic SHA-256 over canonically serialized commitment dictionary."""
    commit_payload = {
        "data": data,
        "index": index,
        "prev_hash": prev_hash.lower(),
        "timestamp": timestamp,
        "topic": topic,
        "version": version
    }
    raw_blob = json.dumps(commit_payload, sort_keys=True, allow_nan=False, separators=(',', ':')).encode("utf-8")
    return hashlib.sha256(raw_blob).hexdigest()


def validate_record_schema(rec: dict, line_num: int, expected_index: int, expected_prev_hash: str) -> None:
    """Strictly validates record types, schema constraints, whitelisted keys, and sequential continuity."""
    if not isinstance(rec, dict):
        raise ValueError(f"Line {line_num}: Record is not a valid JSON object")

    keys = set(rec.keys())
    if keys != RECORD_ALLOWED_KEYS:
        extra = keys - RECORD_ALLOWED_KEYS
        missing = RECORD_ALLOWED_KEYS - keys
        if extra:
            raise ValueError(f"Line {line_num}: Unauthenticated extra field(s) detected: {sorted(list(extra))}")
        if missing:
            raise ValueError(f"Line {line_num}: Missing required field(s): {sorted(list(missing))}")

    ver = rec["version"]
    if not isinstance(ver, int) or isinstance(ver, bool) or ver != RECORD_VERSION:
        raise ValueError(f"Line {line_num}: Field 'version' must be an integer equal to {RECORD_VERSION}, got {ver!r} ({type(ver).__name__})")

    idx = rec["index"]
    if not isinstance(idx, int) or isinstance(idx, bool):
        raise ValueError(f"Line {line_num}: Field 'index' must be a valid integer, got {type(idx).__name__}")
    if idx != expected_index:
        raise ValueError(f"Line {line_num}: Index discontinuity: expected {expected_index}, got {idx}")

    ts = rec["timestamp"]
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        raise ValueError(f"Line {line_num}: Field 'timestamp' must be a numeric value, got {type(ts).__name__}")
    try:
        if not math.isfinite(ts):
            raise ValueError(f"Line {line_num}: Field 'timestamp' must be finite, got {ts}")
    except OverflowError:
        raise ValueError(f"Line {line_num}: Field 'timestamp' exceeds allowable numeric bounds (overflow)")
    if ts < 0.0 or ts > MAX_REALISTIC_EPOCH:
        raise ValueError(f"Line {line_num}: Field 'timestamp' out of realistic epoch range (0 to {MAX_REALISTIC_EPOCH}): {ts}")

    topic = rec["topic"]
    if not isinstance(topic, str) or not topic.strip():
        raise ValueError(f"Line {line_num}: Field 'topic' must be a non-empty string")

    data = rec["data"]
    if not isinstance(data, dict):
        raise ValueError(f"Line {line_num}: Field 'data' must be a dictionary, got {type(data).__name__}")
    validate_dict_keys_are_strings(data, path=f"Line {line_num} data")

    p_hash = rec["prev_hash"]
    if not isinstance(p_hash, str) or len(p_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in p_hash):
        raise ValueError(f"Line {line_num}: Field 'prev_hash' must be a 64-character hexadecimal SHA-256 digest")
    if p_hash.lower() != expected_prev_hash.lower():
        raise ValueError(f"Line {line_num}: Backward hash pointer mismatch: expected {expected_prev_hash}, got {p_hash}")

    curr_hash = rec["hash"]
    if not isinstance(curr_hash, str) or len(curr_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in curr_hash):
        raise ValueError(f"Line {line_num}: Field 'hash' must be a 64-character hexadecimal SHA-256 digest")

    computed_hash = compute_record_hash(idx, ts, topic, data, p_hash, version=ver)
    if computed_hash.lower() != curr_hash.lower():
        raise ValueError(f"Line {line_num}: Self-digest mismatch at index {idx}: recorded {curr_hash}, computed {computed_hash}")


def validate_anchor_schema(anchor_data: dict, anchor_path: str) -> None:
    """Strictly validates trust anchor dictionary structure, types, and bounded values."""
    if not isinstance(anchor_data, dict):
        raise ValueError(f"Anchor {anchor_path}: content is not a valid JSON dictionary")

    keys = set(anchor_data.keys())
    if keys != ANCHOR_ALLOWED_KEYS:
        extra = keys - ANCHOR_ALLOWED_KEYS
        missing = ANCHOR_ALLOWED_KEYS - keys
        if extra:
            raise ValueError(f"Anchor {anchor_path}: Unauthenticated extra field(s): {sorted(list(extra))}")
        if missing:
            raise ValueError(f"Anchor {anchor_path}: Missing required field(s): {sorted(list(missing))}")

    ver = anchor_data.get("version")
    if not isinstance(ver, int) or isinstance(ver, bool) or ver != RECORD_VERSION:
        raise ValueError(f"Anchor {anchor_path}: Field 'version' must be an integer equal to {RECORD_VERSION}, got {ver!r} ({type(ver).__name__})")

    idx = anchor_data.get("index")
    if not isinstance(idx, int) or isinstance(idx, bool):
        raise ValueError(f"Anchor {anchor_path}: 'index' must be a valid integer, got {type(idx).__name__}")
    if idx < -1:
        raise ValueError(f"Anchor {anchor_path}: 'index' cannot be less than -1, got {idx}")

    ts = anchor_data.get("timestamp")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        raise ValueError(f"Anchor {anchor_path}: 'timestamp' must be a numeric value, got {type(ts).__name__}")
    try:
        if not math.isfinite(ts):
            raise ValueError(f"Anchor {anchor_path}: 'timestamp' must be finite, got {ts}")
    except OverflowError:
        raise ValueError(f"Anchor {anchor_path}: 'timestamp' exceeds allowable numeric bounds (overflow)")
    if ts < 0.0 or ts > MAX_REALISTIC_EPOCH:
        raise ValueError(f"Anchor {anchor_path}: 'timestamp' out of realistic epoch range (0 to {MAX_REALISTIC_EPOCH}): {ts}")

    head = anchor_data.get("head_hash")
    if not isinstance(head, str) or len(head) != 64 or not all(c in "0123456789abcdefABCDEF" for c in head):
        raise ValueError(f"Anchor {anchor_path}: 'head_hash' must be a 64-character hexadecimal SHA-256 digest")
    if idx == -1 and head.lower() != GENESIS_HASH:
        raise ValueError(f"Anchor {anchor_path}: Uninitialized anchor (index -1) must have genesis head hash ({GENESIS_HASH}), got {head}")


def _verify_chain_stream_unlocked(vault_path: str) -> tuple[bool, int, str, str, str]:
    """
    Internal stream verifier without locking; caller must hold lock if synchronization is required.
    Returns: (is_valid, record_count, last_hash, penultimate_hash, err)
    """
    if not os.path.exists(vault_path):
        return True, 0, GENESIS_HASH, GENESIS_HASH, ""

    prev_hash = GENESIS_HASH
    penultimate_hash = GENESIS_HASH
    record_count = 0

    with open(vault_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                rec = json.loads(line, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
            except (json.JSONDecodeError, ValueError) as e:
                return False, record_count, prev_hash, penultimate_hash, f"Corrupted or invalid JSON at line {line_num}: {e}"

            try:
                validate_record_schema(rec, line_num, expected_index=record_count, expected_prev_hash=prev_hash)
            except ValueError as e:
                return False, record_count, prev_hash, penultimate_hash, str(e)

            penultimate_hash = prev_hash
            prev_hash = rec["hash"].lower()
            record_count += 1

    return True, record_count, prev_hash, penultimate_hash, ""


def verify_chain_stream(vault_path: str) -> tuple[bool, int, str, str]:
    """Public thread-safe stream verifier with shared advisory locking (LOCK_SH)."""
    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")
    os.makedirs(vault_dir, exist_ok=True)

    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
        try:
            if not os.path.exists(vault_path):
                return True, 0, GENESIS_HASH, ""
            is_valid, count, head, _penult, err = _verify_chain_stream_unlocked(vault_path)
            return is_valid, count, head, err
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def durable_write_anchor(anchor_path: str, index: int, timestamp: float, head_hash: str) -> None:
    """Writes anchor checkpoint atomically with file and parent-directory fsync."""
    anchor_dir = os.path.dirname(os.path.abspath(anchor_path))
    os.makedirs(anchor_dir, exist_ok=True)
    anchor_tmp = f"{anchor_path}.tmp.{os.getpid()}_{time.time_ns()}"

    anchor_content = {
        "head_hash": head_hash.lower(),
        "index": index,
        "timestamp": timestamp,
        "version": RECORD_VERSION
    }

    with open(anchor_tmp, "w", encoding="utf-8") as af:
        af.write(json.dumps(anchor_content, sort_keys=True, allow_nan=False, separators=(',', ':')) + "\n")
        af.flush()
        os.fsync(af.fileno())

    os.replace(anchor_tmp, anchor_path)

    # Fsync directory to guarantee atomic rename durability on crash/reboot
    dir_fd = os.open(anchor_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def append_record(vault_path: str, topic: str, data: dict, anchor_path: str | None = None) -> dict:
    """
    Appends a new record under an exclusive OS advisory lock (LOCK_EX) with pre-append
    chain and external anchor verification. Guarantees serialized execution for cooperating writers.
    """
    # 1. Prospective Input Validation
    if not isinstance(topic, str) or not topic.strip():
        raise ValueError("Field 'topic' must be a non-empty string")
    if not isinstance(data, dict):
        raise ValueError(f"Field 'data' must be a dictionary, got {type(data).__name__}")
    validate_dict_keys_are_strings(data, path="data")
    try:
        json.dumps(data, sort_keys=True, allow_nan=False, separators=(',', ':'))
    except (ValueError, TypeError) as e:
        raise ValueError(f"Field 'data' failed strict JSON serialization: {e}")

    if anchor_path and _is_path_collision(anchor_path, vault_path):
        raise ValueError(f"Invalid configuration: external trust anchor collides with ledger vault file: '{anchor_path}' -> '{vault_path}'")

    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    os.makedirs(vault_dir, exist_ok=True)
    lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")

    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            # 2. Pre-append Chain Verification: Verify existing ledger integrity before mutation
            is_valid, record_count, last_hash, penultimate_hash, err = _verify_chain_stream_unlocked(vault_path)
            if not is_valid:
                raise RuntimeError(f"Audit vault append rejected: existing ledger is corrupt ({err})")

            # 3. Pre-append Anchor Verification: Fail-closed verification of existing anchor
            if anchor_path:
                if not os.path.exists(anchor_path):
                    raise RuntimeError(
                        f"Audit vault append rejected: anchor_path specified but '{anchor_path}' does not exist. "
                        f"Explicit bootstrap via --init-anchor is required before appends are permitted."
                    )

                try:
                    with open(anchor_path, "r", encoding="utf-8") as af:
                        anchor_data = json.load(af, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
                    validate_anchor_schema(anchor_data, anchor_path)
                except Exception as e:
                    raise RuntimeError(f"Audit vault append rejected: existing anchor is corrupt or invalid ({e})")

                anchor_head = anchor_data["head_hash"].lower()
                anchor_idx = anchor_data["index"]
                expected_prior_idx = record_count - 1 if record_count > 0 else -1

                if anchor_head != last_hash.lower() or anchor_idx != expected_prior_idx:
                    # Rigorous Interrupted-Commit Check:
                    # 1. Ledger has exactly one more record than anchor (record_count == anchor_idx + 2)
                    # 2. The anchor hash matches the actual historical ledger record at anchor_idx (penultimate_hash)
                    if record_count == anchor_idx + 2 and anchor_head == penultimate_hash.lower():
                        state_msg = (
                            f"INTERRUPTED COMMIT DETECTED! "
                            f"Ledger advanced to index {record_count - 1} ({last_hash[:16]}...) while anchor remained at index {anchor_idx} ({anchor_head[:16]}...). "
                            f"The anchor hash matches the verified historical ledger record (#{anchor_idx}). "
                            f"Storage commit was likely interrupted between ledger fsync and anchor update. "
                            f"Requires operator investigation or authorized anchor resynchronization."
                        )
                    else:
                        state_msg = (
                            f"EXTERNAL ANCHOR DIVERGENCE! "
                            f"Ledger head (idx={expected_prior_idx}, hash={last_hash}) != anchor (idx={anchor_idx}, hash={anchor_head}). "
                            f"Anchor does not match prior ledger history. Refusing to append to diverged history."
                        )
                    raise RuntimeError(f"Audit vault append rejected: {state_msg}")

            # 4. Canonical Serialization & Hashing
            new_index = record_count
            new_timestamp = time.time()
            new_hash = compute_record_hash(new_index, new_timestamp, topic, data, last_hash, version=RECORD_VERSION)

            record = {
                "version": RECORD_VERSION,
                "index": new_index,
                "timestamp": new_timestamp,
                "topic": topic,
                "data": data,
                "prev_hash": last_hash.lower(),
                "hash": new_hash.lower()
            }

            # 5. Synchronous Durable Write
            serialized = json.dumps(record, sort_keys=True, allow_nan=False, separators=(',', ':')) + "\n"
            with open(vault_path, "a", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())

            # 6. Durable External Chain-Head Anchor Update
            if anchor_path:
                try:
                    durable_write_anchor(anchor_path, new_index, new_timestamp, new_hash)
                except Exception as e:
                    raise RuntimeError(
                        f"DURABLE_COMMIT_UNCERTAIN: Record #{new_index} was durably written and fsynced to ledger ({vault_path}), "
                        f"but external trust anchor update to '{anchor_path}' failed ({e}). "
                        f"Ledger and anchor are now in an interrupted-commit state."
                    )

            return record

        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def verify_chain(vault_path: str, require_records: bool = False, anchor_path: str | None = None) -> bool:
    """
    CLI wrapper for full ledger and anchor verification.
    Holds a unified shared advisory lock (LOCK_SH) across BOTH ledger and anchor verification.
    """
    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")
    os.makedirs(vault_dir, exist_ok=True)

    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
        try:
            if not os.path.exists(vault_path):
                print(f"Error: Vault file not found at {vault_path}")
                return False

            is_valid, count, head_hash, _penult, err = _verify_chain_stream_unlocked(vault_path)
            if not is_valid:
                print(f"[FAIL] Cryptographic chain verification failed: {err}")
                return False

            if anchor_path:
                if not os.path.exists(anchor_path):
                    print(f"[FAIL] Configured external trust anchor not found at {anchor_path}")
                    return False
                try:
                    with open(anchor_path, "r", encoding="utf-8") as af:
                        anchor_data = json.load(af, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
                    validate_anchor_schema(anchor_data, anchor_path)
                except Exception as e:
                    print(f"[FAIL] Failed to read or validate external trust anchor: {e}")
                    return False

                expected_head = anchor_data["head_hash"].lower()
                expected_idx = anchor_data["index"]
                expected_last_idx = count - 1 if count > 0 else -1

                if expected_idx != expected_last_idx:
                    print(f"[FAIL] External Anchor Index Mismatch: ledger last index {expected_last_idx} != anchor index {expected_idx}")
                    return False
                if expected_head != head_hash.lower():
                    print(f"[FAIL] External Anchor Divergence: ledger head {head_hash} != anchor head {expected_head}")
                    return False
                print(f"[OK] External trust anchor verified: index {expected_idx}, head {expected_head}")

            if count == 0:
                if require_records:
                    print("[FAIL] Audit ledger contains 0 records (empty ledger rejected under strict policy).")
                    return False
                else:
                    print("[INFO] Audit ledger verified clean (0 records, uninitialized state).")
                    return True

            print(f"[OK] Cryptographic chain verified clean across {count:,} records.")
            print(f"   Head Hash: {head_hash}")
            return True

        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def compute_admin_event_hash(
    action: str,
    admin_index: int,
    anchor_path: str,
    details: dict,
    new_head_hash: str,
    new_index: int,
    operator_pid: int | None,
    operator_uid: int | None,
    prev_admin_hash: str,
    prior_anchor: dict | None,
    reason: str,
    timestamp: float,
    transaction_id: str,
    vault_path: str,
    version: int = ADMIN_RECORD_VERSION,
) -> str:
    """Computes deterministic SHA-256 over canonical administrative commitment dictionary."""
    commit_payload = {
        "action": action,
        "admin_index": admin_index,
        "anchor_path": anchor_path,
        "details": details if details is not None else {},
        "new_head_hash": new_head_hash,
        "new_index": new_index,
        "operator_pid": operator_pid,
        "operator_uid": operator_uid,
        "prev_admin_hash": prev_admin_hash.lower(),
        "prior_anchor": prior_anchor,
        "reason": reason,
        "timestamp": timestamp,
        "transaction_id": transaction_id,
        "vault_path": vault_path,
        "version": version,
    }
    raw_blob = json.dumps(commit_payload, sort_keys=True, allow_nan=False, separators=(',', ':')).encode("utf-8")
    return hashlib.sha256(raw_blob).hexdigest()


def validate_admin_record_schema(rec: dict, line_num: int, expected_index: int, expected_prev_hash: str) -> None:
    """Strictly validates administrative record types, schema constraints, whitelisted keys, and sequential continuity."""
    if not isinstance(rec, dict):
        raise ValueError(f"Admin Line {line_num}: Record is not a valid JSON object")

    keys = set(rec.keys())
    if keys != ADMIN_ALLOWED_KEYS:
        extra = keys - ADMIN_ALLOWED_KEYS
        missing = ADMIN_ALLOWED_KEYS - keys
        if extra:
            raise ValueError(f"Admin Line {line_num}: Unauthenticated extra field(s) detected: {sorted(list(extra))}")
        if missing:
            raise ValueError(f"Admin Line {line_num}: Missing required field(s): {sorted(list(missing))}")

    ver = rec["version"]
    if not isinstance(ver, int) or isinstance(ver, bool) or ver != ADMIN_RECORD_VERSION:
        raise ValueError(f"Admin Line {line_num}: Field 'version' must be integer equal to {ADMIN_RECORD_VERSION}, got {ver!r}")

    idx = rec["admin_index"]
    if not isinstance(idx, int) or isinstance(idx, bool):
        raise ValueError(f"Admin Line {line_num}: Field 'admin_index' must be integer, got {type(idx).__name__}")
    if idx != expected_index:
        raise ValueError(f"Admin Line {line_num}: Index discontinuity: expected {expected_index}, got {idx}")

    ts = rec["timestamp"]
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        raise ValueError(f"Admin Line {line_num}: Field 'timestamp' must be numeric, got {type(ts).__name__}")
    try:
        if not math.isfinite(ts):
            raise ValueError(f"Admin Line {line_num}: Field 'timestamp' must be finite, got {ts}")
    except OverflowError:
        raise ValueError(f"Admin Line {line_num}: Field 'timestamp' exceeds bounds")
    if ts < 0.0 or ts > MAX_REALISTIC_EPOCH:
        raise ValueError(f"Admin Line {line_num}: Field 'timestamp' out of realistic epoch range: {ts}")

    action = rec["action"]
    if action not in ADMIN_VALID_ACTIONS:
        raise ValueError(f"Admin Line {line_num}: Unknown administrative action: {action!r}")

    tx_id = rec["transaction_id"]
    if not isinstance(tx_id, str) or not tx_id.strip():
        raise ValueError(f"Admin Line {line_num}: Field 'transaction_id' must be non-empty string")

    p_hash = rec["prev_admin_hash"]
    if not isinstance(p_hash, str) or len(p_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in p_hash):
        raise ValueError(f"Admin Line {line_num}: Field 'prev_admin_hash' must be 64-char hex digest")
    if p_hash.lower() != expected_prev_hash.lower():
        raise ValueError(f"Admin Line {line_num}: Backward hash mismatch: expected {expected_prev_hash}, got {p_hash}")

    curr_hash = rec["admin_hash"]
    if not isinstance(curr_hash, str) or len(curr_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in curr_hash):
        raise ValueError(f"Admin Line {line_num}: Field 'admin_hash' must be 64-char hex digest")

    details = rec.get("details", {})
    if not isinstance(details, dict):
        raise ValueError(f"Admin Line {line_num}: Field 'details' must be a dictionary")
    validate_dict_keys_are_strings(details, path=f"Admin Line {line_num} details")

    computed = compute_admin_event_hash(
        action=action,
        admin_index=idx,
        anchor_path=rec["anchor_path"],
        details=details,
        new_head_hash=rec["new_head_hash"],
        new_index=rec["new_index"],
        operator_pid=rec["operator_pid"],
        operator_uid=rec["operator_uid"],
        prev_admin_hash=p_hash,
        prior_anchor=rec["prior_anchor"],
        reason=rec["reason"],
        timestamp=ts,
        transaction_id=tx_id,
        vault_path=rec["vault_path"],
        version=ver,
    )
    if computed.lower() != curr_hash.lower():
        raise ValueError(f"Admin Line {line_num}: Self-digest mismatch: recorded {curr_hash}, computed {computed}")


def verify_admin_chain(admin_log: str) -> tuple[bool, int, str, str]:
    """
    Cryptographically verifies the administrative audit hash chain.
    Returns: (is_valid, record_count, last_hash, err_msg)
    """
    if not os.path.exists(admin_log):
        return True, 0, GENESIS_HASH, ""

    admin_dir = os.path.dirname(os.path.abspath(admin_log))
    lock_path = os.path.join(admin_dir, f".{os.path.basename(admin_log)}.lock")
    os.makedirs(admin_dir, exist_ok=True)

    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
        try:
            prev_hash = GENESIS_HASH
            count = 0
            with open(admin_log, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
                    except Exception as e:
                        return False, count, prev_hash, f"Corrupted JSON at admin line {line_num}: {e}"
                    try:
                        validate_admin_record_schema(rec, line_num, expected_index=count, expected_prev_hash=prev_hash)
                    except ValueError as e:
                        return False, count, prev_hash, str(e)
                    prev_hash = rec["admin_hash"].lower()
                    count += 1
            return True, count, prev_hash, ""
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _is_path_collision(path_a: str, path_b: str) -> bool:
    """Checks whether two paths resolve to the same canonical filesystem location or inode."""
    norm_a = os.path.realpath(os.path.abspath(path_a))
    norm_b = os.path.realpath(os.path.abspath(path_b))
    if norm_a == norm_b:
        return True
    try:
        if os.path.exists(path_a) and os.path.exists(path_b):
            return os.path.samefile(path_a, path_b)
    except OSError:
        pass
    return False


def _open_admin_log_fd_safe(admin_log: str, vault_path: str, anchor_path: str) -> tuple[int, bool]:
    """
    Opens administrative log with restrictive permissions (0600) and verifies under open file descriptors
    that it does not collide with vault_path or anchor_path. Rejects symlinks to eliminate TOCTOU races.
    """
    if os.path.islink(admin_log):
        raise ValueError(f"Security violation: administrative audit log cannot be a symbolic link: {admin_log}")

    admin_dir = os.path.dirname(os.path.abspath(admin_log))
    os.makedirs(admin_dir, exist_ok=True)

    is_new = not os.path.exists(admin_log)
    open_flags = os.O_CREAT | os.O_RDWR | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(admin_log, open_flags, 0o600)
    try:
        os.chmod(admin_log, 0o600)
        admin_st = os.fstat(fd)

        # TOCTOU Inode verification against vault file
        if os.path.exists(vault_path):
            v_fd = os.open(vault_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                v_st = os.fstat(v_fd)
                if (admin_st.st_dev, admin_st.st_ino) == (v_st.st_dev, v_st.st_ino):
                    raise ValueError(f"TOCTOU Collision: administrative audit log shares inode with ledger vault file ({admin_log})")
            finally:
                os.close(v_fd)

        # TOCTOU Inode verification against anchor file
        if os.path.exists(anchor_path):
            a_fd = os.open(anchor_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                a_st = os.fstat(a_fd)
                if (admin_st.st_dev, admin_st.st_ino) == (a_st.st_dev, a_st.st_ino):
                    raise ValueError(f"TOCTOU Collision: administrative audit log shares inode with trust anchor file ({admin_log})")
            finally:
                os.close(a_fd)

        return fd, is_new
    except Exception:
        os.close(fd)
        raise


def _get_admin_log_tail(admin_log: str) -> tuple[int, str]:
    """Scans admin log to retrieve the next index and prior hash."""
    if not os.path.exists(admin_log) or os.path.getsize(admin_log) == 0:
        return 0, GENESIS_HASH

    count = 0
    last_hash = GENESIS_HASH
    with open(admin_log, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
            count = rec["admin_index"] + 1
            last_hash = rec["admin_hash"].lower()
    return count, last_hash


def _append_admin_event_unlocked(
    admin_log: str,
    action: str,
    transaction_id: str,
    anchor_path: str,
    vault_path: str,
    reason: str,
    prior_anchor: dict | None,
    new_head_hash: str,
    new_index: int,
    details: dict | None = None,
) -> dict:
    """Appends an administrative audit event to the cryptographic admin hash-chain (caller holds admin_lock)."""
    admin_fd, is_new = _open_admin_log_fd_safe(admin_log, vault_path, anchor_path)
    try:
        admin_index, prev_admin_hash = _get_admin_log_tail(admin_log)
        ts = time.time()
        op_pid = os.getpid()
        op_uid = os.getuid() if hasattr(os, "getuid") else None
        event_details = details if details is not None else {}

        admin_hash = compute_admin_event_hash(
            action=action,
            admin_index=admin_index,
            anchor_path=os.path.abspath(anchor_path),
            details=event_details,
            new_head_hash=new_head_hash,
            new_index=new_index,
            operator_pid=op_pid,
            operator_uid=op_uid,
            prev_admin_hash=prev_admin_hash,
            prior_anchor=prior_anchor,
            reason=reason,
            timestamp=ts,
            transaction_id=transaction_id,
            vault_path=os.path.abspath(vault_path),
            version=ADMIN_RECORD_VERSION,
        )

        record = {
            "action": action,
            "admin_hash": admin_hash.lower(),
            "admin_index": admin_index,
            "anchor_path": os.path.abspath(anchor_path),
            "details": event_details,
            "new_head_hash": new_head_hash,
            "new_index": new_index,
            "operator_pid": op_pid,
            "operator_uid": op_uid,
            "prev_admin_hash": prev_admin_hash.lower(),
            "prior_anchor": prior_anchor,
            "reason": reason,
            "timestamp": ts,
            "transaction_id": transaction_id,
            "vault_path": os.path.abspath(vault_path),
            "version": ADMIN_RECORD_VERSION,
        }

        serialized = json.dumps(record, sort_keys=True, allow_nan=False, separators=(',', ':')) + "\n"
        encoded = serialized.encode("utf-8")

        written = 0
        while written < len(encoded):
            n = os.write(admin_fd, encoded[written:])
            if n == 0:
                raise OSError("Zero bytes written to admin log")
            written += n
        os.fsync(admin_fd)
    finally:
        os.close(admin_fd)

    if is_new:
        admin_dir = os.path.dirname(os.path.abspath(admin_log))
        dir_fd = os.open(admin_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    return record


def _append_admin_event(
    admin_log: str,
    action: str,
    transaction_id: str,
    anchor_path: str,
    vault_path: str,
    reason: str,
    prior_anchor: dict | None,
    new_head_hash: str,
    new_index: int,
    details: dict | None = None,
) -> dict:
    """Public wrapper that acquires Level 2 (Admin Log) lock if not already held."""
    admin_dir = os.path.dirname(os.path.abspath(admin_log))
    os.makedirs(admin_dir, exist_ok=True)
    admin_lock_path = os.path.join(admin_dir, f".{os.path.basename(admin_log)}.lock")

    with open(admin_lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            return _append_admin_event_unlocked(
                admin_log=admin_log,
                action=action,
                transaction_id=transaction_id,
                anchor_path=anchor_path,
                vault_path=vault_path,
                reason=reason,
                prior_anchor=prior_anchor,
                new_head_hash=new_head_hash,
                new_index=new_index,
                details=details,
            )
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _recover_admin_transaction_unlocked(vault_path: str, anchor_path: str, admin_log: str) -> dict:
    """Internal recovery routine under held locks (Level 1 Vault and Level 2 Admin)."""
    if not os.path.exists(admin_log) or os.path.getsize(admin_log) == 0:
        return {"status": "CLEAN", "message": "No administrative log found"}

    last_rec = None
    with open(admin_log, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    last_rec = json.loads(line, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
                except Exception as e:
                    return {"status": "CORRUPT_ADMIN_LOG", "message": f"Corrupted admin line: {e}"}

    if not last_rec:
        return {"status": "CLEAN", "message": "Administrative log is empty"}

    action = last_rec.get("action")
    if action in {
        "TRUST_ROOT_RESET_COMMITTED",
        "TRUST_ROOT_RESET_FAILED_BEFORE_REPLACEMENT",
        "TRUST_ROOT_RESET_RECONCILED_COMMITTED",
        "TRUST_ROOT_RESET_RECONCILED_ABORTED",
    }:
        return {"status": "CLEAN", "message": f"Last transaction was already resolved ({action})"}

    if action in {"TRUST_ROOT_RESET_PREPARED", "TRUST_ROOT_RESET_REPLACEMENT_UNCERTAIN"}:
        tx_id = last_rec.get("transaction_id", "unknown")
        target_head = (last_rec.get("new_head_hash") or "").lower()
        target_idx = last_rec.get("new_index")
        prior = last_rec.get("prior_anchor")
        prior_head = (prior.get("head_hash") or "").lower() if isinstance(prior, dict) else None
        prior_idx = prior.get("index") if isinstance(prior, dict) else None

        if os.path.exists(anchor_path):
            try:
                with open(anchor_path, "r", encoding="utf-8") as af:
                    curr_anchor = json.load(af, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
                curr_head = (curr_anchor.get("head_hash") or "").lower()
                curr_idx = curr_anchor.get("index")
            except Exception as e:
                curr_anchor = None
                curr_head = None
                curr_idx = None

            if curr_anchor is not None and curr_head == target_head and curr_idx == target_idx:
                _append_admin_event_unlocked(
                    admin_log=admin_log,
                    action="TRUST_ROOT_RESET_RECONCILED_COMMITTED",
                    transaction_id=tx_id,
                    anchor_path=anchor_path,
                    vault_path=vault_path,
                    reason=f"Recovery reconciled: anchor on disk matches intended target state (from {action})",
                    prior_anchor=prior,
                    new_head_hash=target_head,
                    new_index=target_idx,
                    details={"reconciled_from": action, "resolved_anchor_head": curr_head}
                )
                return {
                    "status": "RECONCILED_COMMITTED",
                    "transaction_id": tx_id,
                    "message": f"Incomplete transaction {tx_id} reconciled: anchor replacement was confirmed on disk."
                }
            elif curr_anchor is not None and prior and curr_head == prior_head and curr_idx == prior_idx:
                _append_admin_event_unlocked(
                    admin_log=admin_log,
                    action="TRUST_ROOT_RESET_RECONCILED_ABORTED",
                    transaction_id=tx_id,
                    anchor_path=anchor_path,
                    vault_path=vault_path,
                    reason=f"Recovery reconciled: anchor on disk remains at prior state (from {action}); transaction aborted",
                    prior_anchor=prior,
                    new_head_hash=target_head,
                    new_index=target_idx,
                    details={"reconciled_from": action, "retained_prior_head": curr_head}
                )
                return {
                    "status": "RECONCILED_ABORTED",
                    "transaction_id": tx_id,
                    "message": f"Incomplete transaction {tx_id} reconciled: anchor was not replaced, marked aborted."
                }
            else:
                _append_admin_event_unlocked(
                    admin_log=admin_log,
                    action="TRUST_ROOT_RESET_RECOVERY_REQUIRED",
                    transaction_id=tx_id,
                    anchor_path=anchor_path,
                    vault_path=vault_path,
                    reason=f"Recovery failed: anchor matches neither prior nor intended target state (from {action})",
                    prior_anchor=prior,
                    new_head_hash=target_head,
                    new_index=target_idx,
                    details={"reconciled_from": action, "curr_head": curr_head, "curr_idx": curr_idx}
                )
                return {
                    "status": "RECOVERY_REQUIRED",
                    "transaction_id": tx_id,
                    "message": "CRITICAL: Anchor state is diverged from both prior and intended states. Manual operator intervention required."
                }
        else:
            if prior is None:
                _append_admin_event_unlocked(
                    admin_log=admin_log,
                    action="TRUST_ROOT_RESET_RECONCILED_ABORTED",
                    transaction_id=tx_id,
                    anchor_path=anchor_path,
                    vault_path=vault_path,
                    reason="Recovery reconciled: initial anchor creation interrupted before creation; marked aborted",
                    prior_anchor=None,
                    new_head_hash=target_head,
                    new_index=target_idx,
                    details={"reconciled_from": action}
                )
                return {"status": "RECONCILED_ABORTED", "transaction_id": tx_id, "message": "Initial bootstrap interrupted, marked aborted."}
            else:
                _append_admin_event_unlocked(
                    admin_log=admin_log,
                    action="TRUST_ROOT_RESET_RECOVERY_REQUIRED",
                    transaction_id=tx_id,
                    anchor_path=anchor_path,
                    vault_path=vault_path,
                    reason="Recovery failed: anchor file missing after interrupted reset",
                    prior_anchor=prior,
                    new_head_hash=target_head,
                    new_index=target_idx,
                    details={"reconciled_from": action, "missing_file": anchor_path}
                )
                return {"status": "RECOVERY_REQUIRED", "transaction_id": tx_id, "message": "CRITICAL: Anchor file missing after interrupted reset."}

    return {"status": "UNKNOWN_ACTION", "message": f"Unrecognized action in admin log: {action}"}


def recover_admin_transaction(vault_path: str, anchor_path: str, admin_audit_log: str | None = None) -> dict:
    """
    Public entrypoint for transaction recovery. Acquires Level 1 (Vault) -> Level 2 (Admin) lock
    and reconciles incomplete administrative transactions against disk state.
    """
    admin_log = admin_audit_log or os.getenv("AUDIT_VAULT_ADMIN_LOG")
    if not admin_log:
        anchor_dir = os.path.dirname(os.path.abspath(anchor_path))
        admin_log = os.path.join(anchor_dir, ".audit_vault_admin.log")

    if not os.path.exists(admin_log) or os.path.getsize(admin_log) == 0:
        return {"status": "CLEAN", "message": "No administrative log found"}

    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    vault_lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")
    admin_dir = os.path.dirname(os.path.abspath(admin_log))
    admin_lock_path = os.path.join(admin_dir, f".{os.path.basename(admin_log)}.lock")

    os.makedirs(vault_dir, exist_ok=True)
    os.makedirs(admin_dir, exist_ok=True)

    with open(vault_lock_path, "a+") as vault_lock_file:
        fcntl.flock(vault_lock_file.fileno(), fcntl.LOCK_EX)
        try:
            with open(admin_lock_path, "a+") as admin_lock_file:
                fcntl.flock(admin_lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    return _recover_admin_transaction_unlocked(vault_path, anchor_path, admin_log)
                finally:
                    fcntl.flock(admin_lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            fcntl.flock(vault_lock_file.fileno(), fcntl.LOCK_UN)


def init_anchor(
    vault_path: str,
    anchor_path: str,
    force: bool = False,
    reason: str | None = None,
    admin_audit_log: str | None = None,
) -> bool:
    """
    Explicitly bootstraps or resets the external trust anchor from a verified existing ledger.
    Adheres strictly to Level 1 (Vault) -> Level 2 (Admin Log) lock acquisition hierarchy.
    Enforces automatic crash-recovery reconciliation, TOCTOU collision defense via open file
    descriptors, and granular two-phase write-ahead logging (PREPARED -> COMMITTED)
    into a cryptographically tamper-evident administrative hash-chain.
    """
    if reason and not force:
        print("[FAIL] Invalid arguments: --reason is only permitted when resetting an existing trust root with --force.")
        return False

    if _is_path_collision(anchor_path, vault_path):
        print(f"[FAIL] Invalid configuration: anchor path collides with ledger vault file: {anchor_path}")
        return False

    admin_log = admin_audit_log or os.getenv("AUDIT_VAULT_ADMIN_LOG")
    if not admin_log:
        anchor_dir = os.path.dirname(os.path.abspath(anchor_path))
        admin_log = os.path.join(anchor_dir, ".audit_vault_admin.log")

    if force and os.path.exists(anchor_path):
        if _is_path_collision(admin_log, vault_path):
            print(f"[FAIL] Invalid configuration: administrative audit log collides with ledger vault file: {admin_log}")
            return False
        if _is_path_collision(admin_log, anchor_path):
            print(f"[FAIL] Invalid configuration: administrative audit log collides with trust anchor file: {admin_log}")
            return False

    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    vault_lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")
    os.makedirs(vault_dir, exist_ok=True)

    admin_dir = os.path.dirname(os.path.abspath(admin_log))
    admin_lock_path = os.path.join(admin_dir, f".{os.path.basename(admin_log)}.lock")
    os.makedirs(admin_dir, exist_ok=True)

    # Global Lock Hierarchy: Level 1 (Vault) -> Level 2 (Admin Log)
    with open(vault_lock_path, "a+") as vault_lock_file:
        fcntl.flock(vault_lock_file.fileno(), fcntl.LOCK_EX)
        try:
            with open(admin_lock_path, "a+") as admin_lock_file:
                fcntl.flock(admin_lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    # 1. Automatic Crash Recovery Reconciliation Check
                    rec_result = _recover_admin_transaction_unlocked(vault_path, anchor_path, admin_log)
                    if rec_result["status"] == "RECOVERY_REQUIRED":
                        print(f"[FAIL] Unreconciled prior administrative transaction requires manual intervention: {rec_result['message']}")
                        return False
                    elif rec_result["status"] in {"RECONCILED_COMMITTED", "RECONCILED_ABORTED"}:
                        print(f"[INFO] Prior interrupted administrative transaction was automatically reconciled: {rec_result['message']}")

                    if not os.path.exists(vault_path):
                        print(f"Error: Ledger file not found at {vault_path}")
                        return False

                    prior_anchor_data = None
                    if os.path.exists(anchor_path):
                        if not force:
                            print(f"[FAIL] Anchor file already exists at {anchor_path}. Overwrite refused without --force.")
                            return False
                        if not reason or not reason.strip():
                            print("[FAIL] Overwrite refused: --force requires a mandatory, non-empty --reason documenting operational justification.")
                            return False

                        try:
                            with open(anchor_path, "r", encoding="utf-8") as af:
                                raw_anchor = af.read()
                            prior_anchor_data = json.loads(raw_anchor, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
                            json.dumps(prior_anchor_data, allow_nan=False)
                        except Exception as e:
                            prior_anchor_data = {"error": f"unparseable_or_invalid: {e}"}

                    is_valid, count, head_hash, _penult, err = _verify_chain_stream_unlocked(vault_path)
                    if not is_valid:
                        print(f"[FAIL] Cannot initialize anchor: existing ledger is corrupt ({err})")
                        return False

                    last_idx = count - 1 if count > 0 else -1
                    ts = time.time()
                    is_forced_reset = force and (prior_anchor_data is not None)

                    if is_forced_reset:
                        tx_id = f"tx-{int(ts * 1e6)}-{os.getpid()}-{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}"

                        # Boundary 1: Write PREPARED event
                        try:
                            _append_admin_event_unlocked(
                                admin_log=admin_log,
                                action="TRUST_ROOT_RESET_PREPARED",
                                transaction_id=tx_id,
                                anchor_path=anchor_path,
                                vault_path=vault_path,
                                reason=reason.strip(),
                                prior_anchor=prior_anchor_data,
                                new_head_hash=head_hash,
                                new_index=last_idx,
                                details={"target": "anchor_replacement"}
                            )
                        except Exception as e:
                            print(f"[FAIL] Failed to log PREPARED intent to {admin_log}: {e}. Trust root reset aborted.")
                            return False

                        # Boundary 2: Write temporary anchor file
                        anchor_dir = os.path.dirname(os.path.abspath(anchor_path))
                        os.makedirs(anchor_dir, exist_ok=True)
                        anchor_tmp = f"{anchor_path}.tmp.{os.getpid()}_{time.time_ns()}"

                        anchor_content = {
                            "head_hash": head_hash.lower(),
                            "index": last_idx,
                            "timestamp": ts,
                            "version": RECORD_VERSION
                        }

                        try:
                            with open(anchor_tmp, "w", encoding="utf-8") as af:
                                af.write(json.dumps(anchor_content, sort_keys=True, allow_nan=False, separators=(',', ':')) + "\n")
                                af.flush()
                                os.fsync(af.fileno())
                        except Exception as e:
                            _append_admin_event_unlocked(
                                admin_log=admin_log,
                                action="TRUST_ROOT_RESET_FAILED_BEFORE_REPLACEMENT",
                                transaction_id=tx_id,
                                anchor_path=anchor_path,
                                vault_path=vault_path,
                                reason=reason.strip(),
                                prior_anchor=prior_anchor_data,
                                new_head_hash=head_hash,
                                new_index=last_idx,
                                details={"error": f"Failed writing temporary anchor: {e}", "boundary": "temp_file_fsync"}
                            )
                            print(f"[FAIL] Failed writing temporary anchor: {e}")
                            return False

                        # Boundary 3: Atomic rename
                        try:
                            os.replace(anchor_tmp, anchor_path)
                        except Exception as e:
                            _append_admin_event_unlocked(
                                admin_log=admin_log,
                                action="TRUST_ROOT_RESET_FAILED_BEFORE_REPLACEMENT",
                                transaction_id=tx_id,
                                anchor_path=anchor_path,
                                vault_path=vault_path,
                                reason=reason.strip(),
                                prior_anchor=prior_anchor_data,
                                new_head_hash=head_hash,
                                new_index=last_idx,
                                details={"error": f"Failed atomic rename: {e}", "boundary": "os_replace"}
                            )
                            print(f"[FAIL] Failed atomic anchor replacement: {e}")
                            return False

                        # Boundary 4: Parent directory fsync
                        try:
                            dir_fd = os.open(anchor_dir, os.O_RDONLY | os.O_DIRECTORY)
                            try:
                                os.fsync(dir_fd)
                            finally:
                                os.close(dir_fd)
                        except Exception as e:
                            _append_admin_event_unlocked(
                                admin_log=admin_log,
                                action="TRUST_ROOT_RESET_REPLACEMENT_UNCERTAIN",
                                transaction_id=tx_id,
                                anchor_path=anchor_path,
                                vault_path=vault_path,
                                reason=reason.strip(),
                                prior_anchor=prior_anchor_data,
                                new_head_hash=head_hash,
                                new_index=last_idx,
                                details={"error": f"Directory fsync failed after rename: {e}", "boundary": "directory_fsync"}
                            )
                            print(f"[WARN] ⚠️ Anchor replaced, but directory durability fsync failed: {e}")
                            return False

                        # Boundary 5: COMMITTED confirmation
                        try:
                            _append_admin_event_unlocked(
                                admin_log=admin_log,
                                action="TRUST_ROOT_RESET_COMMITTED",
                                transaction_id=tx_id,
                                anchor_path=anchor_path,
                                vault_path=vault_path,
                                reason=reason.strip(),
                                prior_anchor=prior_anchor_data,
                                new_head_hash=head_hash,
                                new_index=last_idx,
                                details={"completed": True, "boundary": "all_confirmed"}
                            )
                        except Exception as e:
                            print(f"[WARN] ⚠️ Anchor replaced, but COMMITTED event logging failed: {e}")

                        print(f"[WARN] ⚠️ TRUST ROOT RESET: Overwriting existing trust anchor at {anchor_path} (--force used).")
                        print(f"       Operator Reason: {reason.strip()}")
                        print(f"       Administrative Audit Logged (Two-Phase PREPARED -> COMMITTED): {admin_log}")
                    else:
                        durable_write_anchor(anchor_path, last_idx, ts, head_hash)

                    print(f"[OK] Trust anchor successfully initialized for ledger with {count} records:")
                    print(f"   Anchor Path: {anchor_path}")
                    print(f"   Head Hash:   {head_hash}")
                    print(f"   Last Index:  {last_idx}")
                    return True

                finally:
                    fcntl.flock(admin_lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            fcntl.flock(vault_lock_file.fileno(), fcntl.LOCK_UN)


def verify_chain(vault_path: str, require_records: bool = False, anchor_path: str | None = None) -> bool:
    """
    CLI wrapper for full ledger, anchor, and administrative audit chain verification.
    Adheres strictly to Level 1 (Vault) -> Level 2 (Admin Log) shared lock hierarchy (LOCK_SH).
    """
    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")
    os.makedirs(vault_dir, exist_ok=True)

    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
        try:
            if not os.path.exists(vault_path):
                print(f"Error: Vault file not found at {vault_path}")
                return False

            is_valid, count, head_hash, _penult, err = _verify_chain_stream_unlocked(vault_path)
            if not is_valid:
                print(f"[FAIL] Cryptographic chain verification failed: {err}")
                return False

            if anchor_path:
                if not os.path.exists(anchor_path):
                    print(f"[FAIL] Configured external trust anchor not found at {anchor_path}")
                    return False
                try:
                    with open(anchor_path, "r", encoding="utf-8") as af:
                        anchor_data = json.load(af, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
                    validate_anchor_schema(anchor_data, anchor_path)
                except Exception as e:
                    print(f"[FAIL] Failed to read or validate external trust anchor: {e}")
                    return False

                expected_head = anchor_data["head_hash"].lower()
                expected_idx = anchor_data["index"]
                expected_last_idx = count - 1 if count > 0 else -1

                if expected_idx != expected_last_idx:
                    print(f"[FAIL] External Anchor Index Mismatch: ledger last index {expected_last_idx} != anchor index {expected_idx}")
                    return False
                if expected_head != head_hash.lower():
                    print(f"[FAIL] External Anchor Divergence: ledger head {head_hash} != anchor head {expected_head}")
                    return False
                print(f"[OK] External trust anchor verified: index {expected_idx}, head {expected_head}")

                # If admin log exists, verify its cryptographic hash chain and reconcile any open transactions
                anchor_dir = os.path.dirname(os.path.abspath(anchor_path))
                admin_log = os.getenv("AUDIT_VAULT_ADMIN_LOG", os.path.join(anchor_dir, ".audit_vault_admin.log"))
                if os.path.exists(admin_log) and os.path.getsize(admin_log) > 0:
                    admin_ok, admin_count, admin_head, admin_err = verify_admin_chain(admin_log)
                    if not admin_ok:
                        print(f"[FAIL] Administrative audit log hash-chain verification failed: {admin_err}")
                        return False
                    print(f"[OK] Administrative audit hash-chain verified clean across {admin_count} events (Head: {admin_head[:16]}...)")

                    rec_result = recover_admin_transaction(vault_path, anchor_path, admin_audit_log=admin_log)
                    if rec_result["status"] == "RECOVERY_REQUIRED":
                        print(f"[FAIL] Administrative audit trail has unresolved recovery state: {rec_result['message']}")
                        return False

            if count == 0:
                if require_records:
                    print("[FAIL] Audit ledger contains 0 records (empty ledger rejected under strict policy).")
                    return False
                else:
                    print("[INFO] Audit ledger verified clean (0 records, uninitialized state).")
                    return True

            print(f"[OK] Cryptographic chain verified clean across {count:,} records.")
            print(f"   Head Hash: {head_hash}")
            return True

        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def main():
    parser = argparse.ArgumentParser(description="Cryptographically Tamper-Evident Audit Vault (v1.3.6)")
    parser.add_argument("--vault-file", default=DEFAULT_VAULT_FILE, help="Path to audit_chain.jsonl")
    parser.add_argument("--verify", action="store_true", help="Verify chain integrity")
    parser.add_argument("--verify-admin", action="store_true", help="Cryptographically verify administrative audit hash-chain")
    parser.add_argument("--recover-admin", action="store_true", help="Reconcile incomplete administrative transactions")
    parser.add_argument("--require-records", action="store_true", help="Reject empty ledgers during verification")
    parser.add_argument("--anchor-file", help="Path to external trust anchor checkpoint")
    parser.add_argument("--init-anchor", action="store_true", help="Explicitly bootstrap trust anchor from verified ledger")
    parser.add_argument("--force", action="store_true", help="Force overwrite existing anchor during --init-anchor")
    parser.add_argument("--reason", help="Mandatory documented reason for anchor reset when using --force")
    parser.add_argument("--admin-log", help="Path to administrative audit log file")
    parser.add_argument("--append", help="JSON data payload to append")
    parser.add_argument("--topic", default="security.alerts.kernel", help="Event topic")

    args = parser.parse_args()

    if args.init_anchor:
        if not args.anchor_file:
            print("Error: --init-anchor requires --anchor-file path")
            sys.exit(1)
        success = init_anchor(args.vault_file, args.anchor_file, force=args.force, reason=args.reason, admin_audit_log=args.admin_log)
        sys.exit(0 if success else 1)
    elif args.verify_admin:
        admin_log = args.admin_log or os.getenv("AUDIT_VAULT_ADMIN_LOG")
        if not admin_log:
            if args.anchor_file:
                anchor_dir = os.path.dirname(os.path.abspath(args.anchor_file))
                admin_log = os.path.join(anchor_dir, ".audit_vault_admin.log")
            else:
                admin_log = ".audit_vault_admin.log"
        is_valid, count, head, err = verify_admin_chain(admin_log)
        if not is_valid:
            print(f"[FAIL] Administrative audit chain verification failed: {err}")
            sys.exit(1)
        print(f"[OK] Administrative audit chain verified clean across {count} records. Head: {head}")
        sys.exit(0)
    elif args.recover_admin:
        if not args.anchor_file:
            print("Error: --recover-admin requires --anchor-file path")
            sys.exit(1)
        result = recover_admin_transaction(args.vault_file, args.anchor_file, admin_audit_log=args.admin_log)
        print(f"[{result['status']}] {result['message']}")
        sys.exit(0 if result["status"] in {"CLEAN", "RECONCILED_COMMITTED", "RECONCILED_ABORTED"} else 1)
    elif args.verify:
        success = verify_chain(args.vault_file, require_records=args.require_records, anchor_path=args.anchor_file)
        sys.exit(0 if success else 1)
    elif args.append:
        try:
            data = json.loads(args.append, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
            if not isinstance(data, dict):
                raise ValueError("JSON payload must be a dictionary object")
        except Exception as e:
            print(f"Invalid JSON payload: {e}")
            sys.exit(1)

        try:
            rec = append_record(args.vault_file, args.topic, data, anchor_path=args.anchor_file)
            print(f"[OK] Record #{rec['index']} committed: {rec['hash']}")
            sys.exit(0)
        except Exception as e:
            print(f"[FAIL] Append rejected: {e}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
