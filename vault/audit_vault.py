#!/usr/bin/env python3
"""
Cryptographically Tamper-Evident Audit Vault (v1.3.0)
Appends events to a sequential SHA-256 cryptographic hash-chain ledger
with exclusive advisory file locking, pre-append integrity gating,
strict schema validation, and optional external chain-head anchoring.

Each record commits to:
  Hash_n = SHA-256(index | timestamp | topic | payload | prev_hash)

Usage:
  python3 audit_vault.py --verify [--vault-file path/to/audit_chain.jsonl] [--require-records] [--anchor-file path]
  python3 audit_vault.py --append '{"event": "probe", "severity": "WARNING"}' [--topic security.alerts.kernel]
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


def compute_record_hash(index: int, timestamp: float, topic: str, data: dict, prev_hash: str) -> str:
    """Computes deterministic SHA-256 over serialized record tuple."""
    payload_str = json.dumps(data, sort_keys=True, allow_nan=False)
    raw_blob = f"{index}|{timestamp}|{topic}|{payload_str}|{prev_hash}".encode("utf-8")
    return hashlib.sha256(raw_blob).hexdigest()


def validate_record_schema(rec: dict, line_num: int, expected_index: int, expected_prev_hash: str) -> None:
    """Strictly validates record types, schema constraints, and sequential index continuity."""
    if not isinstance(rec, dict):
        raise ValueError(f"Line {line_num}: Record is not a valid JSON object")

    for required_key in ("index", "timestamp", "topic", "data", "prev_hash", "hash"):
        if required_key not in rec:
            raise ValueError(f"Line {line_num}: Missing required key '{required_key}'")

    idx = rec["index"]
    if not isinstance(idx, int) or isinstance(idx, bool):
        raise ValueError(f"Line {line_num}: Field 'index' must be a valid integer, got {type(idx).__name__}")
    if idx != expected_index:
        raise ValueError(f"Line {line_num}: Index discontinuity: expected {expected_index}, got {idx}")

    ts = rec["timestamp"]
    if not isinstance(ts, (int, float)) or not math.isfinite(ts):
        raise ValueError(f"Line {line_num}: Field 'timestamp' must be a finite numeric value, got {ts}")

    topic = rec["topic"]
    if not isinstance(topic, str) or not topic.strip():
        raise ValueError(f"Line {line_num}: Field 'topic' must be a non-empty string")

    data = rec["data"]
    if not isinstance(data, dict):
        raise ValueError(f"Line {line_num}: Field 'data' must be a dictionary, got {type(data).__name__}")

    p_hash = rec["prev_hash"]
    if not isinstance(p_hash, str) or len(p_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in p_hash):
        raise ValueError(f"Line {line_num}: Field 'prev_hash' must be a 64-character hexadecimal SHA-256 digest")
    if p_hash.lower() != expected_prev_hash.lower():
        raise ValueError(f"Line {line_num}: Backward hash pointer mismatch: expected {expected_prev_hash}, got {p_hash}")

    curr_hash = rec["hash"]
    if not isinstance(curr_hash, str) or len(curr_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in curr_hash):
        raise ValueError(f"Line {line_num}: Field 'hash' must be a 64-character hexadecimal SHA-256 digest")

    computed_hash = compute_record_hash(idx, ts, topic, data, p_hash)
    if computed_hash.lower() != curr_hash.lower():
        raise ValueError(f"Line {line_num}: Self-digest mismatch at index {idx}: recorded {curr_hash}, computed {computed_hash}")


def verify_chain_stream(vault_path: str) -> tuple[bool, int, str, str]:
    """
    Verifies complete cryptographic integrity, sequential continuity, and strict schema.
    Returns: (is_valid, record_count, head_hash, error_message)
    """
    if not os.path.exists(vault_path):
        return True, 0, GENESIS_HASH, ""

    prev_hash = GENESIS_HASH
    record_count = 0

    with open(vault_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                return False, record_count, prev_hash, f"Corrupted JSON at line {line_num}: {e}"

            try:
                validate_record_schema(rec, line_num, expected_index=record_count, expected_prev_hash=prev_hash)
            except ValueError as e:
                return False, record_count, prev_hash, str(e)

            prev_hash = rec["hash"]
            record_count += 1

    return True, record_count, prev_hash, ""


def append_record(vault_path: str, topic: str, data: dict, anchor_path: str | None = None) -> dict:
    """
    Appends a new record under an exclusive OS file lock with pre-append chain verification.
    Guarantees ACID writer serialization and fail-closed integrity against corrupted histories.
    """
    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    os.makedirs(vault_dir, exist_ok=True)
    lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")

    with open(lock_path, "w") as lock_file:
        # Acquire exclusive non-blocking/blocking advisory lock
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            # 1. Pre-append Verification: Verify existing ledger integrity before mutation
            is_valid, record_count, last_hash, err = verify_chain_stream(vault_path)
            if not is_valid:
                raise RuntimeError(f"Audit vault append rejected: existing ledger is corrupt ({err})")

            # 2. Strict Serialization & Hashing
            new_index = record_count
            new_timestamp = time.time()
            new_hash = compute_record_hash(new_index, new_timestamp, topic, data, last_hash)

            record = {
                "index": new_index,
                "timestamp": new_timestamp,
                "topic": topic,
                "data": data,
                "prev_hash": last_hash,
                "hash": new_hash
            }

            # 3. Synchronous Durable Write
            serialized = json.dumps(record, sort_keys=True, allow_nan=False) + "\n"
            with open(vault_path, "a", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())

            # 4. Optional External Chain-Head Anchor Update
            if anchor_path:
                os.makedirs(os.path.dirname(os.path.abspath(anchor_path)), exist_ok=True)
                anchor_tmp = f"{anchor_path}.tmp.{os.getpid()}"
                with open(anchor_tmp, "w", encoding="utf-8") as af:
                    af.write(json.dumps({"index": new_index, "timestamp": new_timestamp, "head_hash": new_hash}) + "\n")
                    af.flush()
                    os.fsync(af.fileno())
                os.replace(anchor_tmp, anchor_path)

            return record

        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def verify_chain(vault_path: str, require_records: bool = False, anchor_path: str | None = None) -> bool:
    """CLI wrapper for full ledger verification with anchor and record-count gating."""
    if not os.path.exists(vault_path):
        print(f"Error: Vault file not found at {vault_path}")
        return False

    is_valid, count, head_hash, err = verify_chain_stream(vault_path)
    if not is_valid:
        print(f"[FAIL] Cryptographic chain verification failed: {err}")
        return False

    if count == 0:
        if require_records:
            print("[FAIL] Audit ledger contains 0 records (empty ledger rejected under strict policy).")
            return False
        else:
            print("[INFO] Audit ledger verified clean (0 records, uninitialized state).")
            return True

    if anchor_path and os.path.exists(anchor_path):
        try:
            with open(anchor_path, "r", encoding="utf-8") as af:
                anchor_data = json.load(af)
            expected_head = anchor_data.get("head_hash")
            if expected_head and expected_head.lower() != head_hash.lower():
                print(f"[FAIL] External Anchor Divergence: ledger head {head_hash} != anchor head {expected_head}")
                return False
            print(f"[OK] External trust anchor verified: {expected_head}")
        except Exception as e:
            print(f"[FAIL] Failed to read external trust anchor: {e}")
            return False

    print(f"[OK] Cryptographic chain verified clean across {count:,} records.")
    print(f"   Head Hash: {head_hash}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Cryptographically Tamper-Evident Audit Vault (v1.3.0)")
    parser.add_argument("--vault-file", default=DEFAULT_VAULT_FILE, help="Path to audit_chain.jsonl")
    parser.add_argument("--verify", action="store_true", help="Verify chain integrity")
    parser.add_argument("--require-records", action="store_true", help="Reject empty ledgers during verification")
    parser.add_argument("--anchor-file", help="Path to external trust anchor checkpoint")
    parser.add_argument("--append", help="JSON data payload to append")
    parser.add_argument("--topic", default="security.alerts.kernel", help="Event topic")

    args = parser.parse_args()

    if args.verify:
        success = verify_chain(args.vault_file, require_records=args.require_records, anchor_path=args.anchor_file)
        sys.exit(0 if success else 1)
    elif args.append:
        try:
            data = json.loads(args.append)
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
