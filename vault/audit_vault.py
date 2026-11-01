#!/usr/bin/env python3
"""
Cryptographically Tamper-Evident Audit Vault (v1.3.1)
Appends events to a sequential SHA-256 cryptographic hash-chain ledger
with serialized advisory file locking (shared-read/exclusive-write),
pre-append chain and anchor verification, strict schema validation,
and external trust-anchor checkpointing with directory-level durability.

Each record commits to:
  Hash_n = SHA-256(index | timestamp | topic | payload | prev_hash)

Usage:
  python3 audit_vault.py --verify [--vault-file path/to/audit_chain.jsonl] [--require-records] [--anchor-file path]
  python3 audit_vault.py --append '{"event": "probe", "severity": "WARNING"}' [--topic security.alerts.kernel] [--anchor-file path]
  python3 audit_vault.py --init-anchor [--vault-file path/to/audit_chain.jsonl] --anchor-file path
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


def _verify_chain_stream_unlocked(vault_path: str) -> tuple[bool, int, str, str]:
    """Internal stream verifier without locking; caller must hold lock if synchronization is required."""
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


def verify_chain_stream(vault_path: str) -> tuple[bool, int, str, str]:
    """
    Verifies complete cryptographic integrity, sequential continuity, and strict schema.
    Acquires a shared advisory lock (LOCK_SH) to prevent reading concurrent half-written lines.
    Returns: (is_valid, record_count, head_hash, error_message)
    """
    if not os.path.exists(vault_path):
        return True, 0, GENESIS_HASH, ""

    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")
    os.makedirs(vault_dir, exist_ok=True)

    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
        try:
            return _verify_chain_stream_unlocked(vault_path)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def durable_write_anchor(anchor_path: str, index: int, timestamp: float, head_hash: str) -> None:
    """Writes anchor checkpoint atomically with file and parent-directory fsync."""
    anchor_dir = os.path.dirname(os.path.abspath(anchor_path))
    os.makedirs(anchor_dir, exist_ok=True)
    anchor_tmp = f"{anchor_path}.tmp.{os.getpid()}_{time.time_ns()}"

    with open(anchor_tmp, "w", encoding="utf-8") as af:
        af.write(json.dumps({"index": index, "timestamp": timestamp, "head_hash": head_hash}, sort_keys=True) + "\n")
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
    try:
        json.dumps(data, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Field 'data' failed strict JSON serialization: {e}")

    vault_dir = os.path.dirname(os.path.abspath(vault_path))
    os.makedirs(vault_dir, exist_ok=True)
    lock_path = os.path.join(vault_dir, f".{os.path.basename(vault_path)}.lock")

    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            # 2. Pre-append Chain Verification: Verify existing ledger integrity before mutation
            is_valid, record_count, last_hash, err = _verify_chain_stream_unlocked(vault_path)
            if not is_valid:
                raise RuntimeError(f"Audit vault append rejected: existing ledger is corrupt ({err})")

            # 3. Pre-append Anchor Verification: Verify existing anchor before advancing history
            if anchor_path:
                if os.path.exists(anchor_path):
                    try:
                        with open(anchor_path, "r", encoding="utf-8") as af:
                            anchor_data = json.load(af)
                    except Exception as e:
                        raise RuntimeError(f"Audit vault append rejected: existing anchor is corrupt or unreadable ({e})")

                    anchor_head = anchor_data.get("head_hash")
                    anchor_idx = anchor_data.get("index")

                    if not isinstance(anchor_head, str) or len(anchor_head) != 64:
                        raise RuntimeError("Audit vault append rejected: anchor head_hash format invalid")

                    expected_prior_idx = record_count - 1 if record_count > 0 else -1
                    if anchor_head.lower() != last_hash.lower():
                        raise RuntimeError(
                            f"Audit vault append rejected: external anchor divergence! "
                            f"Ledger head {last_hash} != anchor head {anchor_head}. Refusing to append to diverged history."
                        )
                    if anchor_idx != expected_prior_idx and not (record_count == 0 and anchor_idx is None):
                        raise RuntimeError(
                            f"Audit vault append rejected: external anchor index mismatch! "
                            f"Expected index {expected_prior_idx}, got {anchor_idx}."
                        )
                else:
                    if record_count > 0:
                        raise RuntimeError(
                            "Audit vault append rejected: anchor_path specified but anchor file is missing while ledger "
                            "contains records. Run with --init-anchor to explicitly bootstrap the trust anchor."
                        )

            # 4. Strict Serialization & Hashing
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

            # 5. Synchronous Durable Write
            serialized = json.dumps(record, sort_keys=True, allow_nan=False) + "\n"
            with open(vault_path, "a", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())

            # 6. Durable External Chain-Head Anchor Update
            if anchor_path:
                durable_write_anchor(anchor_path, new_index, new_timestamp, new_hash)

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

    if anchor_path:
        if not os.path.exists(anchor_path):
            print(f"[FAIL] Configured external trust anchor not found at {anchor_path}")
            return False
        try:
            with open(anchor_path, "r", encoding="utf-8") as af:
                anchor_data = json.load(af)
            expected_head = anchor_data.get("head_hash")
            expected_idx = anchor_data.get("index")
            if not expected_head or len(expected_head) != 64:
                print("[FAIL] External trust anchor malformed: missing or invalid 'head_hash'")
                return False
            if expected_idx != count - 1:
                print(f"[FAIL] External Anchor Index Mismatch: ledger last index {count - 1} != anchor index {expected_idx}")
                return False
            if expected_head.lower() != head_hash.lower():
                print(f"[FAIL] External Anchor Divergence: ledger head {head_hash} != anchor head {expected_head}")
                return False
            print(f"[OK] External trust anchor verified: index {expected_idx}, head {expected_head}")
        except Exception as e:
            print(f"[FAIL] Failed to read external trust anchor: {e}")
            return False

    print(f"[OK] Cryptographic chain verified clean across {count:,} records.")
    print(f"   Head Hash: {head_hash}")
    return True


def init_anchor(vault_path: str, anchor_path: str) -> bool:
    """Explicitly bootstraps or resets the external trust anchor from a verified existing ledger."""
    if not os.path.exists(vault_path):
        print(f"Error: Ledger file not found at {vault_path}")
        return False

    is_valid, count, head_hash, err = verify_chain_stream(vault_path)
    if not is_valid:
        print(f"[FAIL] Cannot initialize anchor: existing ledger is corrupt ({err})")
        return False

    last_idx = count - 1 if count > 0 else -1
    ts = time.time()
    durable_write_anchor(anchor_path, last_idx, ts, head_hash)
    print(f"[OK] Trust anchor successfully initialized for ledger with {count} records:")
    print(f"   Anchor Path: {anchor_path}")
    print(f"   Head Hash:   {head_hash}")
    print(f"   Last Index:  {last_idx}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Cryptographically Tamper-Evident Audit Vault (v1.3.1)")
    parser.add_argument("--vault-file", default=DEFAULT_VAULT_FILE, help="Path to audit_chain.jsonl")
    parser.add_argument("--verify", action="store_true", help="Verify chain integrity")
    parser.add_argument("--require-records", action="store_true", help="Reject empty ledgers during verification")
    parser.add_argument("--anchor-file", help="Path to external trust anchor checkpoint")
    parser.add_argument("--init-anchor", action="store_true", help="Explicitly bootstrap trust anchor from verified ledger")
    parser.add_argument("--append", help="JSON data payload to append")
    parser.add_argument("--topic", default="security.alerts.kernel", help="Event topic")

    args = parser.parse_args()

    if args.init_anchor:
        if not args.anchor_file:
            print("Error: --init-anchor requires --anchor-file path")
            sys.exit(1)
        success = init_anchor(args.vault_file, args.anchor_file)
        sys.exit(0 if success else 1)
    elif args.verify:
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
