#!/usr/bin/env python3
"""
Cryptographically Tamper-Evident Audit Vault (v1.0.0)
Appends events to a sequential SHA-256 cryptographic hash-chain ledger.

Each record commits to:
  Hash_n = SHA-256(index | timestamp | topic | payload | prev_hash)

Usage:
  python3 audit_vault.py --verify [--vault-file path/to/audit_chain.jsonl]
  python3 audit_vault.py --append '{"event": "probe", "severity": "WARNING"}' [--topic sovereign.security.alert]
"""

import sys
import os
import time
import json
import hashlib
import argparse

DEFAULT_VAULT_FILE = os.getenv("AUDIT_VAULT_FILE", "./audit_chain.jsonl")
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def compute_record_hash(index: int, timestamp: float, topic: str, data: dict, prev_hash: str) -> str:
    """Computes deterministic SHA-256 over serialized record tuple."""
    payload_str = json.dumps(data, sort_keys=True)
    raw_blob = f"{index}|{timestamp}|{topic}|{payload_str}|{prev_hash}".encode("utf-8")
    return hashlib.sha256(raw_blob).hexdigest()


def append_record(vault_path: str, topic: str, data: dict) -> dict:
    """Atomically appends a new verified record to the hash-chain ledger."""
    os.makedirs(os.path.dirname(os.path.abspath(vault_path)), exist_ok=True)
    
    last_index = -1
    last_hash = GENESIS_HASH
    
    if os.path.exists(vault_path):
        with open(vault_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rec = json.loads(line)
                        last_index = rec.get("index", last_index)
                        last_hash = rec.get("hash", last_hash)
                    except json.JSONDecodeError:
                        continue

    new_index = last_index + 1
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
    
    with open(vault_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()
        os.fsync(f.fileno())
        
    return record


def verify_chain(vault_path: str) -> bool:
    """Verifies complete cryptographic integrity of the hash chain."""
    if not os.path.exists(vault_path):
        print(f"❌ Error: Vault file not found at {vault_path}")
        return False

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
                print(f"❌ Corrupted JSON at line {line_num}: {e}")
                return False
                
            idx = rec.get("index")
            ts = rec.get("timestamp")
            topic = rec.get("topic")
            data = rec.get("data")
            p_hash = rec.get("prev_hash")
            curr_hash = rec.get("hash")
            
            # Verify backward pointer
            if p_hash != prev_hash:
                print(f"❌ Chain Break at index {idx} (line {line_num})!")
                print(f"   Expected prev_hash: {prev_hash}")
                print(f"   Recorded prev_hash: {p_hash}")
                return False
                
            # Verify self digest
            computed = compute_record_hash(idx, ts, topic, data, p_hash)
            if computed != curr_hash:
                print(f"❌ Digest Mismatch at index {idx} (line {line_num})!")
                print(f"   Recorded: {curr_hash}")
                print(f"   Computed: {computed}")
                return False
                
            prev_hash = curr_hash
            record_count += 1

    print(f"✅ Cryptographic chain verified clean across {record_count:,} records.")
    print(f"   Head Hash: {prev_hash}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Cryptographically Tamper-Evident Audit Vault")
    parser.add_argument("--vault-file", default=DEFAULT_VAULT_FILE, help="Path to audit_chain.jsonl")
    parser.add_argument("--verify", action="store_true", help="Verify chain integrity")
    parser.add_argument("--append", help="JSON data payload to append")
    parser.add_argument("--topic", default="sovereign.security.alert", help="Event topic")
    
    args = parser.parse_args()
    
    if args.verify:
        success = verify_chain(args.vault_file)
        sys.exit(0 if success else 1)
    elif args.append:
        try:
            data = json.loads(args.append)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON payload: {e}")
            sys.exit(1)
            
        rec = append_record(args.vault_file, args.topic, data)
        print(f"✅ Record #{rec['index']} committed: {rec['hash']}")
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
