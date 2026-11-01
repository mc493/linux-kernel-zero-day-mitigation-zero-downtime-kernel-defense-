#!/usr/bin/env python3
"""
Unit Test Suite for Cryptographically Tamper-Evident Audit Vault (v1.3.5)
Tests schema verification, canonical path collision defenses, bounded recursive depth,
anchor index boundary conditions, and two-phase administrative reset transactions.
"""

import os
import stat
import json
import tempfile
import unittest

from vault.audit_vault import (
    GENESIS_HASH,
    RECORD_VERSION,
    validate_anchor_schema,
    validate_dict_keys_are_strings,
    _is_path_collision,
    _append_admin_event,
    init_anchor,
    append_record,
    verify_chain,
    rejecting_duplicates_object_pairs_hook,
)


class TestAnchorSchema(unittest.TestCase):
    def test_valid_genesis_anchor(self):
        anchor = {
            "version": 1,
            "index": -1,
            "timestamp": 1700000000.0,
            "head_hash": GENESIS_HASH,
        }
        validate_anchor_schema(anchor, "anchor.json")

    def test_valid_initialized_anchor(self):
        anchor = {
            "version": 1,
            "index": 0,
            "timestamp": 1700000000.0,
            "head_hash": "a" * 64,
        }
        validate_anchor_schema(anchor, "anchor.json")

    def test_anchor_index_less_than_minus_one_rejected(self):
        anchor = {
            "version": 1,
            "index": -2,
            "timestamp": 1700000000.0,
            "head_hash": GENESIS_HASH,
        }
        with self.assertRaises(ValueError) as ctx:
            validate_anchor_schema(anchor, "anchor.json")
        self.assertIn("cannot be less than -1", str(ctx.exception))

    def test_genesis_anchor_requires_genesis_hash(self):
        anchor = {
            "version": 1,
            "index": -1,
            "timestamp": 1700000000.0,
            "head_hash": "a" * 64,
        }
        with self.assertRaises(ValueError) as ctx:
            validate_anchor_schema(anchor, "anchor.json")
        self.assertIn("must have genesis head hash", str(ctx.exception))

    def test_anchor_boolean_version_rejected(self):
        anchor = {
            "version": True,
            "index": -1,
            "timestamp": 1700000000.0,
            "head_hash": GENESIS_HASH,
        }
        with self.assertRaises(ValueError) as ctx:
            validate_anchor_schema(anchor, "anchor.json")
        self.assertIn("Field 'version' must be an integer", str(ctx.exception))

    def test_anchor_extra_fields_rejected(self):
        anchor = {
            "version": 1,
            "index": -1,
            "timestamp": 1700000000.0,
            "head_hash": GENESIS_HASH,
            "extra": "unauthenticated",
        }
        with self.assertRaises(ValueError) as ctx:
            validate_anchor_schema(anchor, "anchor.json")
        self.assertIn("Unauthenticated extra field", str(ctx.exception))


class TestDictKeyValidation(unittest.TestCase):
    def test_valid_string_keys(self):
        data = {"event": "probe", "nested": {"key": "val", "list": [{"a": 1}]}}
        validate_dict_keys_are_strings(data)

    def test_non_string_keys_rejected(self):
        data = {123: "val"}
        with self.assertRaises(ValueError) as ctx:
            validate_dict_keys_are_strings(data)
        self.assertIn("contains non-string dictionary key", str(ctx.exception))

    def test_max_depth_exceeded_raises_value_error(self):
        deep = {"level": "base"}
        curr = deep
        for i in range(40):
            curr["nested"] = {"level": i}
            curr = curr["nested"]
        with self.assertRaises(ValueError) as ctx:
            validate_dict_keys_are_strings(deep, max_depth=32)
        self.assertIn("exceeds maximum allowable nesting depth", str(ctx.exception))

    def test_circular_reference_raises_value_error_not_recursion_error(self):
        cycle = {"a": "test"}
        cycle["self"] = cycle
        with self.assertRaises(ValueError) as ctx:
            validate_dict_keys_are_strings(cycle, max_depth=32)
        self.assertIn("exceeds maximum allowable nesting depth", str(ctx.exception))

    def test_duplicate_key_json_rejected(self):
        raw = '{"key": "first", "key": "second"}'
        with self.assertRaises(ValueError) as ctx:
            json.loads(raw, object_pairs_hook=rejecting_duplicates_object_pairs_hook)
        self.assertIn("Duplicate JSON key detected", str(ctx.exception))


class TestPathCollisionProtection(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_path_collision_detection(self):
        f1 = os.path.join(self.tmpdir.name, "file1.txt")
        with open(f1, "w") as f:
            f.write("test")
        symlink = os.path.join(self.tmpdir.name, "symlink.txt")
        os.symlink(f1, symlink)

        self.assertTrue(_is_path_collision(f1, symlink))
        self.assertTrue(_is_path_collision(symlink, f1))

        f2 = os.path.join(self.tmpdir.name, "file2.txt")
        with open(f2, "w") as f:
            f.write("test2")
        self.assertFalse(_is_path_collision(f1, f2))

    def test_init_anchor_refuses_collision_between_anchor_and_vault(self):
        with open(self.vault_file, "w") as f:
            f.write("")
        success = init_anchor(self.vault_file, self.vault_file)
        self.assertFalse(success)

    def test_init_anchor_refuses_admin_log_colliding_with_vault(self):
        # Create valid empty ledger and initialize first anchor
        with open(self.vault_file, "w") as f:
            f.write("")
        self.assertTrue(init_anchor(self.vault_file, self.anchor_file))

        # Attempt forced reset with admin_log pointing to vault_file
        success = init_anchor(
            self.vault_file,
            self.anchor_file,
            force=True,
            reason="test reset",
            admin_audit_log=self.vault_file
        )
        self.assertFalse(success)

    def test_init_anchor_refuses_admin_log_colliding_with_anchor(self):
        with open(self.vault_file, "w") as f:
            f.write("")
        self.assertTrue(init_anchor(self.vault_file, self.anchor_file))

        success = init_anchor(
            self.vault_file,
            self.anchor_file,
            force=True,
            reason="test reset",
            admin_audit_log=self.anchor_file
        )
        self.assertFalse(success)

    def test_append_record_refuses_anchor_colliding_with_vault(self):
        with open(self.vault_file, "w") as f:
            f.write("")
        with self.assertRaises(ValueError) as ctx:
            append_record(self.vault_file, "test.topic", {"event": 1}, anchor_path=self.vault_file)
        self.assertIn("collides with ledger vault file", str(ctx.exception))


class TestTwoPhaseAdministrativeReset(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_two_phase_transaction_lifecycle(self):
        # 1. Initialize anchor normally
        with open(self.vault_file, "w") as f:
            f.write("")
        self.assertTrue(init_anchor(self.vault_file, self.anchor_file))

        # Append a record to advance ledger
        rec = append_record(self.vault_file, "security.test", {"status": "ok"}, anchor_path=self.anchor_file)
        self.assertEqual(rec["index"], 0)

        # 2. Corrupt anchor manually to simulate desynchronization
        with open(self.anchor_file, "w") as f:
            json.dump({
                "version": 1,
                "index": 999,
                "timestamp": 1700000000.0,
                "head_hash": "f" * 64
            }, f)

        # 3. Forced reset with justification and explicit admin log
        reason = "Emergency resynchronization after recovery"
        success = init_anchor(
            self.vault_file,
            self.anchor_file,
            force=True,
            reason=reason,
            admin_audit_log=self.admin_log
        )
        self.assertTrue(success)

        # 4. Verify admin log existence, restrictive permissions, and two-phase entries
        self.assertTrue(os.path.exists(self.admin_log))
        file_stat = os.stat(self.admin_log)
        file_mode = stat.S_IMODE(file_stat.st_mode)
        self.assertEqual(file_mode, 0o600, f"Admin log permissions must be 0600, got {oct(file_mode)}")

        with open(self.admin_log, "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        self.assertEqual(len(lines), 2, "Expected exactly 2 entries (PREPARED and COMMITTED)")
        self.assertEqual(lines[0]["action"], "TRUST_ROOT_RESET_PREPARED")
        self.assertEqual(lines[0]["reason"], reason)
        self.assertEqual(lines[0]["prior_anchor"]["index"], 999)
        self.assertEqual(lines[0]["new_index"], 0)
        self.assertEqual(lines[0]["new_head_hash"], rec["hash"])

        self.assertEqual(lines[1]["action"], "TRUST_ROOT_RESET_COMMITTED")
        self.assertEqual(lines[1]["reason"], reason)
        self.assertEqual(lines[1]["new_index"], 0)
        self.assertEqual(lines[1]["new_head_hash"], rec["hash"])

        # 5. Verify the reset anchor is valid and chain passes verification
        self.assertTrue(verify_chain(self.vault_file, require_records=True, anchor_path=self.anchor_file))


if __name__ == "__main__":
    unittest.main()
