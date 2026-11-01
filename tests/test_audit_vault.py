#!/usr/bin/env python3
"""
Unit Test Suite for Cryptographically Tamper-Evident Audit Vault (v1.3.6)
Tests schema verification, canonical path collision defenses, bounded recursive depth,
anchor index boundary conditions, cryptographic administrative hash-chains,
TOCTOU-immune open file descriptor checks, and crash-recovery transaction reconciliation.
"""

import os
import stat
import json
import tempfile
import unittest
import multiprocessing
import time

from vault.audit_vault import (
    GENESIS_HASH,
    RECORD_VERSION,
    ADMIN_RECORD_VERSION,
    validate_anchor_schema,
    validate_dict_keys_are_strings,
    validate_admin_record_schema,
    verify_admin_chain,
    _is_path_collision,
    _open_admin_log_fd_safe,
    _append_admin_event,
    _append_admin_event_unlocked,
    recover_admin_transaction,
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
        with open(self.vault_file, "w") as f:
            f.write("")
        self.assertTrue(init_anchor(self.vault_file, self.anchor_file))

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


class TestTOCTOUAndSymlinkHardening(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")
        with open(self.vault_file, "w") as f:
            f.write("")
        with open(self.anchor_file, "w") as f:
            f.write("")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_open_admin_log_rejects_symlink(self):
        target = os.path.join(self.tmpdir.name, "real_admin.log")
        with open(target, "w") as f:
            f.write("")
        os.symlink(target, self.admin_log)

        with self.assertRaises(ValueError) as ctx:
            _open_admin_log_fd_safe(self.admin_log, self.vault_file, self.anchor_file)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_open_admin_log_detects_hardlink_to_anchor_via_fstat(self):
        os.link(self.anchor_file, self.admin_log)
        with self.assertRaises(ValueError) as ctx:
            _open_admin_log_fd_safe(self.admin_log, self.vault_file, self.anchor_file)
        self.assertIn("shares inode with trust anchor file", str(ctx.exception))

    def test_open_admin_log_detects_hardlink_to_vault_via_fstat(self):
        os.link(self.vault_file, self.admin_log)
        with self.assertRaises(ValueError) as ctx:
            _open_admin_log_fd_safe(self.admin_log, self.vault_file, self.anchor_file)
        self.assertIn("shares inode with ledger vault file", str(ctx.exception))


class TestAdminLogHashChain(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")
        with open(self.vault_file, "w") as f:
            f.write("")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_admin_hash_chain_verification_and_tamper_detection(self):
        # Create 3 valid admin records
        tx1 = "tx-001"
        _append_admin_event(self.admin_log, "TRUST_ROOT_RESET_PREPARED", tx1, self.anchor_file, self.vault_file, "reason 1", None, "a"*64, 0)
        _append_admin_event(self.admin_log, "TRUST_ROOT_RESET_COMMITTED", tx1, self.anchor_file, self.vault_file, "reason 1", None, "a"*64, 0)

        tx2 = "tx-002"
        _append_admin_event(self.admin_log, "TRUST_ROOT_RESET_PREPARED", tx2, self.anchor_file, self.vault_file, "reason 2", {"index": 0}, "b"*64, 1)

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid, f"Expected clean admin chain, got error: {err}")
        self.assertEqual(count, 3)

        # Tamper test: modify one character in record 1
        with open(self.admin_log, "r") as f:
            lines = f.readlines()
        corrupted = json.loads(lines[1])
        corrupted["reason"] = "tampered reason"
        lines[1] = json.dumps(corrupted) + "\n"
        with open(self.admin_log, "w") as f:
            f.writelines(lines)

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertFalse(is_valid)
        self.assertIn("Self-digest mismatch", err)


class TestAdminCrashRecoveryMatrix(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")

        # Initialize ledger with 1 record
        with open(self.vault_file, "w") as f:
            f.write("")
        init_anchor(self.vault_file, self.anchor_file)
        append_record(self.vault_file, "sys.init", {"init": True}, anchor_path=self.anchor_file)

        with open(self.anchor_file, "r") as af:
            self.prior_anchor = json.load(af)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_recovery_boundary_1_crash_after_prepared_reconciles_aborted(self):
        """Boundary 1: Crash after PREPARED write; anchor was never modified on disk."""
        tx_id = "tx-boundary-1"
        target_head = "e" * 64
        target_idx = 10

        _append_admin_event(
            self.admin_log,
            "TRUST_ROOT_RESET_PREPARED",
            tx_id,
            self.anchor_file,
            self.vault_file,
            "Emergency reset",
            self.prior_anchor,
            target_head,
            target_idx
        )

        # Disk anchor still matches prior_anchor
        res = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res["status"], "RECONCILED_ABORTED")

        # Check admin log chain
        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid)
        self.assertEqual(count, 2)

    def test_recovery_boundary_3_crash_after_rename_reconciles_committed(self):
        """Boundary 3: Crash after atomic rename; anchor was replaced on disk before crash."""
        tx_id = "tx-boundary-3"
        target_head = "f" * 64
        target_idx = 10

        _append_admin_event(
            self.admin_log,
            "TRUST_ROOT_RESET_PREPARED",
            tx_id,
            self.anchor_file,
            self.vault_file,
            "Emergency reset",
            self.prior_anchor,
            target_head,
            target_idx
        )

        # Simulate that rename succeeded on disk before the crash
        with open(self.anchor_file, "w") as f:
            json.dump({
                "version": 1,
                "index": target_idx,
                "timestamp": 1700000000.0,
                "head_hash": target_head
            }, f)

        res = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res["status"], "RECONCILED_COMMITTED")

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid)
        self.assertEqual(count, 2)

    def test_recovery_boundary_4_directory_fsync_uncertain_reconciles_committed(self):
        """Boundary 4: REPLACEMENT_UNCERTAIN logged; recovery confirms replacement on disk."""
        tx_id = "tx-boundary-4"
        target_head = "7" * 64
        target_idx = 5

        _append_admin_event(
            self.admin_log,
            "TRUST_ROOT_RESET_PREPARED",
            tx_id,
            self.anchor_file,
            self.vault_file,
            "Emergency reset",
            self.prior_anchor,
            target_head,
            target_idx
        )
        _append_admin_event(
            self.admin_log,
            "TRUST_ROOT_RESET_REPLACEMENT_UNCERTAIN",
            tx_id,
            self.anchor_file,
            self.vault_file,
            "Emergency reset",
            self.prior_anchor,
            target_head,
            target_idx,
            details={"error": "EIO on directory fsync"}
        )

        # Anchor on disk contains target state
        with open(self.anchor_file, "w") as f:
            json.dump({
                "version": 1,
                "index": target_idx,
                "timestamp": 1700000000.0,
                "head_hash": target_head
            }, f)

        res = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res["status"], "RECONCILED_COMMITTED")

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid)
        self.assertEqual(count, 3)

    def test_recovery_boundary_5_corrupted_divergence_requires_manual_recovery(self):
        """Boundary 5: Anchor on disk matches neither prior nor target state."""
        tx_id = "tx-boundary-5"
        target_head = "8" * 64
        target_idx = 10

        _append_admin_event(
            self.admin_log,
            "TRUST_ROOT_RESET_PREPARED",
            tx_id,
            self.anchor_file,
            self.vault_file,
            "Emergency reset",
            self.prior_anchor,
            target_head,
            target_idx
        )

        # Corrupt anchor with arbitrary third hash
        with open(self.anchor_file, "w") as f:
            json.dump({
                "version": 1,
                "index": 999,
                "timestamp": 1700000000.0,
                "head_hash": "c" * 64
            }, f)

        res = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res["status"], "RECOVERY_REQUIRED")

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid)
        self.assertEqual(count, 2)


class TestTwoPhaseAdministrativeReset(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_two_phase_transaction_lifecycle(self):
        with open(self.vault_file, "w") as f:
            f.write("")
        self.assertTrue(init_anchor(self.vault_file, self.anchor_file))

        rec = append_record(self.vault_file, "security.test", {"status": "ok"}, anchor_path=self.anchor_file)
        self.assertEqual(rec["index"], 0)

        # Corrupt anchor manually
        with open(self.anchor_file, "w") as f:
            json.dump({
                "version": 1,
                "index": 999,
                "timestamp": 1700000000.0,
                "head_hash": "f" * 64
            }, f)

        reason = "Emergency resynchronization after recovery"
        success = init_anchor(
            self.vault_file,
            self.anchor_file,
            force=True,
            reason=reason,
            admin_audit_log=self.admin_log
        )
        self.assertTrue(success)

        self.assertTrue(os.path.exists(self.admin_log))
        file_stat = os.stat(self.admin_log)
        file_mode = stat.S_IMODE(file_stat.st_mode)
        self.assertEqual(file_mode, 0o600, f"Admin log permissions must be 0600, got {oct(file_mode)}")

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid, f"Admin chain invalid: {err}")
        self.assertEqual(count, 2)

        self.assertTrue(verify_chain(self.vault_file, require_records=True, anchor_path=self.anchor_file))


def _concurrent_worker(vault_file, anchor_file, worker_id, count):
    for i in range(count):
        try:
            append_record(vault_file, f"worker.{worker_id}", {"seq": i, "worker": worker_id}, anchor_path=anchor_file)
        except Exception as e:
            pass


class TestMultiprocessConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        with open(self.vault_file, "w") as f:
            f.write("")
        init_anchor(self.vault_file, self.anchor_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_concurrent_writers_no_deadlock_or_corruption(self):
        num_workers = 4
        ops_per_worker = 15
        processes = []

        for wid in range(num_workers):
            p = multiprocessing.Process(target=_concurrent_worker, args=(self.vault_file, self.anchor_file, wid, ops_per_worker))
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=10.0)
            self.assertFalse(p.is_alive(), "Worker process timed out or deadlocked")

        self.assertTrue(verify_chain(self.vault_file, require_records=True, anchor_path=self.anchor_file))


if __name__ == "__main__":
    unittest.main()
