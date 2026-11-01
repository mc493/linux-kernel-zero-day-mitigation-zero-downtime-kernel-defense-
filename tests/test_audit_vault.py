#!/usr/bin/env python3
"""
Unit Test Suite for Cryptographically Tamper-Evident Audit Vault (v1.3.8)
Tests schema verification, canonical path collision defenses, bounded recursive depth,
anchor index boundary conditions, cryptographic administrative hash-chains,
TOCTOU-immune dir_fd O_NOFOLLOW open checks, regular file mode enforcement,
hardlink immunity (st_nlink == 1), parent directory security audits,
external administrative trust anchor checkpoints with truncation and divergence detection,
optional HMAC-SHA256 checkpoint signatures, evidence-preserving EOF quarantine,
crash-recovery transaction reconciliation with interrupted-commit repair, and multi-operation concurrency.
"""

import os
import stat
import json
import tempfile
import unittest
import multiprocessing
import time
import hashlib
import hmac

from vault.audit_vault import (
    GENESIS_HASH,
    RECORD_VERSION,
    ADMIN_RECORD_VERSION,
    ADMIN_ANCHOR_RECORD_VERSION,
    validate_anchor_schema,
    validate_admin_anchor_schema,
    validate_dict_keys_are_strings,
    validate_admin_record_schema,
    verify_admin_chain,
    _verify_admin_chain_unlocked,
    _is_path_collision,
    _open_and_validate_dir_fd,
    _open_admin_log_fd_safe,
    _append_admin_event,
    _append_admin_event_unlocked,
    durable_write_admin_anchor,
    _sanitize_admin_log_eof,
    recover_admin_transaction,
    init_anchor,
    append_record,
    verify_chain,
    compute_admin_event_hash,
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

    def test_open_admin_log_rejects_fifo(self):
        fifo_path = os.path.join(self.tmpdir.name, "fifo_admin.log")
        try:
            os.mkfifo(fifo_path)
        except (AttributeError, OSError):
            self.skipTest("mkfifo not supported on environment")

        with self.assertRaises(ValueError) as ctx:
            _open_admin_log_fd_safe(fifo_path, self.vault_file, self.anchor_file)
        self.assertIn("must be a regular file", str(ctx.exception))


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

    def test_admin_log_truncation_detection(self):
        tx1 = "tx-001"
        _append_admin_event(self.admin_log, "TRUST_ROOT_RESET_PREPARED", tx1, self.anchor_file, self.vault_file, "reason 1", None, "a"*64, 0)
        _append_admin_event(self.admin_log, "TRUST_ROOT_RESET_COMMITTED", tx1, self.anchor_file, self.vault_file, "reason 1", None, "a"*64, 0)
        _append_admin_event(self.admin_log, "TRUST_ROOT_RESET_PREPARED", "tx-002", self.anchor_file, self.vault_file, "reason 2", {"index": 0}, "b"*64, 1)

        admin_anchor = f"{self.admin_log}.anchor.json"
        self.assertTrue(os.path.exists(admin_anchor))

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid)
        self.assertEqual(count, 3)

        # Truncate admin log: remove last line
        with open(self.admin_log, "r") as f:
            lines = f.readlines()
        with open(self.admin_log, "w") as f:
            f.writelines(lines[:-1])

        # Verify admin chain detects truncation against the external anchor
        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertFalse(is_valid)
        self.assertIn("ADMIN_LOG_TRUNCATION_DETECTED", err)

    def test_admin_log_anchor_divergence_detection(self):
        tx1 = "tx-001"
        _append_admin_event(self.admin_log, "TRUST_ROOT_RESET_PREPARED", tx1, self.anchor_file, self.vault_file, "reason 1", None, "a"*64, 0)

        admin_anchor = f"{self.admin_log}.anchor.json"
        with open(admin_anchor, "r") as f:
            anchor_data = json.load(f)

        anchor_data["head_hash"] = "0" * 64
        with open(admin_anchor, "w") as f:
            json.dump(anchor_data, f)

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertFalse(is_valid)
        self.assertIn("ADMIN_ANCHOR_DIVERGENCE", err)


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

    def test_recovery_boundary_2_crash_after_temp_file_fsync(self):
        """Boundary 2: Crash after temporary anchor file fsync, before atomic rename."""
        tx_id = "tx-boundary-2"
        target_head = "d" * 64
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

        # Write temporary anchor file simulating Boundary 2 state
        anchor_tmp = f"{self.anchor_file}.tmp.simulated"
        with open(anchor_tmp, "w") as f:
            json.dump({
                "version": 1,
                "index": target_idx,
                "timestamp": 1700000000.0,
                "head_hash": target_head
            }, f)

        # Disk anchor remains prior_anchor (rename never happened)
        res = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res["status"], "RECONCILED_ABORTED")

        # Verify prior anchor remains authoritative
        with open(self.anchor_file, "r") as f:
            curr_anchor = json.load(f)
        self.assertEqual(curr_anchor["head_hash"], self.prior_anchor["head_hash"])
        self.assertEqual(curr_anchor["index"], self.prior_anchor["index"])

        # Check admin log chain
        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid)
        self.assertEqual(count, 2)

    def test_recovery_after_partial_write_at_eof(self):
        """Recovery cleans un-newline-terminated trailing partial write at EOF and reconciles."""
        tx_id = "tx-partial"
        target_head = "9" * 64
        target_idx = 10

        _append_admin_event(
            self.admin_log,
            "TRUST_ROOT_RESET_PREPARED",
            tx_id,
            self.anchor_file,
            self.vault_file,
            "Interrupted write test",
            self.prior_anchor,
            target_head,
            target_idx
        )

        # Inject trailing un-newline-terminated partial line at EOF
        with open(self.admin_log, "ab") as f:
            f.write(b'{"action": "TRUST_ROOT_RESET_RECONCILED_COMMITTED", "admin_index": 1, "partial": ')

        res = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res["status"], "RECONCILED_ABORTED")

        is_valid, count, head, err = verify_admin_chain(self.admin_log)
        self.assertTrue(is_valid, f"Chain should be valid after partial write recovery: {err}")
        self.assertEqual(count, 2)

    def test_recovery_idempotency(self):
        """Repeated recovery executions on already reconciled transactions are no-op returning CLEAN."""
        tx_id = "tx-idempotent"
        _append_admin_event(
            self.admin_log,
            "TRUST_ROOT_RESET_PREPARED",
            tx_id,
            self.anchor_file,
            self.vault_file,
            "Idempotency test",
            self.prior_anchor,
            "a" * 64,
            5
        )

        res1 = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res1["status"], "RECONCILED_ABORTED")

        # Second recovery call MUST be a no-op returning CLEAN
        res2 = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res2["status"], "CLEAN")
        self.assertIn("already resolved", res2["message"])

        # Third recovery call still CLEAN
        res3 = recover_admin_transaction(self.vault_file, self.anchor_file, admin_audit_log=self.admin_log)
        self.assertEqual(res3["status"], "CLEAN")

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


def _concurrent_appender(vault_file, anchor_file, worker_id, count):
    for i in range(count):
        try:
            append_record(vault_file, f"worker.{worker_id}", {"seq": i, "worker": worker_id}, anchor_path=anchor_file)
        except Exception:
            pass


def _concurrent_resetter(vault_file, anchor_file, admin_log, count):
    for i in range(count):
        try:
            init_anchor(vault_file, anchor_file, force=True, reason=f"Concurrent reset iteration {i}", admin_audit_log=admin_log)
        except Exception:
            pass


def _concurrent_verifier(vault_file, anchor_file, count):
    for _ in range(count):
        try:
            verify_chain(vault_file, require_records=False, anchor_path=anchor_file)
        except Exception:
            pass


def _concurrent_recoverer(vault_file, anchor_file, admin_log, count):
    for _ in range(count):
        try:
            recover_admin_transaction(vault_file, anchor_file, admin_audit_log=admin_log)
        except Exception:
            pass


def _concurrent_admin_recovery_worker(vault_file, anchor_file, admin_log, admin_anchor, results_queue):
    try:
        res = recover_admin_transaction(vault_file, anchor_file, admin_audit_log=admin_log, admin_anchor_path=admin_anchor)
        results_queue.put(res["status"])
    except Exception as e:
        results_queue.put(f"ERROR: {e}")


class TestMultiprocessConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")
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

    def test_concurrent_append_and_admin_reset(self):
        processes = []
        for wid in range(2):
            p = multiprocessing.Process(target=_concurrent_appender, args=(self.vault_file, self.anchor_file, wid, 15))
            processes.append(p)
            p.start()

        r_p = multiprocessing.Process(target=_concurrent_resetter, args=(self.vault_file, self.anchor_file, self.admin_log, 3))
        processes.append(r_p)
        r_p.start()

        for p in processes:
            p.join(timeout=10.0)
            self.assertFalse(p.is_alive(), "Process timed out or deadlocked under concurrent append + reset")

        self.assertTrue(verify_chain(self.vault_file, require_records=False, anchor_path=self.anchor_file))

    def test_concurrent_reset_and_recovery(self):
        processes = []
        r_p = multiprocessing.Process(target=_concurrent_resetter, args=(self.vault_file, self.anchor_file, self.admin_log, 4))
        rec_p = multiprocessing.Process(target=_concurrent_recoverer, args=(self.vault_file, self.anchor_file, self.admin_log, 8))
        processes.extend([r_p, rec_p])
        for p in processes:
            p.start()

        for p in processes:
            p.join(timeout=10.0)
            self.assertFalse(p.is_alive(), "Process timed out or deadlocked under concurrent reset + recovery")

        self.assertTrue(verify_chain(self.vault_file, require_records=False, anchor_path=self.anchor_file))

    def test_concurrent_verify_and_reset(self):
        processes = []
        for _ in range(2):
            v_p = multiprocessing.Process(target=_concurrent_verifier, args=(self.vault_file, self.anchor_file, 10))
            processes.append(v_p)
            v_p.start()

        r_p = multiprocessing.Process(target=_concurrent_resetter, args=(self.vault_file, self.anchor_file, self.admin_log, 3))
        processes.append(r_p)
        r_p.start()

        for p in processes:
            p.join(timeout=10.0)
            self.assertFalse(p.is_alive(), "Process timed out or deadlocked under concurrent verify + reset")

        self.assertTrue(verify_chain(self.vault_file, require_records=False, anchor_path=self.anchor_file))


class TestAdversarialHardeningMatrix(unittest.TestCase):
    """
    Adversarial and Edge-Condition Test Matrix (A1 - A10):
    A1: Directory fd validation rejects symbolic links
    A2: Directory fd validation rejects world-writable permissions without sticky bit
    A3: Admin log open rejects multiple hardlinks (st_nlink > 1)
    A4: Interrupted admin commit reconciliation (step 2 fsync log -> crash before anchor advance)
    A5: Boundary 4 recovery reconciliation (REPLACEMENT_UNCERTAIN confirmed against disk)
    A6: Optional HMAC-SHA256 signature verification on admin anchor checkpoints
    A7: Non-destructive partial write recovery: damaged trailing bytes quarantined before truncation
    A8: Refusal of silent truncation when damaged record is referenced by committed anchor
    A9: Administrative recovery idempotency across repeated consecutive executions
    A10: Multi-process concurrent recovery serialization without duplicate resolution records
    """
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.tmpdir.name, "ledger.jsonl")
        self.anchor_file = os.path.join(self.tmpdir.name, "anchor.json")
        self.admin_log = os.path.join(self.tmpdir.name, "admin.log")
        self.admin_anchor = os.path.join(self.tmpdir.name, "admin.log.anchor.json")
        with open(self.vault_file, "w") as f:
            f.write("")
        init_anchor(self.vault_file, self.anchor_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_a1_dir_fd_rejects_symlink_directory(self):
        """A1: Parent directory open via _open_and_validate_dir_fd rejects symbolic links with O_NOFOLLOW."""
        real_dir = os.path.join(self.tmpdir.name, "real_dir")
        os.makedirs(real_dir, exist_ok=True)
        symlink_dir = os.path.join(self.tmpdir.name, "sym_dir")
        os.symlink(real_dir, symlink_dir)

        with self.assertRaises(ValueError) as ctx:
            _open_and_validate_dir_fd(symlink_dir)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_a2_dir_fd_rejects_world_writable_directory(self):
        """A2: Directory validation rejects world-writable directories lacking sticky bit (perm 0777)."""
        ww_dir = os.path.join(self.tmpdir.name, "ww_dir")
        os.makedirs(ww_dir, exist_ok=True)
        os.chmod(ww_dir, 0o777)

        with self.assertRaises(ValueError) as ctx:
            _open_and_validate_dir_fd(ww_dir)
        self.assertIn("world-writable without sticky bit", str(ctx.exception))

        # Sticky bit directory (01777, like /tmp) should be accepted
        os.chmod(ww_dir, 0o1777)
        fd = _open_and_validate_dir_fd(ww_dir)
        self.assertIsInstance(fd, int)
        os.close(fd)

    def test_a3_open_admin_log_rejects_unrelated_hardlink(self):
        """A3: Opening admin log rejects files with st_nlink != 1 to prevent hardlink aliasing."""
        unrelated_file = os.path.join(self.tmpdir.name, "unrelated_target.txt")
        with open(unrelated_file, "w") as f:
            f.write("target data\n")

        admin_link = os.path.join(self.tmpdir.name, "admin_hardlinked.log")
        os.link(unrelated_file, admin_link)

        with self.assertRaises(ValueError) as ctx:
            _open_admin_log_fd_safe(admin_link, self.vault_file, self.anchor_file)
        self.assertIn("multiple hardlinks", str(ctx.exception))

    def test_a4_interrupted_admin_commit_reconciliation(self):
        """A4: Interrupted admin commit (log fsynced but crash before anchor update) auto-reconciles."""
        prior = {"index": -1, "head_hash": GENESIS_HASH}
        _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_PREPARED",
            transaction_id="tx-a4",
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A4 test prep",
            prior_anchor=prior,
            new_head_hash="1" * 64,
            new_index=0,
        )
        rec1 = _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_COMMITTED",
            transaction_id="tx-a4",
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A4 test commit",
            prior_anchor=prior,
            new_head_hash="1" * 64,
            new_index=0,
        )

        # Durably write anchor at index 1
        durable_write_admin_anchor(self.admin_anchor, 1, time.time(), rec1["admin_hash"])

        # Simulate crash: record appended to log, but anchor not yet updated
        _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_PREPARED",
            transaction_id="tx-a4-crash",
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="Interrupted crash event",
            prior_anchor=prior,
            new_head_hash="2" * 64,
            new_index=1,
        )
        # Reset anchor back to index 1 to simulate crash occurring before anchor update
        durable_write_admin_anchor(self.admin_anchor, 1, time.time(), rec1["admin_hash"])

        # Without auto_reconcile, verify_admin_chain flags ADMIN_ANCHOR_INTERRUPTED_COMMIT
        is_valid, count, head, err = verify_admin_chain(
            self.admin_log,
            admin_anchor_path=self.admin_anchor,
            auto_reconcile=False,
        )
        self.assertFalse(is_valid)
        self.assertIn("ADMIN_ANCHOR_INTERRUPTED_COMMIT", err)

        # Recovery should automatically reconcile and advance the admin anchor
        res = recover_admin_transaction(
            self.vault_file,
            self.anchor_file,
            admin_audit_log=self.admin_log,
            admin_anchor_path=self.admin_anchor,
        )
        self.assertIn(res["status"], {"CLEAN", "RECONCILED_ABORTED"})

        # Chain and anchor should now be fully consistent (record count 4: 2 initial + 1 interrupted + 1 reconciled abort)
        is_valid, count, head, err = verify_admin_chain(
            self.admin_log,
            admin_anchor_path=self.admin_anchor,
        )
        self.assertTrue(is_valid, f"Chain should be valid after reconciliation: {err}")
        self.assertEqual(count, 4)

    def test_a5_uncertain_admin_checkpoint_reconciliation(self):
        """A5: REPLACEMENT_UNCERTAIN in admin log is reconciled against matching anchor state on disk."""
        tx_id = "tx-a5-uncertain"
        target_head = "5" * 64
        target_idx = 4
        prior = {"index": 0, "head_hash": "0" * 64}

        _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_PREPARED",
            transaction_id=tx_id,
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A5 uncertain test",
            prior_anchor=prior,
            new_head_hash=target_head,
            new_index=target_idx,
        )
        _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_REPLACEMENT_UNCERTAIN",
            transaction_id=tx_id,
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A5 uncertain test",
            prior_anchor=prior,
            new_head_hash=target_head,
            new_index=target_idx,
            details={"error": "simulated fsync timeout"},
        )

        with open(self.anchor_file, "w", encoding="utf-8") as af:
            json.dump({
                "version": 1,
                "index": target_idx,
                "timestamp": 1700000000.0,
                "head_hash": target_head,
            }, af)

        res = recover_admin_transaction(
            self.vault_file,
            self.anchor_file,
            admin_audit_log=self.admin_log,
            admin_anchor_path=self.admin_anchor,
        )
        self.assertEqual(res["status"], "RECONCILED_COMMITTED")

    def test_a6_hmac_signed_admin_anchor_tamper_detection(self):
        """A6: Optional HMAC-SHA256 signatures detect tampering or forgery of admin anchor checkpoints."""
        secret_key = "sovereign-vault-root-auth-key"
        test_head = "a" * 64
        test_index = 0
        ts = 1700000000.0

        durable_write_admin_anchor(
            self.admin_anchor,
            test_index,
            ts,
            test_head,
            secret_key=secret_key,
        )

        with open(self.admin_anchor, "r", encoding="utf-8") as af:
            data = json.load(af)
        self.assertIn("signature", data)
        validate_admin_anchor_schema(data, self.admin_anchor, secret_key=secret_key)

        tampered_data = dict(data)
        tampered_data["admin_index"] = 1
        with self.assertRaises(ValueError) as ctx:
            validate_admin_anchor_schema(tampered_data, self.admin_anchor, secret_key=secret_key)
        self.assertIn("HMAC signature verification failed", str(ctx.exception))

        unsigned_data = {k: v for k, v in data.items() if k != "signature"}
        with self.assertRaises(ValueError) as ctx:
            validate_admin_anchor_schema(unsigned_data, self.admin_anchor, secret_key=secret_key)
        self.assertIn("Missing mandatory cryptographic signature", str(ctx.exception))

    def test_a7_uncommitted_partial_write_quarantined_and_repaired(self):
        """A7: Uncommitted damaged trailing bytes at EOF are preserved in quarantine file before truncation."""
        rec0 = _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_PREPARED",
            transaction_id="tx-a7",
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A7 prep",
            prior_anchor=None,
            new_head_hash="7" * 64,
            new_index=0,
        )
        durable_write_admin_anchor(self.admin_anchor, 0, time.time(), rec0["admin_hash"])

        partial_junk = b'{"action": "TRUST_ROOT_RESET_COMMITTED", "admin_index": 1, "incomplete_json": '
        with open(self.admin_log, "ab") as f:
            f.write(partial_junk)

        modified, q_path = _sanitize_admin_log_eof(self.admin_log, admin_anchor_path=self.admin_anchor)
        self.assertTrue(modified)
        self.assertIsNotNone(q_path)
        self.assertTrue(os.path.exists(q_path))

        with open(q_path, "rb") as qf:
            quarantined_bytes = qf.read()
        self.assertEqual(quarantined_bytes, partial_junk)

        is_valid, count, head, err = verify_admin_chain(self.admin_log, admin_anchor_path=self.admin_anchor)
        self.assertTrue(is_valid, f"Admin chain must be valid: {err}")
        self.assertEqual(count, 1)

    def test_a8_committed_record_corruption_refuses_truncation(self):
        """A8: Corrupted record referenced by committed anchor checkpoint refuses silent truncation."""
        rec0 = _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_PREPARED",
            transaction_id="tx-a8",
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A8 prep",
            prior_anchor=None,
            new_head_hash="8" * 64,
            new_index=0,
        )
        rec1 = _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_COMMITTED",
            transaction_id="tx-a8",
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A8 commit",
            prior_anchor=None,
            new_head_hash="8" * 64,
            new_index=0,
        )
        durable_write_admin_anchor(self.admin_anchor, 1, time.time(), rec1["admin_hash"])

        with open(self.admin_log, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)
        lines[1] = '{"corrupted_data": "invalid\n'
        with open(self.admin_log, "w", encoding="utf-8") as f:
            f.writelines(lines)

        orig_size = os.path.getsize(self.admin_log)

        with self.assertRaises(ValueError) as ctx:
            _sanitize_admin_log_eof(self.admin_log, admin_anchor_path=self.admin_anchor)
        self.assertIn("Silent truncation refused", str(ctx.exception))
        self.assertEqual(os.path.getsize(self.admin_log), orig_size)

    def test_a9_recovery_reconciliation_append_idempotency(self):
        """A9: Repeated recovery invocations on already resolved transactions are clean no-ops."""
        tx_id = "tx-a9-idempotency"
        _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_PREPARED",
            transaction_id=tx_id,
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A9 idempotency test",
            prior_anchor={"index": -1, "head_hash": GENESIS_HASH},
            new_head_hash="9" * 64,
            new_index=0,
        )

        res1 = recover_admin_transaction(
            self.vault_file,
            self.anchor_file,
            admin_audit_log=self.admin_log,
            admin_anchor_path=self.admin_anchor,
        )
        self.assertEqual(res1["status"], "RECONCILED_ABORTED")

        res2 = recover_admin_transaction(
            self.vault_file,
            self.anchor_file,
            admin_audit_log=self.admin_log,
            admin_anchor_path=self.admin_anchor,
        )
        self.assertEqual(res2["status"], "CLEAN")

        res3 = recover_admin_transaction(
            self.vault_file,
            self.anchor_file,
            admin_audit_log=self.admin_log,
            admin_anchor_path=self.admin_anchor,
        )
        self.assertEqual(res3["status"], "CLEAN")

    def test_a10_concurrent_multiprocess_admin_recovery(self):
        """A10: Multi-process concurrent recovery serializes safely and avoids duplicated reconciliations."""
        tx_id = "tx-a10-concurrent"
        _append_admin_event_unlocked(
            admin_log=self.admin_log,
            action="TRUST_ROOT_RESET_PREPARED",
            transaction_id=tx_id,
            anchor_path=self.anchor_file,
            vault_path=self.vault_file,
            reason="A10 concurrent recovery test",
            prior_anchor={"index": -1, "head_hash": GENESIS_HASH},
            new_head_hash="a" * 64,
            new_index=0,
        )

        q = multiprocessing.Queue()
        processes = []
        for _ in range(4):
            p = multiprocessing.Process(
                target=_concurrent_admin_recovery_worker,
                args=(self.vault_file, self.anchor_file, self.admin_log, self.admin_anchor, q),
            )
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=10.0)
            self.assertFalse(p.is_alive(), "Recovery worker process timed out or deadlocked")

        results = []
        while not q.empty():
            results.append(q.get())

        self.assertEqual(len(results), 4)
        reconciled_count = sum(1 for r in results if r in {"RECONCILED_ABORTED", "RECONCILED_COMMITTED"})
        clean_count = sum(1 for r in results if r == "CLEAN")
        self.assertEqual(reconciled_count, 1, f"Expected exactly 1 reconciling worker, got: {results}")
        self.assertEqual(clean_count, 3, f"Expected 3 clean workers, got: {results}")

        is_valid, count, head, err = verify_admin_chain(self.admin_log, admin_anchor_path=self.admin_anchor)
        self.assertTrue(is_valid, f"Admin chain corrupted under concurrent recovery: {err}")
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
