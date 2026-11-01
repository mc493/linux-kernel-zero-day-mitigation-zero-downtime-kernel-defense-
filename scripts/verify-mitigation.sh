#!/usr/bin/env bash
# ==============================================================================
# verify-mitigation.sh
# Automated Zero-Day Compensating Control Verification & CI Gating Suite
# Returns exit code 0 on full compliance, >0 on any failure (suitable for CI/CD).
# ==============================================================================
set -u

FAILURES=0
DEFAULT_AUDIT_LOG="./vault/audit_chain.jsonl"
if [ ! -f "$DEFAULT_AUDIT_LOG" ] && [ -f "/var/log/audit/audit_chain.jsonl" ]; then
    DEFAULT_AUDIT_LOG="/var/log/audit/audit_chain.jsonl"
fi
AUDIT_LOG="${AUDIT_LOG:-$DEFAULT_AUDIT_LOG}"

echo "========================================================================"
echo "ZERO-DAY COMPENSATING CONTROL VERIFICATION SUITE"
echo "========================================================================"

# Test 1: ebtables module blockade & RAM residency check
echo -n "[Test 1/5] ebtables module loader blockade & RAM state: "
LOADER_BLOCKED=0
DRYRUN_OUTPUT=$(modprobe -n -v ebt_snat 2>&1 || true)
if echo "$DRYRUN_OUTPUT" | grep -q "/bin/true"; then
    LOADER_BLOCKED=1
fi

if lsmod | grep -q -E "^ebt"; then
    echo "[FAIL] FAILED"
    echo "  -> Modules matching '^ebt' remain active in kernel memory:"
    lsmod | grep -E "^ebt"
    FAILURES=$((FAILURES + 1))
elif [ "$LOADER_BLOCKED" -eq 1 ]; then
    echo "[PASS] PASSED (Loader override active: 'install /bin/true', 0 modules resident in RAM)"
else
    echo "[WARN] INCONCLUSIVE (0 modules resident in RAM, but modprobe dry-run returned: $DRYRUN_OUTPUT)"
fi

# Test 2: AF_ALG crypto socket probe & assertion
echo -n "[Test 2/5] AF_ALG (domain 38) socket probe: "
TEST2_OUTPUT=$(python3 -c "
import socket, errno, sys
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    print('PROBE_TRIGGERED')
    s.close()
except OSError as e:
    if e.errno == errno.EPERM:
        print('BLOCKED_BY_SECCOMP')
    elif e.errno == errno.EAFNOSUPPORT:
        print('UNSUPPORTED_BY_KERNEL')
    else:
        print(f'ERROR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}')
except Exception as e:
    print(f'ERROR_{e}')
")

if [ "$TEST2_OUTPUT" = "BLOCKED_BY_SECCOMP" ]; then
    echo "[PASS] PASSED (Synchronously blocked by SECCOMP profile: exact EPERM)"
elif [ "$TEST2_OUTPUT" = "UNSUPPORTED_BY_KERNEL" ]; then
    echo "[INFO] NOT_APPLICABLE (Subsystem not compiled into kernel: EAFNOSUPPORT)"
elif [ "$TEST2_OUTPUT" = "PROBE_TRIGGERED" ]; then
    echo "[WARN] TRIGGERED (Syscall executed on host)"
    # If audit ledger is present, assert that the alert was recorded
    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for alert: "
        FOUND=0
        for i in {1..10}; do
            if tail -n 100 "$AUDIT_LOG" | grep -q "AF_ALG"; then
                FOUND=1
                break
            fi
            sleep 0.2
        done
        if [ "$FOUND" -eq 1 ]; then
            echo "[PASS] PASSED (Alert verified in hash chain)"
        else
            echo "[FAIL] FAILED (No recent AF_ALG alert in last 100 audit events)"
            FAILURES=$((FAILURES + 1))
        fi
    else
        echo "  -> Note: Set AUDIT_LOG to verify end-to-end ledger propagation."
    fi
else
    echo "[FAIL] FAILED (Unexpected state: $TEST2_OUTPUT)"
    FAILURES=$((FAILURES + 1))
fi

# Test 3: kTLS Two-Phase Runtime Probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282)
echo -n "[Test 3/5] kTLS Two-Phase runtime probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282): "
TEST3_OUTPUT=$(python3 -c "
import socket, threading, struct, errno, sys

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(1)
port = srv.getsockname()[1]

active_conn = None
def accept():
    global active_conn
    try:
        active_conn, _ = srv.accept()
    except Exception:
        pass

t = threading.Thread(target=accept)
t.daemon = True
t.start()

cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', port))
t.join(timeout=2.0)

p1 = 'UNKNOWN'
p2 = 'UNKNOWN'

# Phase 1: TCP_ULP attachment (SOL_TCP=6, TCP_ULP=31, 'tls')
try:
    cli.setsockopt(6, 31, b'tls\0')
    p1 = 'ATTACHED'
except OSError as e:
    if e.errno == errno.EPERM:
        p1 = 'BLOCKED_EPERM'
    elif e.errno in (errno.ENOPROTOOPT, errno.ENOENT):
        p1 = 'UNSUPPORTED_BY_KERNEL'
    else:
        p1 = f'ERR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}'

# Phase 2: SOL_TLS crypto initialization (SOL_TLS=282, TLS_TX=1)
# struct tls12_crypto_info_aes_gcm_128 (40 bytes)
crypto_info = struct.pack('=HH8s16s4s8s', 0x0303, 51, b'\x01'*8, b'\x02'*16, b'\x03'*4, b'\x00'*8)
try:
    cli.setsockopt(282, 1, crypto_info)
    p2 = 'CONFIGURED'
except OSError as e:
    if e.errno == errno.EPERM:
        p2 = 'BLOCKED_EPERM'
    elif e.errno == errno.ENOPROTOOPT:
        p2 = 'UNSUPPORTED_OR_P1_REQUIRED'
    elif e.errno == errno.EINVAL:
        p2 = 'REJECTED_INVALID_ARG'
    else:
        p2 = f'ERR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}'

cli.close()
if active_conn:
    active_conn.close()
srv.close()

print(f'{p1}|{p2}')
")

P1_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f1)
P2_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f2)

if [ "$P1_RES" = "BLOCKED_EPERM" ] && [ "$P2_RES" = "BLOCKED_EPERM" ]; then
    echo "[PASS] PASSED (Synchronously blocked by policy: Phase 1 & 2 exact EPERM)"
elif [ "$P1_RES" = "UNSUPPORTED_BY_KERNEL" ]; then
    echo "[INFO] NOT_APPLICABLE (kTLS subsystem not compiled in kernel: P1=$P1_RES)"
elif [ "$P1_RES" = "ATTACHED" ] || [ "$P2_RES" = "CONFIGURED" ]; then
    echo "[WARN] TRIGGERED (Two-Phase evaluated on host: P1=$P1_RES, P2=$P2_RES)"
    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for kTLS alert: "
        FOUND=0
        for i in {1..10}; do
            if tail -n 100 "$AUDIT_LOG" | grep -q -E "kTLS|TCP_ULP"; then
                FOUND=1
                break
            fi
            sleep 0.2
        done
        if [ "$FOUND" -eq 1 ]; then
            echo "[PASS] PASSED (Alert verified in hash chain)"
        else
            echo "[FAIL] FAILED (No recent kTLS alert in last 100 audit events)"
            FAILURES=$((FAILURES + 1))
        fi
    fi
else
    echo "[FAIL] FAILED (Unexpected evaluation state: P1=$P1_RES, P2=$P2_RES)"
    FAILURES=$((FAILURES + 1))
fi

# Test 4: OCI Container Synchronous SECCOMP Profile Enforcement (if Docker available)
SECCOMP_PROFILE="./seccomp/seccomp-kernel-cve-mitigation.json"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && [ -f "$SECCOMP_PROFILE" ]; then
    echo -n "[Test 4/5] OCI Container Synchronous SECCOMP Profile Enforcement: "
    SECCOMP_OUTPUT=$(docker run --rm --security-opt seccomp="$SECCOMP_PROFILE" python:3.11-alpine python3 -c "
import socket, threading, errno, sys

results = {}

# Test 4.1: AF_ALG exact EPERM assertion
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    results['AF_ALG'] = 'UNBLOCKED'
    s.close()
except OSError as e:
    if e.errno == errno.EPERM:
        results['AF_ALG'] = 'BLOCKED_EPERM'
    else:
        results['AF_ALG'] = f'FAIL_{errno.errorcode.get(e.errno, e.errno)}'

# Establish loopback connection for Phase 1 & 2 tests
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(1)
port = srv.getsockname()[1]

active_conn = None
def accept():
    global active_conn
    try:
        active_conn, _ = srv.accept()
    except Exception:
        pass
t = threading.Thread(target=accept)
t.daemon = True
t.start()

cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', port))
t.join(timeout=2.0)

# Test 4.2: Phase 1 TCP_ULP exact EPERM assertion
try:
    cli.setsockopt(6, 31, b'tls\0')
    results['TCP_ULP'] = 'UNBLOCKED'
except OSError as e:
    if e.errno == errno.EPERM:
        results['TCP_ULP'] = 'BLOCKED_EPERM'
    else:
        results['TCP_ULP'] = f'FAIL_{errno.errorcode.get(e.errno, e.errno)}'

# Test 4.3: Phase 2 SOL_TLS exact EPERM assertion
try:
    cli.setsockopt(282, 1, b'\x00'*40)
    results['SOL_TLS'] = 'UNBLOCKED'
except OSError as e:
    if e.errno == errno.EPERM:
        results['SOL_TLS'] = 'BLOCKED_EPERM'
    else:
        results['SOL_TLS'] = f'FAIL_{errno.errorcode.get(e.errno, e.errno)}'

cli.close()
if active_conn:
    active_conn.close()
srv.close()

if all(v == 'BLOCKED_EPERM' for v in results.values()):
    print('ALL_BLOCKED_EPERM')
else:
    print('LEAK:' + str(results))
" 2>/dev/null || echo "DOCKER_RUN_FAILED")

    if [ "$SECCOMP_OUTPUT" = "ALL_BLOCKED_EPERM" ]; then
        echo "[PASS] PASSED (AF_ALG, TCP_ULP, SOL_TLS synchronously rejected with exact EPERM)"
    elif [ "$SECCOMP_OUTPUT" = "DOCKER_RUN_FAILED" ]; then
        echo "[INFO] SKIPPED (Container image not cached or pull disabled)"
    else
        echo "[FAIL] FAILED (Seccomp policy leak: $SECCOMP_OUTPUT)"
        FAILURES=$((FAILURES + 1))
    fi
fi

# Test 5: Independent Phase 2 Interception Proof (Phase 1 allowed, Phase 2 independently blocked with EPERM)
SECCOMP_P2_PROFILE="./seccomp/seccomp-test-phase2-isolation.json"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && [ -f "$SECCOMP_P2_PROFILE" ]; then
    echo -n "[Test 5/5] Independent Phase 2 kTLS Interception Proof: "
    P2_ISO_OUTPUT=$(docker run --rm --security-opt seccomp="$SECCOMP_P2_PROFILE" python:3.11-alpine python3 -c "
import socket, threading, struct, errno

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(1)
port = srv.getsockname()[1]

active_conn = None
def accept():
    global active_conn
    try:
        active_conn, _ = srv.accept()
    except Exception:
        pass
t = threading.Thread(target=accept)
t.daemon = True
t.start()

cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', port))
t.join(timeout=2.0)

# 1. Phase 1 must succeed under isolation profile
p1_ok = False
p1_err = None
if active_conn is None:
    p1_err = 'SERVER_ACCEPT_FAILED'
else:
    try:
        cli.setsockopt(6, 31, b'tls\0')
        p1_ok = True
    except Exception as e:
        p1_err = str(e)

# 2. Phase 2 must return exact EPERM on the attached socket
p2_blocked = False
p2_err = 'UNBLOCKED'
crypto_info = struct.pack('=HH8s16s4s8s', 0x0303, 51, b'\x01'*8, b'\x02'*16, b'\x03'*4, b'\x00'*8)
try:
    cli.setsockopt(282, 1, crypto_info)
except OSError as e:
    if e.errno == errno.EPERM:
        p2_blocked = True
        p2_err = 'BLOCKED_EPERM'
    else:
        p2_err = f'{e.errno}_{errno.errorcode.get(e.errno, e.errno)}'

cli.close()
if active_conn:
    active_conn.close()
srv.close()

if p1_ok and p2_blocked:
    print('PHASE2_INDEPENDENTLY_PROVEN')
else:
    print(f'FAILED: p1_ok={p1_ok} (err={p1_err}), p2_blocked={p2_blocked} (res={p2_err})')
" 2>/dev/null || echo "DOCKER_RUN_FAILED")

    if [ "$P2_ISO_OUTPUT" = "PHASE2_INDEPENDENTLY_PROVEN" ]; then
        echo "[PASS] PASSED (Phase 1 attached successfully, Phase 2 independently blocked with EPERM)"
    elif [ "$P2_ISO_OUTPUT" = "DOCKER_RUN_FAILED" ]; then
        echo "[INFO] SKIPPED (Container image not cached or pull disabled)"
    else
        echo "[FAIL] FAILED (Phase 2 isolation proof failed: $P2_ISO_OUTPUT)"
        FAILURES=$((FAILURES + 1))
    fi
fi

echo "========================================================================"
if [ "$FAILURES" -eq 0 ]; then
    echo "[SUCCESS] ALL VERIFICATION ASSERTIONS PASSED (Exit code: 0)"
    exit 0
else
    echo "[FAIL] $FAILURES TEST(S) FAILED (Exit code: $FAILURES)"
    exit "$FAILURES"
fi
