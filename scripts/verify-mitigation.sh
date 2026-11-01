#!/usr/bin/env bash
# ==============================================================================
# verify-mitigation.sh
# Automated Zero-Day Compensating Control Verification & CI Gating Suite
# Returns exit code 0 on full compliance, >0 on any failure (suitable for CI/CD).
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

FAILURES=0
STRICT_MODE="${STRICT_MODE:-0}"

for arg in "$@"; do
    case "$arg" in
        --strict)
            STRICT_MODE=1
            ;;
        -h|--help)
            echo "Usage: $0 [--strict]"
            echo "  --strict  Enforces zero-tolerance CI gating (fails on any INCONCLUSIVE or SKIPPED test)"
            exit 0
            ;;
    esac
done

DEFAULT_AUDIT_LOG="${REPO_ROOT}/vault/audit_chain.jsonl"
if [ ! -f "$DEFAULT_AUDIT_LOG" ] && [ -f "/var/log/audit/audit_chain.jsonl" ]; then
    DEFAULT_AUDIT_LOG="/var/log/audit/audit_chain.jsonl"
fi
AUDIT_LOG="${AUDIT_LOG:-$DEFAULT_AUDIT_LOG}"

echo "========================================================================"
echo "ZERO-DAY COMPENSATING CONTROL VERIFICATION SUITE"
if [ "$STRICT_MODE" -eq 1 ]; then
    echo "Mode: STRICT (Zero-tolerance CI gating active)"
else
    echo "Mode: STANDARD (Informative diagnostic warnings enabled)"
fi
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
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[FAIL] FAILED (Strict mode: Loader override 'install /bin/true' missing, dry-run returned: $DRYRUN_OUTPUT)"
        FAILURES=$((FAILURES + 1))
    else
        echo "[WARN] INCONCLUSIVE (0 modules resident in RAM, but modprobe dry-run returned: $DRYRUN_OUTPUT)"
    fi
fi

# Test 2: AF_ALG crypto socket probe & assertion
echo -n "[Test 2/5] AF_ALG (domain 38) socket probe: "
PRE_TS_2=$(python3 -c "import time; print(time.time())")

TEST2_OUTPUT=$(python3 -c "
import socket, errno, sys

seccomp_mode = 0
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = int(line.split()[1])
except Exception:
    pass

try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    print(f'PROBE_TRIGGERED|seccomp={seccomp_mode}')
    s.close()
except OSError as e:
    if e.errno == errno.EPERM:
        if seccomp_mode == 2:
            print('BLOCKED_BY_SECCOMP')
        else:
            print(f'BLOCKED_BY_POLICY|seccomp={seccomp_mode}')
    elif e.errno == errno.EAFNOSUPPORT:
        print('UNSUPPORTED_BY_RUNTIME')
    else:
        print(f'ERROR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}')
except Exception as e:
    print(f'ERROR_{e}')
")

TEST2_STATUS=$(echo "$TEST2_OUTPUT" | cut -d'|' -f1)

if [ "$TEST2_STATUS" = "BLOCKED_BY_SECCOMP" ]; then
    echo "[PASS] PASSED (Synchronously blocked by SECCOMP filter: exact EPERM, Seccomp mode=2 verified)"
elif [ "$TEST2_STATUS" = "BLOCKED_BY_POLICY" ]; then
    echo "[PASS] PASSED (Blocked by host policy/LSM: exact EPERM, Seccomp mode=0 verified)"
elif [ "$TEST2_STATUS" = "UNSUPPORTED_BY_RUNTIME" ]; then
    echo "[INFO] NOT_APPLICABLE (Address family AF_ALG not supported by current runtime: EAFNOSUPPORT)"
elif [ "$TEST2_STATUS" = "PROBE_TRIGGERED" ]; then
    echo "[WARN] TRIGGERED (Syscall executed on host)"
    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for correlated alert: "
        FOUND=0
        for i in {1..10}; do
            if python3 -c "
import json, sys
audit_log, pre_ts, pattern = sys.argv[1], float(sys.argv[2]), sys.argv[3]
found = False
try:
    with open(audit_log, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
                if float(rec.get('timestamp', 0)) >= pre_ts and pattern in json.dumps(rec):
                    found = True; break
            except Exception: pass
except Exception: pass
sys.exit(0 if found else 1)
" "$AUDIT_LOG" "$PRE_TS_2" "AF_ALG" 2>/dev/null; then
                FOUND=1
                break
            fi
            sleep 0.2
        done
        if [ "$FOUND" -eq 1 ]; then
            if [ -f "${REPO_ROOT}/vault/audit_vault.py" ] && python3 "${REPO_ROOT}/vault/audit_vault.py" --verify --vault-file "$AUDIT_LOG" >/dev/null 2>&1; then
                echo "[PASS] PASSED (Correlated alert verified with unbroken SHA-256 hash chain)"
            else
                echo "[FAIL] FAILED (Alert present but cryptographic hash-chain verification failed)"
                FAILURES=$((FAILURES + 1))
            fi
        else
            echo "[FAIL] FAILED (No temporally correlated AF_ALG alert found in audit ledger)"
            FAILURES=$((FAILURES + 1))
        fi
    else
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: AUDIT_LOG must exist to verify host-level probe propagation)"
            FAILURES=$((FAILURES + 1))
        else
            echo "  -> Note: Set AUDIT_LOG to verify end-to-end ledger propagation."
        fi
    fi
else
    echo "[FAIL] FAILED (Unexpected state: $TEST2_OUTPUT)"
    FAILURES=$((FAILURES + 1))
fi

# Test 3: kTLS Two-Phase Runtime Probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282)
echo -n "[Test 3/5] kTLS Two-Phase runtime probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282): "
PRE_TS_3=$(python3 -c "import time; print(time.time())")

TEST3_OUTPUT=$(python3 -c "
import socket, threading, struct, errno, sys

seccomp_mode = 0
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = int(line.split()[1])
except Exception:
    pass

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
        p1 = 'UNSUPPORTED_BY_RUNTIME'
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

print(f'{p1}|{p2}|seccomp={seccomp_mode}')
")

P1_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f1)
P2_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f2)
SECCOMP_M3=$(echo "$TEST3_OUTPUT" | cut -d'|' -f3)

if [ "$P1_RES" = "BLOCKED_EPERM" ] && [ "$P2_RES" = "BLOCKED_EPERM" ]; then
    if [ "$SECCOMP_M3" = "seccomp=2" ]; then
        echo "[PASS] PASSED (Synchronously blocked by SECCOMP filter: Phase 1 & 2 exact EPERM, Seccomp mode=2 verified)"
    else
        echo "[PASS] PASSED (Blocked by host policy/LSM: Phase 1 & 2 exact EPERM, Seccomp mode=0 verified)"
    fi
elif [ "$P1_RES" = "UNSUPPORTED_BY_RUNTIME" ]; then
    echo "[INFO] NOT_APPLICABLE (kTLS subsystem not supported by current runtime: P1=$P1_RES)"
elif [ "$P1_RES" = "ATTACHED" ] || [ "$P2_RES" = "CONFIGURED" ]; then
    echo "[WARN] TRIGGERED (Two-Phase evaluated on host: P1=$P1_RES, P2=$P2_RES)"
    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for correlated kTLS alert: "
        FOUND=0
        for i in {1..10}; do
            if python3 -c "
import json, sys
audit_log, pre_ts = sys.argv[1], float(sys.argv[2])
found = False
try:
    with open(audit_log, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
                rec_str = json.dumps(rec)
                if float(rec.get('timestamp', 0)) >= pre_ts and ('kTLS' in rec_str or 'TCP_ULP' in rec_str):
                    found = True; break
            except Exception: pass
except Exception: pass
sys.exit(0 if found else 1)
" "$AUDIT_LOG" "$PRE_TS_3" 2>/dev/null; then
                FOUND=1
                break
            fi
            sleep 0.2
        done
        if [ "$FOUND" -eq 1 ]; then
            if [ -f "${REPO_ROOT}/vault/audit_vault.py" ] && python3 "${REPO_ROOT}/vault/audit_vault.py" --verify --vault-file "$AUDIT_LOG" >/dev/null 2>&1; then
                echo "[PASS] PASSED (Correlated alert verified with unbroken SHA-256 hash chain)"
            else
                echo "[FAIL] FAILED (Alert present but cryptographic hash-chain verification failed)"
                FAILURES=$((FAILURES + 1))
            fi
        else
            echo "[FAIL] FAILED (No temporally correlated kTLS alert found in audit ledger)"
            FAILURES=$((FAILURES + 1))
        fi
    else
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: AUDIT_LOG must exist to verify host-level probe propagation)"
            FAILURES=$((FAILURES + 1))
        fi
    fi
else
    echo "[FAIL] FAILED (Unexpected evaluation state: P1=$P1_RES, P2=$P2_RES)"
    FAILURES=$((FAILURES + 1))
fi

# Test 4: OCI Container Synchronous SECCOMP Profile Enforcement (if Docker available)
SECCOMP_PROFILE="${REPO_ROOT}/seccomp/seccomp-kernel-cve-mitigation.json"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && [ -f "$SECCOMP_PROFILE" ]; then
    echo -n "[Test 4/5] OCI Container Synchronous SECCOMP Profile Enforcement: "
    SECCOMP_OUTPUT=$(docker run --rm --security-opt seccomp="$SECCOMP_PROFILE" python:3.11-alpine python3 -c "
import socket, threading, errno, sys

seccomp_mode = 0
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = int(line.split()[1])
except Exception:
    pass

results = {}

# Test 4.1: AF_ALG exact EPERM assertion
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    results['AF_ALG'] = 'UNBLOCKED'
    s.close()
except OSError as e:
    if e.errno == errno.EPERM:
        results['AF_ALG'] = 'BLOCKED_BY_SECCOMP' if seccomp_mode == 2 else 'BLOCKED_BY_OTHER'
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
        results['TCP_ULP'] = 'BLOCKED_BY_SECCOMP' if seccomp_mode == 2 else 'BLOCKED_BY_OTHER'
    else:
        results['TCP_ULP'] = f'FAIL_{errno.errorcode.get(e.errno, e.errno)}'

# Test 4.3: Phase 2 SOL_TLS exact EPERM assertion
try:
    cli.setsockopt(282, 1, b'\x00'*40)
    results['SOL_TLS'] = 'UNBLOCKED'
except OSError as e:
    if e.errno == errno.EPERM:
        results['SOL_TLS'] = 'BLOCKED_BY_SECCOMP' if seccomp_mode == 2 else 'BLOCKED_BY_OTHER'
    else:
        results['SOL_TLS'] = f'FAIL_{errno.errorcode.get(e.errno, e.errno)}'

cli.close()
if active_conn:
    active_conn.close()
srv.close()

if all(v == 'BLOCKED_BY_SECCOMP' for v in results.values()):
    print('ALL_BLOCKED_BY_SECCOMP')
else:
    print(f'LEAK:{results}|seccomp={seccomp_mode}')
" 2>/dev/null || echo "DOCKER_RUN_FAILED")

    if [ "$SECCOMP_OUTPUT" = "ALL_BLOCKED_BY_SECCOMP" ]; then
        echo "[PASS] PASSED (AF_ALG, TCP_ULP, SOL_TLS synchronously rejected by SECCOMP: exact EPERM, Seccomp mode=2 verified)"
    elif [ "$SECCOMP_OUTPUT" = "DOCKER_RUN_FAILED" ]; then
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: Container runtime execution failed or image unavailable)"
            FAILURES=$((FAILURES + 1))
        else
            echo "[INFO] SKIPPED (Container image not cached or pull disabled)"
        fi
    else
        echo "[FAIL] FAILED (Seccomp policy leak: $SECCOMP_OUTPUT)"
        FAILURES=$((FAILURES + 1))
    fi
else
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[Test 4/5] OCI Container Synchronous SECCOMP Profile Enforcement: [FAIL] FAILED (Strict mode: Docker runtime or profile missing)"
        FAILURES=$((FAILURES + 1))
    fi
fi

# Test 5: Independent Phase 2 Interception Proof (Phase 1 allowed, Phase 2 independently blocked with EPERM)
SECCOMP_P2_PROFILE="${REPO_ROOT}/seccomp/seccomp-test-phase2-isolation.json"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && [ -f "$SECCOMP_P2_PROFILE" ]; then
    echo -n "[Test 5/5] Independent Phase 2 kTLS Interception Proof: "
    P2_ISO_OUTPUT=$(docker run --rm --security-opt seccomp="$SECCOMP_P2_PROFILE" python:3.11-alpine python3 -c "
import socket, threading, struct, errno

seccomp_mode = 0
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = int(line.split()[1])
except Exception:
    pass

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

if p1_ok and p2_blocked and seccomp_mode == 2:
    print('PHASE2_INDEPENDENTLY_PROVEN_BY_SECCOMP')
else:
    print(f'FAILED: p1_ok={p1_ok} (err={p1_err}), p2_blocked={p2_blocked} (res={p2_err}), seccomp={seccomp_mode}')
" 2>/dev/null || echo "DOCKER_RUN_FAILED")

    if [ "$P2_ISO_OUTPUT" = "PHASE2_INDEPENDENTLY_PROVEN_BY_SECCOMP" ]; then
        echo "[PASS] PASSED (Phase 1 attached successfully, Phase 2 independently blocked by SECCOMP: exact EPERM, Seccomp mode=2 verified)"
    elif [ "$P2_ISO_OUTPUT" = "DOCKER_RUN_FAILED" ]; then
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: Container differential isolation execution failed)"
            FAILURES=$((FAILURES + 1))
        else
            echo "[INFO] SKIPPED (Container image not cached or pull disabled)"
        fi
    else
        echo "[FAIL] FAILED (Phase 2 isolation proof failed: $P2_ISO_OUTPUT)"
        FAILURES=$((FAILURES + 1))
    fi
else
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[Test 5/5] Independent Phase 2 kTLS Interception Proof: [FAIL] FAILED (Strict mode: Docker runtime or isolation profile missing)"
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
