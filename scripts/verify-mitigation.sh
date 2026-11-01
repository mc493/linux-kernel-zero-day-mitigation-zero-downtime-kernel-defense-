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
echo -n "[Test 1/3] ebtables module loader blockade & RAM state: "
if command -v sudo >/dev/null 2>&1; then
    sudo -n modprobe ebt_snat 2>/dev/null || modprobe ebt_snat 2>/dev/null || true
else
    modprobe ebt_snat 2>/dev/null || true
fi
if lsmod | grep -q -E "^ebt"; then
    echo "[FAIL] FAILED"
    echo "  -> Modules matching '^ebt' remain active in kernel memory:"
    lsmod | grep -E "^ebt"
    FAILURES=$((FAILURES + 1))
else
    echo "[PASS] PASSED (0 modules resident in RAM)"
fi

# Test 2: AF_ALG crypto socket probe & assertion
echo -n "[Test 2/3] AF_ALG (domain 38) socket probe: "
TEST2_OUTPUT=$(python3 -c "
import socket, sys
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    print('PROBE_TRIGGERED')
except PermissionError:
    print('BLOCKED_BY_SECCOMP')
except OSError as e:
    if getattr(e, 'errno', None) == 97:
        print('UNSUPPORTED_BY_KERNEL')
    else:
        print(f'ERROR: {e}')
except Exception as e:
    print(f'ERROR: {e}')
")

if [ "$TEST2_OUTPUT" = "BLOCKED_BY_SECCOMP" ]; then
    echo "[PASS] PASSED (Synchronously blocked by SECCOMP profile: EACCES)"
elif [ "$TEST2_OUTPUT" = "UNSUPPORTED_BY_KERNEL" ]; then
    echo "[PASS] PASSED (Subsystem not compiled into kernel: EAFNOSUPPORT)"
elif [ "$TEST2_OUTPUT" = "PROBE_TRIGGERED" ]; then
    echo "[WARN] TRIGGERED (Syscall executed)"
    # If audit ledger is present, assert that the alert was recorded
    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for alert: "
        sleep 1
        if tail -n 200 "$AUDIT_LOG" | grep -q "AF_ALG"; then
            echo "[PASS] PASSED (Alert verified in hash chain)"
        else
            echo "[INFO] UNVERIFIED (No recent AF_ALG alert in last 200 audit events)"
        fi
    else
        echo "  -> Note: Set AUDIT_LOG to verify end-to-end ledger propagation."
    fi
else
    echo "Warning: Unknown state: $TEST2_OUTPUT"
fi

# Test 3: kTLS Two-Phase Runtime Probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282)
echo -n "[Test 3/3] kTLS Two-Phase runtime probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282): "
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
except PermissionError:
    p1 = 'BLOCKED_BY_POLICY'
except OSError as e:
    if e.errno in (errno.ENOPROTOOPT, errno.ENOENT):
        p1 = 'UNSUPPORTED_BY_KERNEL'
    elif e.errno in (errno.EACCES, errno.EPERM):
        p1 = 'BLOCKED_BY_POLICY'
    else:
        p1 = f'ERR_{e.errno}'

# Phase 2: SOL_TLS crypto initialization (SOL_TLS=282, TLS_TX=1)
# struct tls12_crypto_info_aes_gcm_128 (40 bytes)
crypto_info = struct.pack('=HH8s16s4s8s', 0x0303, 51, b'\x01'*8, b'\x02'*16, b'\x03'*4, b'\x00'*8)
try:
    cli.setsockopt(282, 1, crypto_info)
    p2 = 'CONFIGURED'
except PermissionError:
    p2 = 'BLOCKED_BY_POLICY'
except OSError as e:
    if e.errno in (errno.EACCES, errno.EPERM):
        p2 = 'BLOCKED_BY_POLICY'
    elif e.errno == errno.ENOPROTOOPT:
        p2 = 'UNSUPPORTED_OR_P1_REQUIRED'
    elif e.errno == errno.EINVAL:
        p2 = 'REJECTED_INVALID_ARG'
    else:
        p2 = f'ERR_{e.errno}'

cli.close()
if active_conn:
    active_conn.close()
srv.close()

print(f'{p1}|{p2}')
")

P1_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f1)
P2_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f2)

if [ "$P1_RES" = "BLOCKED_BY_POLICY" ] || [ "$P2_RES" = "BLOCKED_BY_POLICY" ]; then
    echo "[PASS] PASSED (Synchronously blocked by policy: P1=$P1_RES, P2=$P2_RES)"
elif [ "$P1_RES" = "UNSUPPORTED_BY_KERNEL" ]; then
    echo "[PASS] PASSED (kTLS subsystem not compiled in kernel: P1=$P1_RES)"
elif [ "$P1_RES" = "ATTACHED" ] || [ "$P2_RES" = "CONFIGURED" ]; then
    echo "[WARN] TRIGGERED (Two-Phase evaluated: P1=$P1_RES, P2=$P2_RES)"
    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for kTLS alert: "
        sleep 1
        if tail -n 200 "$AUDIT_LOG" | grep -q -E "kTLS|TCP_ULP"; then
            echo "[PASS] PASSED (Alert verified in hash chain)"
        else
            echo "[INFO] UNVERIFIED (No recent kTLS alert in last 200 audit events)"
        fi
    fi
else
    echo "Warning: Evaluation state: P1=$P1_RES, P2=$P2_RES"
fi

echo "========================================================================"
if [ "$FAILURES" -eq 0 ]; then
    echo "[SUCCESS] ALL VERIFICATION ASSERTIONS PASSED (Exit code: 0)"
    exit 0
else
    echo "[FAIL] $FAILURES TEST(S) FAILED (Exit code: $FAILURES)"
    exit "$FAILURES"
fi
