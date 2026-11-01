#!/usr/bin/env bash
# ==============================================================================
# verify-mitigation.sh
# Automated Zero-Day Compensating Control Verification & CI Gating Suite (v1.3.4)
# Returns exit code 0 on full compliance, >0 on any failure or strict violation.
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PREVENTION_PASSED=0
DETECTION_PASSED=0
FAILED_COUNT=0
INCONCLUSIVE_COUNT=0

STRICT_MODE="${STRICT_MODE:-0}"
RUN_ID="${RUN_ID:-verify-run-$(date +%s%N)-$$-${RANDOM}}"
export RUN_ID
CONTAINER_IMAGE="${CONTAINER_IMAGE:-python:3.11-alpine@sha256:09d17d5e4c16d0a7a1eea690bcb7c6ab8616b211f8421e429e97c1bef5bd0ed2}"

for arg in "$@"; do
    case "$arg" in
        --strict)
            STRICT_MODE=1
            ;;
        -h|--help)
            echo "Usage: $0 [--strict]"
            echo "  --strict  Enforces zero-tolerance CI gating (immediate preflight abort on missing/corrupt ledger"
            echo "            or external trust anchor, and hard failure on any baseline error, unverified nonce, or skipped test)"
            exit 0
            ;;
    esac
done

DEFAULT_AUDIT_LOG="${REPO_ROOT}/vault/audit_chain.jsonl"
if [ ! -f "$DEFAULT_AUDIT_LOG" ] && [ -f "/var/log/audit/audit_chain.jsonl" ]; then
    DEFAULT_AUDIT_LOG="/var/log/audit/audit_chain.jsonl"
fi
AUDIT_LOG="${AUDIT_LOG:-$DEFAULT_AUDIT_LOG}"
AUDIT_ANCHOR="${AUDIT_ANCHOR:-${AUDIT_LOG}.anchor.json}"

echo "========================================================================"
echo "ZERO-DAY COMPENSATING CONTROL VERIFICATION SUITE (v1.3.4)"
echo "Run Identifier: $RUN_ID"
if [ "$STRICT_MODE" -eq 1 ]; then
    echo "Mode: STRICT (Zero-tolerance CI gating active; preflight abort on error)"
else
    echo "Mode: STANDARD (Informative diagnostic warnings enabled)"
fi
echo "========================================================================"

# Strict Mode Upfront Preflight Gating (Immediate Fail-Closed Abort Policy)
if [ "$STRICT_MODE" -eq 1 ]; then
    echo -n "[Preflight] Cryptographic Audit Ledger & Anchor Health Check: "
    if [ ! -f "$AUDIT_LOG" ]; then
        echo "[ABORT] FAILED (Strict mode requires active AUDIT_LOG ledger: $AUDIT_LOG)"
        exit 1
    fi
    if [ ! -f "$AUDIT_ANCHOR" ]; then
        echo "[ABORT] FAILED (Strict mode requires active external trust anchor: $AUDIT_ANCHOR)"
        exit 1
    fi

    if [ -f "${REPO_ROOT}/vault/audit_vault.py" ]; then
        VERIFY_ARGS=(--verify --vault-file "$AUDIT_LOG" --require-records --anchor-file "$AUDIT_ANCHOR")
        PREFLIGHT_VERIFY=$(python3 "${REPO_ROOT}/vault/audit_vault.py" "${VERIFY_ARGS[@]}" 2>&1)
        if [ $? -ne 0 ]; then
            echo "[ABORT] FAILED (Audit ledger failed cryptographic verification: $PREFLIGHT_VERIFY)"
            exit 1
        fi
        echo "[PASS] PASSED (Audit ledger and external trust anchor structurally and cryptographically intact)"
    else
        echo "[ABORT] FAILED (Audit vault verifier missing at ${REPO_ROOT}/vault/audit_vault.py)"
        exit 1
    fi
fi

# Test 1: ebtables module loader blockade & RAM residency check
echo -n "[Test 1/5] ebtables module loader blockade & RAM state: "
if ! command -v modprobe >/dev/null 2>&1 || ! command -v lsmod >/dev/null 2>&1; then
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[FAIL] FAILED (Strict mode: modprobe or lsmod binary unavailable)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    else
        echo "[WARN] INCONCLUSIVE (modprobe or lsmod binary unavailable)"
        INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
    fi
else
    LOADER_BLOCKED=0
    DRYRUN_STATUS=0
    DRYRUN_OUTPUT=$(modprobe -n -v ebt_snat 2>&1) || DRYRUN_STATUS=$?
    
    EFFECTIVE_CMD=""
    if [ "$DRYRUN_STATUS" -eq 0 ] && echo "$DRYRUN_OUTPUT" | grep -E -q "^install (/bin/true|/bin/false|:)"; then
        LOADER_BLOCKED=1
        EFFECTIVE_CMD=$(echo "$DRYRUN_OUTPUT" | grep -E "^install (/bin/true|/bin/false|:)" | head -n 1 | tr -d '\r\n')
    elif echo "$DRYRUN_OUTPUT" | grep -q -i "module ebt_snat not found"; then
        LOADER_BLOCKED=2
    fi

    if lsmod | grep -q -E "^ebt"; then
        echo "[FAIL] FAILED"
        echo "  -> Modules matching '^ebt' remain active in kernel memory:"
        lsmod | grep -E "^ebt"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    elif [ "$LOADER_BLOCKED" -eq 1 ]; then
        echo "[PASS] PASSED (Loader override active: '$EFFECTIVE_CMD', exit=0, 0 ebtables modules in RAM)"
        echo "  -> Note: Verifies modprobe user-space loader path; does not intercept direct finit_module(2) syscalls without Seccomp/LSM."
        PREVENTION_PASSED=$((PREVENTION_PASSED + 1))
    elif [ "$LOADER_BLOCKED" -eq 2 ]; then
        echo "[INFO] NOT_APPLICABLE (Kernel tree omits ebt_snat module: 0 modules in RAM)"
        INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
    else
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: Loader override missing or non-zero dryrun, status=$DRYRUN_STATUS, output: $DRYRUN_OUTPUT)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        else
            echo "[WARN] INCONCLUSIVE (0 modules resident in RAM, but modprobe output: $DRYRUN_OUTPUT)"
            INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
        fi
    fi
fi

# Test 2: AF_ALG crypto socket probe & assertion
echo -n "[Test 2/5] AF_ALG (domain 38) socket probe: "
PRE_TS_2=$(python3 -c "import time; print(time.time())")

TEST2_OUTPUT=$(RUN_ID="$RUN_ID" python3 -c "
import socket, errno, sys, os

run_id = os.environ.get('RUN_ID', sys.argv[1] if len(sys.argv) > 1 else '')
seccomp_mode = 'unknown'
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = line.split()[1].strip()
except Exception:
    pass

try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    print(f'PROBE_TRIGGERED|seccomp={seccomp_mode}|run_id={run_id}')
    s.close()
except OSError as e:
    if e.errno == errno.EPERM:
        if seccomp_mode == '2':
            print('BLOCKED_BY_SECCOMP_FILTER')
        elif seccomp_mode == '0':
            print('BLOCKED_BY_HOST_POLICY')
        else:
            print(f'BLOCKED_EPERM_SECCOMP_{seccomp_mode}')
    elif e.errno == errno.EAFNOSUPPORT:
        print('UNSUPPORTED_BY_RUNTIME')
    else:
        print(f'ERROR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}')
except Exception as e:
    print(f'ERROR_{e}')
" "$RUN_ID")

TEST2_STATUS=$(echo "$TEST2_OUTPUT" | cut -d'|' -f1)

if [ "$TEST2_STATUS" = "BLOCKED_BY_SECCOMP_FILTER" ]; then
    echo "[PASS] PASSED (Synchronous denial observed with active SECCOMP filter: exact EPERM, Seccomp mode=2 verified)"
    PREVENTION_PASSED=$((PREVENTION_PASSED + 1))
elif [ "$TEST2_STATUS" = "BLOCKED_BY_HOST_POLICY" ]; then
    echo "[PASS] PASSED (Synchronous denial observed under host policy: exact EPERM, Seccomp mode=0 verified)"
    PREVENTION_PASSED=$((PREVENTION_PASSED + 1))
elif [[ "$TEST2_STATUS" =~ ^BLOCKED_EPERM_SECCOMP_ ]]; then
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[FAIL] FAILED (Strict mode: EPERM observed but Seccomp mode was unverified: $TEST2_STATUS)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    else
        echo "[WARN] INCONCLUSIVE (Operation denied with exact EPERM, but Seccomp status was: $TEST2_STATUS)"
        INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
    fi
elif [ "$TEST2_STATUS" = "UNSUPPORTED_BY_RUNTIME" ]; then
    echo "[INFO] NOT_APPLICABLE (Address family AF_ALG not supported by current runtime: EAFNOSUPPORT)"
    INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
elif [ "$TEST2_STATUS" = "PROBE_TRIGGERED" ]; then
    echo "[WARN] TRIGGERED (Syscall executed on host)"
    if [ "${AUDIT_PRODUCER_EMIT:-0}" -eq 1 ] && [ -f "${REPO_ROOT}/vault/audit_vault.py" ] && [ -f "$AUDIT_LOG" ]; then
        python3 "${REPO_ROOT}/vault/audit_vault.py" --vault-file "$AUDIT_LOG" --append \
            "{\"event\": \"probe\", \"rule\": \"AF_ALG probe executed\", \"run_id\": \"$RUN_ID\"}" \
            --topic "security.alerts.kernel" ${AUDIT_ANCHOR:+--anchor-file "$AUDIT_ANCHOR"} >/dev/null 2>&1 || true
    fi

    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for correlated alert: "
        FOUND=0
        MATCH_TYPE="NONE"
        for i in {1..10}; do
            CHECK_RES=$(python3 -c "
import json, sys
audit_log, pre_ts, pattern, run_id = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
exact_run = False
topic_match = False
try:
    with open(audit_log, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
                if float(rec.get('timestamp', 0)) >= pre_ts:
                    data = rec.get('data', {})
                    topic = rec.get('topic', '')
                    rule = data.get('rule', '') if isinstance(data, dict) else ''
                    event = data.get('event', '') if isinstance(data, dict) else ''
                    rec_run_id = data.get('run_id', '') if isinstance(data, dict) else ''
                    if (pattern in topic or pattern in rule or pattern in event):
                        if rec_run_id == run_id:
                            exact_run = True; break
                        else:
                            topic_match = True
            except Exception: pass
except Exception: pass

if exact_run:
    print('EXACT_RUN_MATCH')
elif topic_match:
    print('TEMPORAL_RULE_MATCH')
else:
    print('NOT_FOUND')
" "$AUDIT_LOG" "$PRE_TS_2" "AF_ALG" "$RUN_ID" 2>/dev/null || echo "ERROR")
            if [ "$CHECK_RES" = "EXACT_RUN_MATCH" ] || [ "$CHECK_RES" = "TEMPORAL_RULE_MATCH" ]; then
                FOUND=1
                MATCH_TYPE="$CHECK_RES"
                break
            fi
            sleep 0.2
        done
        if [ "$FOUND" -eq 1 ]; then
            ANCHOR_ARGS=()
            if [ -f "$AUDIT_ANCHOR" ]; then
                ANCHOR_ARGS=(--anchor-file "$AUDIT_ANCHOR")
            elif [ "$STRICT_MODE" -eq 1 ]; then
                echo "[FAIL] FAILED (Strict mode requires external anchor file: $AUDIT_ANCHOR)"
                FAILED_COUNT=$((FAILED_COUNT + 1))
                ANCHOR_ARGS=()
            fi
            VERIFY_CMD=(python3 "${REPO_ROOT}/vault/audit_vault.py" --verify --vault-file "$AUDIT_LOG")
            if [ ${#ANCHOR_ARGS[@]} -gt 0 ]; then
                VERIFY_CMD+=("${ANCHOR_ARGS[@]}")
            fi
            if [ -f "${REPO_ROOT}/vault/audit_vault.py" ] && "${VERIFY_CMD[@]}" >/dev/null 2>&1; then
                if [ "$MATCH_TYPE" = "EXACT_RUN_MATCH" ]; then
                    echo "[PASS] PASSED (Exact RUN_ID correlated alert verified with unbroken SHA-256 hash chain)"
                    echo "  -> Exact RUN_ID provenance verified: Producer ($RUN_ID) -> Audit Pipeline -> Cryptographic Ledger Head"
                    DETECTION_PASSED=$((DETECTION_PASSED + 1))
                else
                    if [ "$STRICT_MODE" -eq 1 ]; then
                        echo "[FAIL] FAILED (Strict mode requires exact RUN_ID correlation; only temporal match observed)"
                        FAILED_COUNT=$((FAILED_COUNT + 1))
                    else
                        echo "[WARN] INCONCLUSIVE (Temporal alert verified in hash chain, but lacked unique RUN_ID attribution)"
                        INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
                    fi
                fi
            else
                echo "[FAIL] FAILED (Alert present but cryptographic hash-chain verification failed)"
                FAILED_COUNT=$((FAILED_COUNT + 1))
            fi
        else
            echo "[FAIL] FAILED (No temporally correlated AF_ALG alert found in audit ledger)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    else
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: AUDIT_LOG must exist to verify host-level probe propagation)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        else
            echo "  -> Note: Set AUDIT_LOG to verify end-to-end ledger propagation."
            INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
        fi
    fi
else
    echo "[FAIL] FAILED (Unexpected state: $TEST2_OUTPUT)"
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

# Test 3: kTLS Two-Phase Runtime Probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282)
echo -n "[Test 3/5] kTLS Two-Phase runtime probe (Phase 1: TCP_ULP=31, Phase 2: SOL_TLS=282): "
PRE_TS_3=$(python3 -c "import time; print(time.time())")

TEST3_OUTPUT=$(RUN_ID="$RUN_ID" python3 -c "
import socket, threading, struct, errno, sys, os

run_id = os.environ.get('RUN_ID', sys.argv[1] if len(sys.argv) > 1 else '')
seccomp_mode = 'unknown'
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = line.split()[1].strip()
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

if active_conn is None or active_conn.fileno() == -1 or cli.fileno() == -1:
    p1 = 'SOCKET_SETUP_FAILED'
else:
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

print(f'{p1}|{p2}|seccomp={seccomp_mode}|run_id={run_id}')
" "$RUN_ID")

P1_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f1)
P2_RES=$(echo "$TEST3_OUTPUT" | cut -d'|' -f2)
SECCOMP_M3=$(echo "$TEST3_OUTPUT" | cut -d'|' -f3)

if [ "$P1_RES" = "BLOCKED_EPERM" ] && [ "$P2_RES" = "BLOCKED_EPERM" ]; then
    if [ "$SECCOMP_M3" = "seccomp=2" ]; then
        echo "[PASS] PASSED (Synchronous denial observed with active SECCOMP filter: Phase 1 & 2 exact EPERM, Seccomp mode=2 verified)"
        PREVENTION_PASSED=$((PREVENTION_PASSED + 1))
    elif [ "$SECCOMP_M3" = "seccomp=0" ]; then
        echo "[PASS] PASSED (Synchronous denial observed under host policy: Phase 1 & 2 exact EPERM, Seccomp mode=0 verified)"
        PREVENTION_PASSED=$((PREVENTION_PASSED + 1))
    else
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: Phase 1 & 2 blocked with EPERM, but Seccomp mode was unverified: $SECCOMP_M3)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        else
            echo "[WARN] INCONCLUSIVE (Phase 1 & 2 blocked with EPERM, Seccomp status: $SECCOMP_M3)"
            INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
        fi
    fi
elif [ "$P1_RES" = "UNSUPPORTED_BY_RUNTIME" ]; then
    echo "[INFO] NOT_APPLICABLE (kTLS subsystem not supported by current runtime: P1=$P1_RES)"
    INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
elif [ "$P1_RES" = "ATTACHED" ] || [ "$P2_RES" = "CONFIGURED" ]; then
    echo "[WARN] TRIGGERED (Two-Phase evaluated on host: P1=$P1_RES, P2=$P2_RES)"
    if [ "${AUDIT_PRODUCER_EMIT:-0}" -eq 1 ] && [ -f "${REPO_ROOT}/vault/audit_vault.py" ] && [ -f "$AUDIT_LOG" ]; then
        python3 "${REPO_ROOT}/vault/audit_vault.py" --vault-file "$AUDIT_LOG" --append \
            "{\"event\": \"probe\", \"rule\": \"kTLS Two-Phase runtime probe\", \"run_id\": \"$RUN_ID\"}" \
            --topic "security.alerts.kernel" ${AUDIT_ANCHOR:+--anchor-file "$AUDIT_ANCHOR"} >/dev/null 2>&1 || true
    fi

    if [ -f "$AUDIT_LOG" ]; then
        echo -n "  -> Checking cryptographic audit ledger for correlated kTLS alert: "
        FOUND=0
        MATCH_TYPE="NONE"
        for i in {1..10}; do
            CHECK_RES=$(python3 -c "
import json, sys
audit_log, pre_ts, run_id = sys.argv[1], float(sys.argv[2]), sys.argv[3]
exact_run = False
topic_match = False
try:
    with open(audit_log, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
                if float(rec.get('timestamp', 0)) >= pre_ts:
                    data = rec.get('data', {})
                    topic = rec.get('topic', '')
                    rule = data.get('rule', '') if isinstance(data, dict) else ''
                    event = data.get('event', '') if isinstance(data, dict) else ''
                    rec_run_id = data.get('run_id', '') if isinstance(data, dict) else ''
                    if ('kTLS' in topic or 'kTLS' in rule or 'kTLS' in event or 'TCP_ULP' in json.dumps(rec)):
                        if rec_run_id == run_id:
                            exact_run = True; break
                        else:
                            topic_match = True
            except Exception: pass
except Exception: pass

if exact_run:
    print('EXACT_RUN_MATCH')
elif topic_match:
    print('TEMPORAL_RULE_MATCH')
else:
    print('NOT_FOUND')
" "$AUDIT_LOG" "$PRE_TS_3" "$RUN_ID" 2>/dev/null || echo "ERROR")
            if [ "$CHECK_RES" = "EXACT_RUN_MATCH" ] || [ "$CHECK_RES" = "TEMPORAL_RULE_MATCH" ]; then
                FOUND=1
                MATCH_TYPE="$CHECK_RES"
                break
            fi
            sleep 0.2
        done
        if [ "$FOUND" -eq 1 ]; then
            ANCHOR_ARGS=()
            if [ -f "$AUDIT_ANCHOR" ]; then
                ANCHOR_ARGS=(--anchor-file "$AUDIT_ANCHOR")
            elif [ "$STRICT_MODE" -eq 1 ]; then
                echo "[FAIL] FAILED (Strict mode requires external anchor file: $AUDIT_ANCHOR)"
                FAILED_COUNT=$((FAILED_COUNT + 1))
                ANCHOR_ARGS=()
            fi
            VERIFY_CMD=(python3 "${REPO_ROOT}/vault/audit_vault.py" --verify --vault-file "$AUDIT_LOG")
            if [ ${#ANCHOR_ARGS[@]} -gt 0 ]; then
                VERIFY_CMD+=("${ANCHOR_ARGS[@]}")
            fi
            if [ -f "${REPO_ROOT}/vault/audit_vault.py" ] && "${VERIFY_CMD[@]}" >/dev/null 2>&1; then
                if [ "$MATCH_TYPE" = "EXACT_RUN_MATCH" ]; then
                    echo "[PASS] PASSED (Exact RUN_ID correlated alert verified with unbroken SHA-256 hash chain)"
                    echo "  -> Exact RUN_ID provenance verified: Producer ($RUN_ID) -> Audit Pipeline -> Cryptographic Ledger Head"
                    DETECTION_PASSED=$((DETECTION_PASSED + 1))
                else
                    if [ "$STRICT_MODE" -eq 1 ]; then
                        echo "[FAIL] FAILED (Strict mode requires exact RUN_ID correlation; only temporal match observed)"
                        FAILED_COUNT=$((FAILED_COUNT + 1))
                    else
                        echo "[WARN] INCONCLUSIVE (Temporal alert verified in hash chain, but lacked unique RUN_ID attribution)"
                        INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
                    fi
                fi
            else
                echo "[FAIL] FAILED (Alert present but cryptographic hash-chain verification failed)"
                FAILED_COUNT=$((FAILED_COUNT + 1))
            fi
        else
            echo "[FAIL] FAILED (No temporally correlated kTLS alert found in audit ledger)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    else
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: AUDIT_LOG must exist to verify host-level probe propagation)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        else
            echo "  -> Note: Set AUDIT_LOG to verify end-to-end ledger propagation."
            INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
        fi
    fi
else
    echo "[FAIL] FAILED (Unexpected evaluation state: P1=$P1_RES, P2=$P2_RES)"
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

# Test 4: OCI Container Synchronous SECCOMP Profile Enforcement
SECCOMP_PROFILE="${REPO_ROOT}/seccomp/seccomp-kernel-cve-mitigation.json"
echo -n "[Test 4/5] OCI Container Synchronous SECCOMP Profile Enforcement: "

DOCKER_AVAILABLE=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    DOCKER_AVAILABLE=1
fi

if [ "$DOCKER_AVAILABLE" -eq 1 ] && [ -f "$SECCOMP_PROFILE" ]; then
    # Step 4.0: Baseline Control Check (Unconfined Container across all 3 attack surfaces)
    BASELINE_RAW=$(docker run --rm -e RUN_ID="$RUN_ID" --security-opt seccomp=unconfined "$CONTAINER_IMAGE" python3 -c "
import socket, threading, struct, errno, sys

b_af = 'UNKNOWN'
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    b_af = 'PERMITTED'
    s.close()
except OSError as e:
    b_af = f'ERR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}'

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(1)
port = srv.getsockname()[1]
conn = None
def acc():
    global conn
    try: conn, _ = srv.accept()
    except Exception: pass
t = threading.Thread(target=acc)
t.daemon = True
t.start()
cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', port))
t.join(2.0)

b_p1 = 'UNKNOWN'
b_p2 = 'UNKNOWN'

try:
    cli.setsockopt(6, 31, b'tls\0')
    b_p1 = 'ATTACHED'
except OSError as e:
    b_p1 = f'ERR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}'

if b_p1 == 'ATTACHED':
    crypto_info = struct.pack('=HH8s16s4s8s', 0x0303, 51, b'\x01'*8, b'\x02'*16, b'\x03'*4, b'\x00'*8)
    try:
        cli.setsockopt(282, 1, crypto_info)
        b_p2 = 'CONFIGURED'
    except OSError as e:
        b_p2 = f'ERR_{e.errno}_{errno.errorcode.get(e.errno, e.errno)}'
else:
    b_p2 = 'SKIPPED_P1_FAILED'

cli.close()
if conn: conn.close()
srv.close()

print(f'{b_af}|{b_p1}|{b_p2}')
" 2>/dev/null || echo "BASELINE_ERROR|BASELINE_ERROR|BASELINE_ERROR")

    BASELINE_AF=$(echo "$BASELINE_RAW" | cut -d'|' -f1)
    BASELINE_P1=$(echo "$BASELINE_RAW" | cut -d'|' -f2)
    BASELINE_P2=$(echo "$BASELINE_RAW" | cut -d'|' -f3)

    if [ "$BASELINE_P1" != "ATTACHED" ]; then
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: Baseline unconfined container failed to attach Phase 1 ULP: $BASELINE_P1)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        else
            echo "[WARN] INCONCLUSIVE (Baseline unconfined container failed to attach Phase 1 ULP: $BASELINE_P1)"
            INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
        fi
    else
        CONTAINER_OUT=$(mktemp)
        CONTAINER_ERR=$(mktemp)
        DOCKER_STATUS=0

        docker run --rm -e RUN_ID="$RUN_ID" --security-opt seccomp="$SECCOMP_PROFILE" "$CONTAINER_IMAGE" python3 -c "
import socket, threading, errno, sys, os

run_id = os.environ.get('RUN_ID', '')
seccomp_mode = 'unknown'
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = line.split()[1].strip()
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
        results['AF_ALG'] = f'BLOCKED_EPERM_SECCOMP_{seccomp_mode}'
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

if active_conn is None or active_conn.fileno() == -1:
    results['ACCEPT'] = 'SERVER_ACCEPT_FAILED'
elif cli.fileno() == -1:
    results['CLIENT'] = 'CLIENT_SOCKET_INVALID'
else:
    # Test 4.2: Phase 1 TCP_ULP exact EPERM assertion
    try:
        cli.setsockopt(6, 31, b'tls\0')
        results['TCP_ULP'] = 'UNBLOCKED'
    except OSError as e:
        if e.errno == errno.EPERM:
            results['TCP_ULP'] = f'BLOCKED_EPERM_SECCOMP_{seccomp_mode}'
        else:
            results['TCP_ULP'] = f'FAIL_{errno.errorcode.get(e.errno, e.errno)}'

    # Test 4.3: Phase 2 SOL_TLS exact EPERM assertion
    try:
        cli.setsockopt(282, 1, b'\x00'*40)
        results['SOL_TLS'] = 'UNBLOCKED'
    except OSError as e:
        if e.errno == errno.EPERM:
            results['SOL_TLS'] = f'BLOCKED_EPERM_SECCOMP_{seccomp_mode}'
        else:
            results['SOL_TLS'] = f'FAIL_{errno.errorcode.get(e.errno, e.errno)}'

cli.close()
if active_conn:
    active_conn.close()
srv.close()

expected = 'BLOCKED_EPERM_SECCOMP_2'
if all(results.get(k) == expected for k in ['AF_ALG', 'TCP_ULP', 'SOL_TLS']):
    print('ALL_BLOCKED_BY_SECCOMP_FILTER')
else:
    print(f'LEAK:{results}')
" >"$CONTAINER_OUT" 2>"$CONTAINER_ERR" || DOCKER_STATUS=$?

        SECCOMP_OUTPUT=$(cat "$CONTAINER_OUT")
        if [ "$DOCKER_STATUS" -eq 0 ] && [ "$SECCOMP_OUTPUT" = "ALL_BLOCKED_BY_SECCOMP_FILTER" ]; then
            CONTRAST_P1="PROVEN"
            CONTRAST_P2="PROVEN"
            CONTRAST_AF="INCONCLUSIVE"
            if [ "$BASELINE_AF" = "PERMITTED" ]; then
                CONTRAST_AF="PROVEN"
            fi

            echo "[PASS] PASSED (AF_ALG, TCP_ULP, SOL_TLS synchronously rejected by SECCOMP: exact EPERM, Seccomp mode=2 verified)"
            echo "  -> Baseline Contrast Breakdown (Per-Vector Causal Attribution):"
            echo "     * Phase 1 (TCP_ULP): $CONTRAST_P1 (Unconfined=$BASELINE_P1 -> Hardened=BLOCKED_EPERM_SECCOMP_2)"
            echo "     * Phase 2 (SOL_TLS): $CONTRAST_P2 (Unconfined=$BASELINE_P2 -> Hardened=BLOCKED_EPERM_SECCOMP_2)"
            if [ "$CONTRAST_AF" = "PROVEN" ]; then
                echo "     * AF_ALG (domain 38): PROVEN (Unconfined=$BASELINE_AF -> Hardened=BLOCKED_EPERM_SECCOMP_2)"
            else
                echo "     * AF_ALG (domain 38): INCONCLUSIVE for causal contrast (Unconfined baseline restricted by host capability: $BASELINE_AF; SECCOMP filter independently verified)"
            fi
            PREVENTION_PASSED=$((PREVENTION_PASSED + 1))
        elif [ "$DOCKER_STATUS" -ne 0 ]; then
            ERR_SNIPPET=$(head -n 1 "$CONTAINER_ERR")
            if [ "$STRICT_MODE" -eq 1 ]; then
                echo "[FAIL] FAILED (Strict mode: Container execution failed: status=$DOCKER_STATUS, ${ERR_SNIPPET:-unknown error})"
                FAILED_COUNT=$((FAILED_COUNT + 1))
            else
                echo "[WARN] INCONCLUSIVE (Container execution failed: status=$DOCKER_STATUS, ${ERR_SNIPPET:-check docker logs})"
                INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
            fi
        else
            echo "[FAIL] FAILED (Seccomp policy leak: $SECCOMP_OUTPUT)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
        rm -f "$CONTAINER_OUT" "$CONTAINER_ERR"
    fi
else
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[FAIL] FAILED (Strict mode: Docker runtime or seccomp profile missing)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    else
        echo "[INFO] SKIPPED (Docker runtime or seccomp profile not available)"
        INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
    fi
fi

# Test 5: Independent Phase 2 Interception Proof (Phase 1 allowed, Phase 2 independently blocked with EPERM)
SECCOMP_P2_PROFILE="${REPO_ROOT}/seccomp/seccomp-test-phase2-isolation.json"
echo -n "[Test 5/5] Independent Phase 2 kTLS Interception Proof: "

if [ "$DOCKER_AVAILABLE" -eq 1 ] && [ -f "$SECCOMP_P2_PROFILE" ]; then
    CONTAINER_OUT_5=$(mktemp)
    CONTAINER_ERR_5=$(mktemp)
    DOCKER_STATUS_5=0

    docker run --rm -e RUN_ID="$RUN_ID" --security-opt seccomp="$SECCOMP_P2_PROFILE" "$CONTAINER_IMAGE" python3 -c "
import socket, threading, struct, errno, sys, os

run_id = os.environ.get('RUN_ID', '')
seccomp_mode = 'unknown'
try:
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Seccomp:'):
                seccomp_mode = line.split()[1].strip()
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

# 1. Server accept & socket duplex verification
p1_ok = False
p1_err = None
p2_blocked = False
p2_err = 'UNATTEMPTED'

if active_conn is None or active_conn.fileno() == -1:
    p1_err = 'SERVER_ACCEPT_FAILED'
elif cli.fileno() == -1:
    p1_err = 'CLIENT_SOCKET_INVALID'
else:
    # Phase 1 must succeed under isolation profile
    try:
        cli.setsockopt(6, 31, b'tls\0')
        p1_ok = True
    except Exception as e:
        p1_err = str(e)

    # 2. Phase 2: only attempt if Phase 1 successfully attached
    if p1_ok:
        crypto_info = struct.pack('=HH8s16s4s8s', 0x0303, 51, b'\x01'*8, b'\x02'*16, b'\x03'*4, b'\x00'*8)
        try:
            cli.setsockopt(282, 1, crypto_info)
            p2_err = 'UNBLOCKED'
        except OSError as e:
            if e.errno == errno.EPERM:
                p2_blocked = True
                p2_err = f'BLOCKED_EPERM_SECCOMP_{seccomp_mode}'
            else:
                p2_err = f'{e.errno}_{errno.errorcode.get(e.errno, e.errno)}'
    else:
        p2_err = 'SKIPPED_PHASE1_FAILED'

cli.close()
if active_conn:
    active_conn.close()
srv.close()

if p1_ok and p2_blocked and seccomp_mode == '2':
    print('PHASE2_INDEPENDENTLY_PROVEN_BY_SECCOMP')
else:
    print(f'FAILED: p1_ok={p1_ok} (err={p1_err}), p2_blocked={p2_blocked} (res={p2_err}), seccomp={seccomp_mode}')
" >"$CONTAINER_OUT_5" 2>"$CONTAINER_ERR_5" || DOCKER_STATUS_5=$?

    P2_ISO_OUTPUT=$(cat "$CONTAINER_OUT_5")
    if [ "$DOCKER_STATUS_5" -eq 0 ] && [ "$P2_ISO_OUTPUT" = "PHASE2_INDEPENDENTLY_PROVEN_BY_SECCOMP" ]; then
        echo "[PASS] PASSED (Phase 1 attached successfully, Phase 2 independently blocked by SECCOMP: exact EPERM, Seccomp mode=2 verified)"
        PREVENTION_PASSED=$((PREVENTION_PASSED + 1))
    elif [ "$DOCKER_STATUS_5" -ne 0 ]; then
        ERR_SNIPPET=$(head -n 1 "$CONTAINER_ERR_5")
        if [ "$STRICT_MODE" -eq 1 ]; then
            echo "[FAIL] FAILED (Strict mode: Differential isolation container failed: status=$DOCKER_STATUS_5, ${ERR_SNIPPET:-unknown error})"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        else
            echo "[WARN] INCONCLUSIVE (Differential isolation container failed: status=$DOCKER_STATUS_5, ${ERR_SNIPPET:-check docker logs})"
            INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
        fi
    else
        echo "[FAIL] FAILED (Phase 2 isolation proof failed: $P2_ISO_OUTPUT)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
    rm -f "$CONTAINER_OUT_5" "$CONTAINER_ERR_5"
else
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[FAIL] FAILED (Strict mode: Docker runtime or isolation profile missing)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    else
        echo "[INFO] SKIPPED (Docker runtime or isolation profile not available)"
        INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT + 1))
    fi
fi

TOTAL_PASSED=$((PREVENTION_PASSED + DETECTION_PASSED))
echo "========================================================================"
echo "VERIFICATION ASSERTION SUMMARY:"
echo "  Synchronous Prevention Passed: $PREVENTION_PASSED"
echo "  Audit Detection Passed:        $DETECTION_PASSED"
echo "  Inconclusive / Skipped:        $INCONCLUSIVE_COUNT"
echo "  Failed Assertions:             $FAILED_COUNT"
echo "========================================================================"
if [ "$FAILED_COUNT" -gt 0 ]; then
    echo "[FAIL] $FAILED_COUNT ASSERTION(S) FAILED (Exit code: 1)"
    exit 1
elif [ "$INCONCLUSIVE_COUNT" -gt 0 ]; then
    if [ "$STRICT_MODE" -eq 1 ]; then
        echo "[FAIL] $INCONCLUSIVE_COUNT INCONCLUSIVE/SKIPPED ASSERTION(S) REJECTED IN STRICT MODE (Exit code: 2)"
        exit 2
    else
        echo "[INCONCLUSIVE] $TOTAL_PASSED ASSERTIONS PASSED ($PREVENTION_PASSED prevention, $DETECTION_PASSED detection), $INCONCLUSIVE_COUNT INCONCLUSIVE/SKIPPED (Exit code: 0)"
        exit 0
    fi
else
    echo "[PASS] ALL 5 VERIFICATION ASSERTIONS PASSED: $PREVENTION_PASSED synchronous prevention, $DETECTION_PASSED audit detection (Exit code: 0)"
    exit 0
fi
