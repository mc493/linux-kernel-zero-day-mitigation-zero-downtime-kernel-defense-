#!/usr/bin/env bash
# ==============================================================================
# verify-mitigation.sh
# Automated Zero-Day Compensating Control Verification Probe
# ==============================================================================
set -euo pipefail

echo "🔍 Running Sovereign Kernel CVE Defense Verification Suite..."

# Test 1: ebtables module blockade
echo -n "[Test 1] ebtables module loader blockade: "
sudo modprobe ebt_snat 2>/dev/null || true
if lsmod | grep -q ebt; then
    echo "❌ FAILED (Module loaded into RAM)"
else
    echo "✅ PASSED (0 modules in RAM)"
fi

# Test 2: Python AF_ALG socket probe
echo -n "[Test 2] AF_ALG (domain 38) socket probe: "
python3 -c "
import socket
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    print('⚠️ Triggered socket(38). Check Falco/SIEM logs for alert.')
except Exception as e:
    print('Blocked or unavailable:', e)
"

# Test 3: kTLS setsockopt probe
echo -n "[Test 3] kTLS TCP_ULP setsockopt probe: "
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    # Attempt to attach TCP_ULP 'tls' (SOL_TCP=6, TCP_ULP=31)
    s.setsockopt(6, 31, b'tls\0')
    print('⚠️ Attached TCP_ULP tls. Check Falco/SIEM logs for alert.')
except Exception as e:
    print('Expected result / blocked:', e)
finally:
    s.close()
"

echo "🎉 Verification probe complete."
