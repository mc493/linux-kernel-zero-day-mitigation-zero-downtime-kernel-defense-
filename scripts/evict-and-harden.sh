#!/usr/bin/env bash
# ==============================================================================
# evict-and-harden.sh
# Zero-Downtime Linux Kernel Module Eviction & Loader Sealing (CVE-2026-53266)
# ==============================================================================
set -euo pipefail

# Detect privilege elevator
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Error: Root privileges required, but sudo is not installed."
        exit 1
    fi
fi

# Target configuration directory (Volatile /run/modprobe.d on read-only systems)
TARGET_DIR="/etc/modprobe.d"
if grep -q " / .* ro," /proc/mounts 2>/dev/null || [ ! -w /etc/modprobe.d ]; then
    TARGET_DIR="/run/modprobe.d"
    echo "Notice: Read-only root filesystem detected. Applying volatile configuration via /run/modprobe.d/..."
fi

echo "[1/3] Evicting active ebtables modules from kernel RAM..."
for mod in ebtable_nat ebtable_filter ebtable_broute ebt_snat ebt_dnat ebt_arpreply ebtables; do
    if lsmod | grep -q -E "^${mod} "; then
        echo "  - Unloading active module: ${mod}"
        $SUDO modprobe -r "${mod}" 2>/dev/null || echo "    Warning: Could not unload ${mod} (in use by active bridge or child dependency)"
    fi
done

echo "[2/3] Sealing kernel loader via ${TARGET_DIR}/blacklist-ebtables.conf..."
$SUDO mkdir -p "$TARGET_DIR"
$SUDO tee "$TARGET_DIR/blacklist-ebtables.conf" > /dev/null << 'EOF'
# Mitigation for CVE-2026-53266: Netfilter ARP table corruption
# Force all module load requests to exit successfully with 0 without loading code into ring-0
install ebtables /bin/true
install ebtable_nat /bin/true
install ebtable_broute /bin/true
install ebtable_filter /bin/true
install ebt_snat /bin/true
install ebt_dnat /bin/true
install ebt_arpreply /bin/true

blacklist ebtables
blacklist ebtable_nat
blacklist ebt_snat
blacklist ebt_arpreply
EOF
$SUDO chmod 644 "$TARGET_DIR/blacklist-ebtables.conf"

# Mirror to /etc/modprobe.d only if writeable
if [ "$TARGET_DIR" = "/run/modprobe.d" ] && [ -w /etc/modprobe.d ]; then
    $SUDO cp /run/modprobe.d/blacklist-ebtables.conf /etc/modprobe.d/blacklist-ebtables.conf 2>/dev/null || true
fi

ALLOW_DEFERRED=false
for arg in "$@"; do
    if [ "$arg" = "--allow-deferred-reboot" ]; then
        ALLOW_DEFERRED=true
    fi
done

echo "[3/3] Verifying kernel state..."
if lsmod | grep -q -E "^ebt"; then
    echo "ERROR: Some ebtables modules remain resident in memory:" >&2
    lsmod | grep -E "^ebt" >&2
    if [ "$ALLOW_DEFERRED" = true ]; then
        echo "WARNING: Continuing due to --allow-deferred-reboot flag. Full mitigation requires a host reboot." >&2
    else
        echo "FAIL-CLOSED: Vulnerable module eviction failed! Code is still active in kernel RAM." >&2
        echo "To allow staged loader sealing prior to a scheduled reboot, rerun with --allow-deferred-reboot." >&2
        exit 1
    fi
else
    echo "Success: 0 ebtables modules resident in kernel memory."
fi

# Verify loader override: install override /bin/true must succeed with exit code 0
if ! $SUDO modprobe ebt_snat 2>/dev/null; then
    echo "Error: modprobe invocation failed unexpectedly."
    exit 1
fi
if lsmod | grep -q -E "^ebt"; then
    echo "Error: Module loader override failed! Module resident in memory:"
    lsmod | grep -E "^ebt"
    exit 1
else
    echo "Success: Loader override verified. 'modprobe ebt_snat' executed /bin/true and resident module count is 0."
fi
