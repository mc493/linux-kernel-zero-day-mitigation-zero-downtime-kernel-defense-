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
        echo "❌ Error: Root privileges required, but sudo is not installed."
        exit 1
    fi
fi

# Detect Immutable OS (Read-Only root filesystem)
IS_RO=false
if grep -q " / .* ro," /proc/mounts 2>/dev/null; then
    IS_RO=true
    echo "ℹ️  Detected read-only root filesystem. Temporarily remounting rw..."
    $SUDO mount -o remount,rw /
fi

echo "🛡️ [1/3] Evicting active ebtables modules from kernel RAM..."
for mod in ebtable_nat ebtable_filter ebtable_broute ebt_snat ebt_dnat ebt_arpreply ebtables; do
    if lsmod | grep -q -E "^${mod} "; then
        echo "  - Unloading active module: ${mod}"
        $SUDO modprobe -r "${mod}" 2>/dev/null || echo "    ⚠️ Could not unload ${mod} (in use by active bridge or child dependency)"
    fi
done

echo "🛡️ [2/3] Sealing kernel loader via /etc/modprobe.d/blacklist-ebtables.conf..."
$SUDO tee /etc/modprobe.d/blacklist-ebtables.conf > /dev/null << 'EOF'
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

# Re-lock filesystem if previously read-only
if [ "$IS_RO" = true ]; then
    sync
    $SUDO mount -o remount,ro /
    echo "  - Re-locked root filesystem in read-only mode."
fi

echo "🛡️ [3/3] Verifying kernel state..."
if lsmod | grep -q -E "^ebt"; then
    echo "⚠️ Warning: Some ebtables modules remain resident in memory:"
    lsmod | grep -E "^ebt"
    echo "A reboot will be required to completely clear active in-use modules."
else
    echo "✅ Success: 0 ebtables modules resident in kernel memory."
fi

# Verify loader override
$SUDO modprobe ebt_snat 2>/dev/null || true
if lsmod | grep -q -E "^ebt"; then
    echo "❌ Error: Module loader override failed!"
    exit 1
else
    echo "✅ Success: Loader override verified. 'modprobe ebt_snat' loaded 0 modules."
fi
