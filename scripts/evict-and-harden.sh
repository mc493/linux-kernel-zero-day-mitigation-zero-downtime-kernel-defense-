#!/usr/bin/env bash
# ==============================================================================
# evict-and-harden.sh
# Zero-Downtime Linux Kernel Module Eviction & Loader Sealing (CVE-2026-53266)
# ==============================================================================
set -euo pipefail

echo "🛡️ [1/3] Evicting active ebtables modules from kernel RAM..."
for mod in ebtable_nat ebtable_filter ebtable_broute ebt_snat ebt_dnat ebt_arpreply ebtables; do
    if lsmod | grep -q -E "^${mod} "; then
        echo "  - Unloading active module: ${mod}"
        sudo modprobe -r "${mod}" 2>/dev/null || echo "    ⚠️ Could not unload ${mod} (in use by active bridge or child dependency)"
    fi
done

echo "🛡️ [2/3] Sealing kernel loader via /etc/modprobe.d/blacklist-ebtables.conf..."
sudo tee /etc/modprobe.d/blacklist-ebtables.conf > /dev/null << 'EOF'
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

echo "🛡️ [3/3] Verifying kernel state..."
if lsmod | grep -q -E "^ebt"; then
    echo "⚠️ Warning: Some ebtables modules remain resident in memory:"
    lsmod | grep -E "^ebt"
    echo "A reboot will be required to completely clear active in-use modules."
else
    echo "✅ Success: 0 ebtables modules resident in kernel memory."
fi

# Verify loader override
sudo modprobe ebt_snat 2>/dev/null || true
if lsmod | grep -q -E "^ebt"; then
    echo "❌ Error: Module loader override failed!"
    exit 1
else
    echo "✅ Success: Loader override verified. 'modprobe ebt_snat' loaded 0 modules."
fi
