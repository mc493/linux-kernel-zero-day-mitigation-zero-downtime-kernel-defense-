---
name: Bug report / Mitigation Bypass
about: Report a failure in a compensating control, script error, or bypass
title: '[BUG] '
labels: bug
assignees: ''

---

**Describe the Bug**
A clear and concise description of the failure in module eviction, eBPF telemetry, SECCOMP profile, or Kubernetes manifest.

**Host Environment Details:**
 - Host Kernel: `uname -r` (e.g. `6.8.0-40-generic`, `7.0.0-28-generic`)
 - Linux Distribution: [e.g. Ubuntu 22.04 / 24.04 LTS, Debian 12, RHEL 9]
 - Container Runtime: [e.g. containerd v1.7.x, v2.2.4]
 - Kubernetes / K3s Version (if applicable): [e.g. v1.30.2]

**Reproduction Steps**
Steps to reproduce the failure:
1. Run `sudo bash scripts/evict-and-harden.sh`
2. Run test workload or `verify-mitigation.sh`
3. See error or unexpected behavior

**Actual Terminal Output**
```text
Paste logs or terminal error here
```

**Impact on Running Workloads**
Did this issue cause unexpected workload eviction, denial of service, or socket failure?
