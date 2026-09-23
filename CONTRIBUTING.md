# Contributing to Linux Kernel Zero-Day Defense

Thank you for your interest in contributing to this defense-in-depth Linux kernel compensating controls framework!

---

## Core Operational Principles

This framework addresses live, in-the-wild zero-day vulnerabilities across production Kubernetes clusters and bare-metal nodes. All contributions must respect these engineering invariants:

1. **Zero-Downtime Requirement:**
   - Mitigations must apply to running systems **without requiring host reboots**.
   - Compensating controls must not disrupt unrelated production workloads or break container runtime socket bindings (containerd/CRI).

2. **Layered Defense-in-Depth:**
   - Controls should be categorized cleanly by defense taxonomy:
     - **Prevention:** Kernel module disassembly & loader overrides (`/etc/modprobe.d/`).
     - **Runtime Enforcement:** Inline LSM, SECCOMP profiles (`seccomp-block-af-alg.json`), or eBPF filter programs.
     - **Containment:** Container user namespaces (`hostUsers: false`) or cgroup isolation.

3. **Verification Suite Gate:**
   - Any added or modified control must pass the automated verification test harness:
     ```bash
     sudo bash scripts/verify-mitigation.sh
     ```
     The script must exit cleanly with code `0`.

---

## Development & Verification Workflow

1. **Fork and Clone:**
   ```bash
   git clone https://github.com/<your-username>/linux-kernel-zero-day-mitigation-zero-downtime-kernel-defense-.git
   cd linux-kernel-zero-day-mitigation-zero-downtime-kernel-defense-
   ```

2. **Create a Feature Branch:**
   ```bash
   git checkout -b feature/new-cve-mitigation
   ```

3. **Test Mitigations Locally:**
   - Run verification in an unprivileged container or staging VM:
     ```bash
     bash scripts/verify-mitigation.sh
     ```

4. **Verify Telemetry Archival:**
   ```bash
   python3 scripts/archive_traffic.py
   ```

---

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

* `feat:` A new compensating control, eBPF rule, or SECCOMP profile.
* `fix:` A bug fix in shell scripts, path resolution, or CRI compatibility.
* `docs:` Threat model updates, CVE descriptions, or postmortem expansions.
* `test:` Additions to `verify-mitigation.sh` or CI test runners.
* `chore:` GitHub Actions, badge telemetry, or repository hygiene.

---

## Submitting a Pull Request

1. Ensure your PR adheres to the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
2. Specify the target kernel versions (e.g. Linux 6.8+, 7.0+) and container runtime tested.
3. Maintainers will review and test the proposed control in a multi-node staging environment.
