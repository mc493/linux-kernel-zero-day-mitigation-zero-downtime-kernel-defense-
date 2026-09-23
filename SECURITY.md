# Security Policy

## Scope of Compensating Controls

This repository contains defense-in-depth compensating controls, eBPF rules, and SECCOMP security profiles designed to mitigate in-the-wild Linux kernel vulnerabilities (specifically CVE-2025-39964, CVE-2026-53266, and CVE-2025-39682) during the vendor upstream patch gap.

While these controls are designed to minimize risk on live production infrastructure without reboots, no compensating control is a complete replacement for vendor-signed upstream kernel upgrades.

---

## Supported Releases & Maintenance

| Branch / Release | Supported          |
| :--------------- | :----------------- |
| `main`           | Yes |
| Historical tags  | No                |

---

## Reporting Security Vulnerabilities

If you discover a flaw, bypass, privilege escalation loophole, or unintended denial-of-service vector within the compensating controls provided in this repository:

1. **Do NOT open a public GitHub issue.**
2. Report the vulnerability privately via **GitHub Private Vulnerability Reporting** (under the repository's Security tab).
3. Alternatively, notify the maintainers directly via email: `nemospecialis@gmail.com`.

### What to Provide:
* Detailed description of the bypass or failure mode.
* Affected kernel versions and container runtimes (e.g. Ubuntu 24.04 HWE, containerd v2.2.4).
* A minimal reproduction script or shell transcript showing how the control was circumvented.
* Suggested remediations (e.g. improved SECCOMP filter, additional module blacklists, or tighter eBPF syscall probes).

### Response SLA:
* **Acknowledgment:** Within **48 hours**.
* **Triage & Assessment:** Within **5 business days**.
* **Remediation & Attestation:** Once validated, a patched compensating control will be released with appropriate security advisory credit.
