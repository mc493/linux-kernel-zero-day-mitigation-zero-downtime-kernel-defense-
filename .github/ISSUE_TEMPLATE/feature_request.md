---
name: Feature request / New CVE Defense
about: Propose a new compensating control for an emerging Linux kernel CVE
title: '[FEAT] '
labels: enhancement
assignees: ''

---

**Target Vulnerability & Subsystem:**
- CVE ID: (e.g. `CVE-YYYY-XXXXX`)
- Affected Subsystem: (e.g. Netfilter, eBPF verifier, io_uring, kTLS)
- Severity / Vector: (e.g. CVSS score, Local Privilege Escalation, Remote Code Execution)

**Proposed Compensating Control:**
A clear description of how to mitigate the flaw without host reboots (e.g. module blacklisting, SECCOMP filter, sysctl parameter, or eBPF probe).

**Compatibility & Production Safety:**
- Does this control break standard unprivileged container workloads?
- How is the mitigation verified?
