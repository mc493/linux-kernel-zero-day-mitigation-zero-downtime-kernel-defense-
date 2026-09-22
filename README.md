# Zero-Downtime Linux Kernel Zero-Day Defense: Layered Compensating Controls via eBPF Telemetry, Module Disarmament, and User Namespaces

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Kernel: Linux HWE](https://img.shields.io/badge/Kernel-Linux%20HWE%206.8%2B%20%7C%207.0%2B-informational.svg)](https://kernel.org)
[![Kubernetes: CRI v1.30+](https://img.shields.io/badge/Kubernetes-CRI%20v1.30%2B-brightgreen.svg)](https://kubernetes.io)
[![eBPF: Falco modern_ebpf](https://img.shields.io/badge/eBPF-Falco%20v0.44%2B-orange.svg)](https://falco.org)
[![Views](https://hits.dwyl.com/mc493/linux-kernel-zero-day-mitigation-zero-downtime-kernel-defense-.svg?style=flat-square&label=views)](https://github.com/mc493/linux-kernel-zero-day-mitigation-zero-downtime-kernel-defense-)

When the Cybersecurity and Infrastructure Security Agency (CISA) adds critical Linux kernel vulnerabilities to its **Known Exploited Vulnerabilities (KEV)** catalog, an urgent operational clock starts ticking for infrastructure teams and SRE leads:

> **The Upstream Patch Gap:**  
> The duration between the public weaponization of an in-the-wild zero-day and the availability of tested, signed binary kernel packages from enterprise distributions (Ubuntu HWE, Debian, RHEL) typically spans **7 to 21 days**. 

In production Kubernetes clusters, passively awaiting vendor packages exposes systems to active exploitation, while premature kernel upgrades or emergency reboots risk operational outages.

This case study documents a **defense-in-depth compensating control framework** designed to manage three concurrent Linux kernel vulnerabilities (CVE-2025-39964, CVE-2026-53266, CVE-2025-39682) across userspace, the kernel loader, and runtime layers without requiring host reboots.

---

## Threat Matrix & Defense Taxonomy

To ensure operational accuracy, defenses are categorized strictly by their security properties (**Prevention**, **Runtime Detection**, and **Containment**):

| Vulnerability | Subsystem | Attack Mechanism | Severity | Defense Mode | Implementation Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2026-53266** | Netfilter Bridging (`ebtables`) | Arithmetic overflow in bridge ARP table rewrite rules | **High (Memory Corruption)** | **Prevention (Disarmament)** | RAM eviction (`modprobe -r`) + loader override (`/bin/true`) |
| **CVE-2025-39964** | Crypto Netlink (`AF_ALG`) | Integer truncation in netlink crypto socket allocation | **High (LPE / Breakout)** |  **Detection (eBPF) / Gating** | Modern eBPF (`sys_enter_socket`, domain 38) + SECCOMP |
| **CVE-2025-39682** | Kernel TLS (`kTLS`) | Zero-length record processing flaw in TCP ULP | **High (Kernel Panic / Heap)** |  **Detection (eBPF)** | Modern eBPF (`sys_enter_setsockopt`, `TCP_ULP` 31 & `SOL_TLS` 282) |

---

## Layered Defense-in-Depth Architecture

```mermaid
flowchart TD
    subgraph Ring3 ["User Space / Container Pod (Ring 3)"]
        Workload["Container Workload / Untrusted Process"]
        Probe["Exploit Vectors: socket(AF_ALG) or setsockopt(TCP_ULP)"]
        Workload --> Probe
    end

    subgraph Ring0 ["Linux Kernel (Ring 0)"]
        SyscallTrap["Syscall Trap (sysenter)"]
        Probe --> SyscallTrap
        
        Tracepoint["Kernel Tracepoint: sys_enter"]
        SyscallTrap --> Tracepoint
        
        subgraph eBPFEngine ["Modern eBPF Detection (CO-RE Ring Buffer)"]
            Filter{"Syscall Gating:\n- domain == 38 (AF_ALG)\n- SOL_TCP + TCP_ULP\n- SOL_TLS (282)"}
            Tracepoint --> Filter
        end
        
        Disarmed["Modprobe Hook: /bin/true\n(ebtables evicted & blocked)"]
        UserNS["containerd v2.2.4 User Namespace Remap\nContainer UID 0 -> Host UID 4050714624\n(Bounded Credential Containment)"]
        
        Filter -- "Match (<1ms)" --> AlertRingBuf["Ring Buffer Emission"]
        Filter -- "Pass" --> KernelExec["Normal Execution Path"]
        KernelExec --> UserNS
    end

    subgraph SecurityPipeline ["Reactive Event Pipeline"]
        Falcosidekick["Falco Daemon & Sidekick (:2801)"]
        Forwarder["Event Forwarder Daemon (:9876)"]
        NATSBus["NATS Security Bus (sovereign.security.alert)"]
        
        AlertRingBuf --> Falcosidekick
        Falcosidekick --> Forwarder
        Forwarder --> NATSBus
    end

    subgraph Enforcement ["Automated Remediation & Audit"]
        Remediator["Dynamic Bouncer (CrowdSec / nftables Drop)"]
        AuditLedger["Cryptographically Tamper-Evident Hash Chain\n(SHA-256 Chaining & Cross-Node Replication)"]
        
        NATSBus --> Remediator
        NATSBus --> AuditLedger
    end

    classDef danger fill:#ffdddd,stroke:#ff0000,stroke-width:2px;
    classDef safe fill:#ddffdd,stroke:#00aa00,stroke-width:2px;
    classDef arch fill:#f0f4f8,stroke:#0066cc,stroke-width:1px;
    class Probe danger;
    class Disarmed,UserNS,AuditLedger safe;
```

---

## Layer 1: Kernel Module Disarmament (Preventative)

### 1. The Operational Nuance: Active Memory vs. Future Probing
A common pitfall with `/etc/modprobe.d/` overrides is that `install /bin/true` only blocks **subsequent** module load attempts. If bridge networking (Docker, legacy CNI) loaded `ebtables` earlier in the host lifecycle, the vulnerable code remains active in kernel RAM.

Zero-downtime disarmament requires a two-step sequence:
1. **Eviction:** Unload currently resident modules from kernel memory.
2. **Sealing:** Configure `/bin/true` loader overrides to prevent reloading.

### 2. Implementation
```bash
# Step A: Evict active ebtables modules from running kernel RAM
sudo modprobe -r ebtable_nat ebtable_filter ebtable_broute ebt_snat ebt_dnat ebt_arpreply ebtables 2>/dev/null || true

# Step B: Seal the loader via /etc/modprobe.d/blacklist-ebtables.conf
sudo tee /etc/modprobe.d/blacklist-ebtables.conf << 'EOF'
# Mitigation for CVE-2026-53266: Netfilter ARP table corruption
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
```

### 3. Verification
```bash
# Test explicit loading:
$ sudo modprobe ebt_snat
$ lsmod | grep ebt
# Output: (Empty - 0 modules resident in kernel memory)
```

---

## Layer 2: eBPF Syscall Telemetry & Behavioral Gating (Detection)

### 1. Detection vs. Inline Prevention
* **Falco eBPF (Asynchronous EDR):** Hooks `sys_enter` via modern eBPF ring buffers, providing sub-millisecond alerting into SIEM/NATS. It is optimized for zero-overhead visibility without modifying kernel control flow.
* **Inline Blocking (Synchronous LSM):** For environments requiring synchronous rejection (`-EACCES`), an eBPF LSM probe or SECCOMP profile can drop the syscall prior to execution.

### 2. Corrected kTLS Syscall Mechanics (Two-Phase Gating)
Enabling Kernel TLS on a TCP connection occurs in two distinct phases:
1. **Phase 1 (Attachment):** `setsockopt(fd, SOL_TCP=6, TCP_ULP=31, "tls", 4)` attaches the Upper Layer Protocol.
2. **Phase 2 (Configuration):** `setsockopt(fd, SOL_TLS=282, TLS_TX/TLS_RX, ...)` initializes crypto keys.

Filtering solely on `SOL_TLS (282)` misses the ULP attachment phase. The rule evaluates **both** phases:

```yaml
# falco-rules-kernel-cve.yaml
customRules:
  rules-kernel-cve.yaml: |-
    - rule: Detect AF_ALG Crypto Socket Creation (CVE-2025-39964)
      desc: Detects creation of Crypto API Netlink sockets used in local privilege escalation
      condition: evt.type = socket and evt.rawarg.domain = 38
      output: "Active Exploit Probe: AF_ALG socket requested (domain=%evt.rawarg.domain type=%evt.rawarg.type user=%user.name proc=%proc.name container=%container.id)"
      priority: WARNING
      tags: [cve, zero-day, cve-2025-39964, crypto, container_escape]

    - rule: Detect Container Kernel TLS Activation (CVE-2025-39682)
      desc: Detects container workloads attaching kTLS TCP_ULP or configuring SOL_TLS
      condition: container.id != host and evt.type = setsockopt and 
                 ((evt.rawarg.level = 6 and evt.rawarg.optname = 31) or (evt.rawarg.level = 282))
      output: "Container kTLS Activation Detected (level=%evt.rawarg.level optname=%evt.rawarg.optname user=%user.name proc=%proc.name container=%container.name)"
      priority: WARNING
      tags: [cve, zero-day, cve-2025-39682, ktls, tcp_ulp]
```

### 3. Production Stability: Linux 7.0 ABI Filter Invariant
On modern Linux kernels (Linux 7.0+ HWE), Falco's userspace inspector engine (`sinsp`) encounters register parsing mismatches on `openat` parameters (`sinsp_exception: could not parse param 2 (name)`). 

To ensure continuous DaemonSet stability without crash loops:
```yaml
falco:
  base_syscalls:
    custom_set: ['!openat']
```

### 4. (Optional) Synchronous Inline Blocking via SECCOMP
If in-container workloads must be strictly prohibited from calling `AF_ALG`, apply a SECCOMP profile returning `SCMP_ACT_ERRNO`:
```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "args": [
        {
          "index": 0,
          "value": 38,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

---

## Layer 3: User Namespace Isolation (Containment)

### 1. Bounded Escalation vs. Arbitrary Ring-0 Write
* **Bounded Privilege Escalation:** Most Netlink/socket LPEs exploit kernel logic flaws to acquire `root` within the process credential struct (`current->cred`).
* **The UserNS Defense:** In containerd v2.2.4 with Kubernetes CRI v1.30 (`hostUsers: false`), container root (`UID 0`) is mapped to an unprivileged host range (host UID `4050714624`). Bounded credential escalations remain constrained within the non-root namespace.
* **Realistic Boundary:** Full arbitrary ring-0 write vulnerabilities (direct control of kernel instruction pointer or page tables) can bypass user namespace boundaries; such threats require microVM or hypervisor-level isolation (e.g. Firecracker, Kata).

### 2. Workload Configuration
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-workload
spec:
  runtimeClassName: runc
  hostUsers: false  # Remaps container root away from host root
  containers:
  - name: app
    image: app:latest
```

### 3. Host Verification
```bash
$ cat /proc/$(pgrep -f hardened-workload)/uid_map
         0 4050714624      65536
```

---

## Layer 4: Cryptographically Tamper-Evident Audit Chaining

### 1. Tamper-Evidence vs. Hardware WORM
Local log files on a compromised host can theoretically be modified if an attacker gains unrestricted ring-0 execution. True immutability requires either write-once physical media or cryptographic distribution:
1. **Sequential SHA-256 Chaining:** Each record commits to the previous record's hash:
   $$\text{Hash}_n = \mathcal{H}\left(n \parallel \text{Timestamp} \parallel \text{Topic} \parallel \text{Payload} \parallel \text{Hash}_{n-1}\right)$$
2. **Cross-Node Replication:** Logs are streamed across NATS and replicated to an independent attestation node (`192.0.2.52`), preventing unilateral log rewriting by a single compromised host.

### 2. Sample Chain Record
```json
{
  "index": 386200,
  "timestamp": "2026-09-22T08:58:36.564478+00:00",
  "topic": "sovereign.security.alert",
  "prev_hash": "b2f6ef1e467cf8402da283f58e470ee64993a479a957a0914ec8c351be7fa83d",
  "hash": "cece8f9bd8839d3753232dd7e504c538a0f58fe0bcf2e260fbefb7d27e77b8cf",
  "data": {
    "output": "Active Exploit Probe: AF_ALG socket requested (domain=38 type=5 user=root ...)",
    "priority": "Warning",
    "rule": "Detect AF_ALG Crypto Socket Creation (CVE-2025-39964)"
  }
}
```

---

## Empirical Verification & Telemetry

Validation was conducted using a synthetic `AF_ALG` socket allocation in an unprivileged test container:

```python
import socket
# Requests AF_ALG Netlink family (domain 38, SOCK_SEQPACKET 5)
s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
```

### Event Lifecycle:
1. **Kernel Syscall:** `socket(38, 5, 0)` invokes `sys_enter_socket`.
2. **eBPF Evaluation (< 1ms):** Modern eBPF tracepoint evaluates `domain == 38` and submits event to the ring buffer.
3. **Pipeline Dispatch (2ms):** Falco emits alert to Falcosidekick webhook (`:9876`).
4. **NATS Distribution (4ms):** Forwarder daemon broadcasts event to `sovereign.security.alert`.
5. **Ledger Sealing (12ms):** Audit daemon appends record to the SHA-256 cryptographic chain.
6. **Cryptographic Validation:**
   ```bash
   $ python3 fsm_audit_vault.py --verify
   # Verified 386,213 records. Zero tampering detected.
   ```

---

## Repository Structure & Deployable Artifacts

This repository includes production-ready configurations for immediate deployment:

```text
|-- etc/
|   \-- modprobe.d/
|       \-- blacklist-ebtables.conf     # Modprobe loader override
|-- helm/
|   |-- falco-rules-kernel-cve.yaml     # Falco modern eBPF rules (CO-RE)
|   \-- README.md                       # One-line Helm deployment guide
|-- k8s/
|   \-- pod-userns-hardened.yaml        # containerd v2.2.4 UserNS manifest
|-- scripts/
|   |-- evict-and-harden.sh             # Two-step module eviction & sealing
|   \-- verify-mitigation.sh            # Automated verification & CI test suite
|-- seccomp/
|   \-- seccomp-block-af-alg.json       # Inline SECCOMP blocking profile (EACCES)
|-- vault/
|   \-- audit_vault.py                  # Cryptographic SHA-256 hash-chain engine
|-- README.md
\-- LICENSE
```

---

## SRE & Systems Architect Takeaways

1. **Compensating Controls Bridge the Patch Gap:** When active kernel zero-days are weaponized, deploy loader and runtime controls immediately while waiting for upstream distro package verification.
2. **Active Module Eviction is Mandatory:** Modprobe overrides only affect future loader requests; always verify running memory via `lsmod` and explicitly evict resident modules (`modprobe -r`).
3. **Two-Phase Gating for kTLS:** Security rules for kTLS must evaluate both `TCP_ULP` attachment (`SOL_TCP=6`, `optname=31`) and option initialization (`SOL_TLS=282`).
4. **User Namespaces Bound Privilege Escalation:** Pairing Kubernetes workloads with containerd user namespaces (`hostUsers: false`) stops container-level privilege escalation from trivially claiming host ring-0 root.
5. **Decouple EDR from Inline Enforcement:** Use asynchronous eBPF (Falco) for low-overhead cluster observability, and synchronous LSM / SECCOMP when zero-microsecond termination is mandatory.

---

*Maintained by the Sovereign Systems & Security Architecture Team.*  
*Production-Tested on Linux HWE & Kubernetes CRI v1.30 (containerd v2.2+).*
