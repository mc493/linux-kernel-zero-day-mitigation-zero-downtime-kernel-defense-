## Description
Briefly summarize the changes introduced in this PR and the specific CVE or operational challenge it addresses.

## Type of Change
- [ ] New compensating control (module disarmament, eBPF rule, SECCOMP filter)
- [ ] Bug fix (fixing a script, CRI compatibility, or syntax error)
- [ ] Documentation update (threat matrix, operational guidelines, or README)
- [ ] Telemetry or CI improvement

## Verification Checklist
- [ ] **Zero-Downtime Verified:** Mitigations apply to a running kernel without requiring host reboot.
- [ ] **Automated Test Suite:** Ran `scripts/verify-mitigation.sh` and it exited with code 0:
  ```bash
  sudo bash scripts/verify-mitigation.sh
  ```
- [ ] **Compatibility Tested:** Verified against at least one modern Linux distribution (e.g. Ubuntu 22.04/24.04, Debian 12, RHEL 9).
- [ ] **Documentation:** Updated relevant threat matrix tables and architecture summaries in `README.md`.
