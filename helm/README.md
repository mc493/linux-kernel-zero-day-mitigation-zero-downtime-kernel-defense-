# Falco Helm Deployment Guide

This directory contains production-tested Helm values for deploying modern eBPF detection rules targeting actively exploited Linux kernel vulnerabilities:
* **CVE-2025-39964:** `AF_ALG` netlink crypto socket allocation
* **CVE-2025-39682:** Kernel TLS (`kTLS`) two-phase activation (`TCP_ULP` attach + `SOL_TLS` options)

---

## 🚀 One-Line Deployment

Deploy or upgrade Falco across all cluster nodes using the modern eBPF driver:

```bash
helm upgrade --install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  -f falco-rules-kernel-cve.yaml
```

---

## 🔍 Verification

Verify all DaemonSet pods are running with 0 restarts:

```bash
kubectl get pods -n falco -l app.kubernetes.io/name=falco -o wide
```

View real-time kernel syscall detection logs:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco -f | grep -E "CVE|AF_ALG|kTLS"
```
