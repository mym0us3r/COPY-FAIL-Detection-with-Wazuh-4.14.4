# COPY FAIL Detection with Wazuh 4.14.4 - CVE-2026-31431

> **Detection engineering for the Copy Fail kernel LPE · Wazuh 4.14.4 · auditd · Ubuntu / RHEL / SUSE / Amazon Linux 2023 / Kali**

![rules](https://img.shields.io/badge/wazuh_rules-8-brightgreen)
![sca](https://img.shields.io/badge/SCA_checks-4-blue)
![status](https://img.shields.io/badge/status-production--validated-success)
![mitre](https://img.shields.io/badge/MITRE-T1068-red)
![cve](https://img.shields.io/badge/CVE-2026--31431-critical)

---

## What is Copy Fail?

CVE-2026-31431 is a logic bug in the Linux kernel's `authencesn` cryptographic template. It allows any unprivileged local user to perform a **deterministic, controlled 4-byte write into the page cache** of any readable file on the system — without requiring race conditions, kernel offsets, or elevated privileges.

A **732-byte Python 3.10+ script** using only standard library modules (`os`, `socket`, `zlib`) exploits the vulnerability to obtain root on all major Linux distributions shipped since 2017.

**The on-disk file remains unchanged**, making traditional file integrity monitoring (FIM) completely blind.

> Discovered by **Taeyang Lee (Theori / Xint)** with the assistance of the Xint Code AI tool.

---

## Official References

| Resource | Link |
|---|---|
| Official CVE Site | https://copy.fail/ |
| Technical Write-up - Xint Research | https://xint.io/blog/copy-fail-linux-distributions |
| PoC - copy_fail_exp.py | https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py |
| Kernel Fix - a664bf3d603d | https://github.com/torvalds/linux/commit/a664bf3d603d |
| Vulnerable Commit - 72548b093ee3 | https://github.com/torvalds/linux/commit/72548b093ee3 |
| MITRE ATT&CK T1068 | https://attack.mitre.org/techniques/T1068/ |

---

## Why FIM Fails - Why This Repo Exists

The write targets only the in-memory page cache. The kernel never marks the page as dirty, so the writeback mechanism never persists it to disk. The on-disk binary remains byte-for-byte identical to the original.

```
Traditional FIM approach:
  read file from disk -> compute hash -> compare -> no anomaly reported

Copy Fail reality:
  on-disk file = UNCHANGED
  page cache   = CORRUPTED
  FIM result   = BLIND
```

**The only effective detection is behavioral**, via syscall monitoring. This repository provides production-validated Wazuh rules that detect the exploit chain at the kernel syscall level.

---

## Exploit Chain

```
Step 1: socket(38, 5, 0)       AF_ALG socket - no privileges required
Step 2: bind()                  Bind to authencesn - activates vulnerable code
Step 3: sendmsg()               Craft AAD payload - bytes 4-7 = value to write
Step 4: splice()          [!]   TRIGGER - page cache pages enter writable SGL
Step 5: recv()                  authencesn writes seqno_lo into page cache
Step 6: execve(/usr/bin/su)     Corrupted setuid binary runs shellcode as UID 0
```

`splice()` is the critical step. It delivers page cache pages into the AF_ALG socket's writable scatterlist without copying — a 2017 in-place optimization in `algif_aead.c` that made pages from the pipe buffer reusable in the destination SGL. When `authencesn.decrypt()` runs, it writes into those pages, which happen to be the page cache of your target file.

---

## Affected Distributions

| Distribution | Kernel | Status |
|---|---|---|
| Ubuntu 24.04 LTS | 6.17.0-1007-aws | ROOT CONFIRMED |
| Amazon Linux 2023 | 6.18.8-9.213.amzn2023 | ROOT CONFIRMED |
| RHEL 10.1 | 6.12.0-124.45.1.el10_1 | ROOT CONFIRMED |
| SUSE 16 | 6.12.0-160000.9-default | ROOT CONFIRMED |
| Kali GNU/Linux 2026.1 | 6.18.12+kali-amd64 | ROOT CONFIRMED |

All Linux distributions shipping kernels since commit `72548b093ee3` (2017) are affected.

> **Container escape**: Copy Fail is also a container escape vector. The page cache is shared across all processes on the host, including across container boundaries. Part 2 by Xint covers Kubernetes exploitation.

---

## Repository Structure

```
copy-fail-detection/
│
├── rules/
│   └── local_rules.xml              # 8 Wazuh detection rules (199600-199607)
│
├── auditd/
│   └── cve-2026-31431.rules         # auditd syscall sensor rules
│
├── sca/
│   └── cve_2026_31431.yml           # SCA policy - kernel-version independent
│
└── docs/
    └── (screenshots, technical notes)
```

---

## Detection Architecture

Two independent layers — neither depends on kernel version.

### Layer 1 - Behavioral Detection (auditd + Wazuh)

The `uid!=0` filter covers users beyond interactive accounts: service accounts (`www-data`, `postgres`, `jenkins`), containers, and web shells with no login session.

**Auditd sensor rules** (`auditd/cve-2026-31431.rules`):
```
-a always,exit -F arch=b64 -S socket -F a0=0x26 -F uid!=0 -k copy_fail_af_alg
-a always,exit -F arch=b32 -S socket -F a0=0x26 -F uid!=0 -k copy_fail_af_alg
-a always,exit -F arch=b64 -S splice -F uid!=0 -k copy_fail_splice
-w /usr/bin/su    -p x -k copy_fail_execve_su
-w /usr/bin/kmod  -p x -k copy_fail_modload
```

### Layer 2 - Vulnerability Surface (SCA Policy)

Automated configuration checks every 12 hours via `sca/cve_2026_31431.yml`. No kernel version required.

### Rule Chain Architecture

| Rule | Parent | Signal | Depth | Level |
|---|---|---|---|---|
| 80700 | decoded_as=auditd | auditd anchor (Wazuh built-in) | 0 | 0 |
| 92600 | 80700 | Python process execution (Wazuh built-in) | 1 | 0 |
| **199600** | **92600** | AF_ALG socket - python chain | **2** | **10** |
| **199601** | **92600** | splice() syscall - python chain | **2** | **10** |
| **199604** | 199601 + if_matched=199600 | EXPLOIT CHAIN - python (same pid/120s) | 3 | **15** |
| **199602** | 80700 | /usr/bin/su execution | 1 | **6** |
| **199603** | 80700 | modprobe/kmod execution | 1 | **12** |
| **199605** | 80700 | AF_ALG socket - non-python | 1 | **10** |
| **199606** | 80700 | splice() syscall - non-python | 1 | **10** |
| **199607** | 199606 + if_matched=199605 | EXPLOIT CHAIN - non-python (same pid/120s) | 2 | **15** |

> **Engineering note**: Rules 199600 and 199601 must be children of rule 92600 (Python process, depth 1), not of 80700. The Wazuh rule engine follows one chain path per event. Placing detection rules at depth 2 under 92600 guarantees they win chain evaluation over sibling rules (e.g. 92603-92606 in 0850-audit_rules.xml which also match `if_group=audit + exe=python`).

---

## Deployment

### Step 1 - Install auditd

```bash
# Ubuntu / Debian / Kali
apt install auditd audispd-plugins -y
systemctl enable --now auditd
auditctl -s | grep enabled
```

```bash
# RHEL / Amazon Linux
yum install audit -y
systemctl enable --now auditd
```

```bash
# SUSE
zypper install audit -y
systemctl enable --now auditd
```

### Step 2 - Deploy auditd sensor rules

```bash
cp auditd/cve-2026-31431.rules /etc/audit/rules.d/
augenrules --load
auditctl -l | grep copy_fail
```

Expected output:
```
-a always,exit -F arch=b64 -S socket -F a0=0x26 -F uid!=0 -F key=copy_fail_af_alg
-a always,exit -F arch=b32 -S socket -F a0=0x26 -F uid!=0 -F key=copy_fail_af_alg
-a always,exit -F arch=b64 -S splice -F uid!=0 -F key=copy_fail_splice
-w /usr/bin/su -p x -k copy_fail_execve_su
-w /usr/bin/kmod -p x -k copy_fail_modload
```

### Step 3 - Deploy Wazuh detection rules

```bash
# Append to your local_rules.xml or deploy as standalone
cp rules/local_rules.xml /var/ossec/etc/rules/cve-2026-31431_rules.xml

# Validate syntax - must exit 0 with zero warnings
/var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5

# Restart manager
systemctl restart wazuh-manager
```

### Step 4 - Deploy SCA policy

```bash
cp sca/cve_2026_31431.yml /var/ossec/etc/shared/default/

# Add to ossec.conf <sca> block:
# <policies>
#   <policy>/var/ossec/etc/shared/default/cve_2026_31431.yml</policy>
# </policies>

systemctl restart wazuh-manager
```

### Step 5 - Configure ossec.conf localfile

Ensure Wazuh ingests the auditd log:

```xml
<!-- Add inside <ossec_config> -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

---

## Validation

### Quick test (no exploit - syscalls only)

```bash
# Create a test user if needed
useradd -m testuser 2>/dev/null || true

# Generate SIGNAL 1 - AF_ALG socket
su - testuser -c "python3 -c \"import socket; socket.socket(38, 5, 0); print('AF_ALG OK')\""

# Generate SIGNAL 3 - /usr/bin/su execution
su - testuser -c "/usr/bin/su --help 2>/dev/null || true"

# Verify auditd captured events
ausearch -k copy_fail_af_alg -ts recent 2>/dev/null | grep "key=\|exe=\|uid=" | head -5

# Verify Wazuh generated alerts
grep -E "199600|199602" /var/ossec/logs/alerts/alerts.log | tail -10
```

### Validate SCA results

```bash
grep -E "31431|cve_2026" /var/ossec/logs/alerts/alerts.log | tail -10
```

Expected SCA score (unmitigated system): **75%** (3 passed / 1 failed - algif_aead not blacklisted)

### Production validation evidence

This ruleset was validated end-to-end with the public PoC on Kali GNU/Linux 2026.1 (Wazuh agent 002, `pentlab`, kernel 6.18.12+kali-amd64):

```
$ su - testuser -c "python3 /tmp/copy_fail_exp.py"
# id ; whoami
uid=0(root) gid=1000(m0us3r) groups=1000(m0us3r),...
root
```

**Wazuh Dashboard Discover results (agent=pentlab, Today)**:

| Rule | Hits | Description |
|---|---|---|
| 199604 | 80 | EXPLOIT CHAIN DETECTED - pid=46784 exe=/usr/bin/python3.13 |
| 199600 | 40 | AF_ALG socket created by non-root process |
| 199603 | 28 | modprobe execution detected |
| 199602 | 12 | /usr/bin/su executed |

`wazuh-analysisd -t`: exit 0 - zero warnings - all 8 rules loaded.

---

## Remediation

### Immediate mitigation (before patch)

```bash
rmmod algif_aead 2>/dev/null || true
echo 'install algif_aead /bin/false' > /etc/modprobe.d/disable-algif-aead.conf
```

This does **not** affect dm-crypt/LUKS, kTLS, IPsec, OpenSSL, GnuTLS, or SSH.

### Permanent fix

Apply kernel commit `a664bf3d603d` via your distribution's kernel update. It reverts the 2017 in-place optimization in `algif_aead.c`, separating `req->src` (TX SGL, where splice delivers pages) from `req->dst` (RX SGL, user buffer). All major distributions are shipping the fix.

```bash
# Ubuntu / Debian
apt update && apt upgrade linux-generic

# RHEL / Amazon Linux
dnf update kernel

# SUSE
zypper update kernel-default
```

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-03-23 | Vulnerability reported to Linux kernel security team |
| 2026-03-24 | Initial confirmation received |
| 2026-03-25 | Patches proposed and reviewed |
| 2026-04-01 | Patch committed to mainline kernel (a664bf3d603d) |
| 2026-04-22 | CVE-2026-31431 assigned |
| 2026-04-29 | Public disclosure - Xint write-up + PoC published |

---

## Comparison with Similar Vulnerabilities

| | Dirty Cow (2016-5195) | Dirty Pipe (2022-0847) | Copy Fail (2026-31431) |
|---|---|---|---|
| Race condition | Yes - multiple attempts | No | No - deterministic logic |
| Can crash system | Yes | No | No |
| Portability | Limited | Version-specific | All distros 2017+ |
| Exploit size | Kilobytes (C) | Hundreds of bytes | 732 bytes (Python stdlib) |
| FIM detection | Possible | Possible | Not possible |

---

## SCA Policy Summary

| Check | Title | Risk |
|---|---|---|
| 31431001 | algif_aead not loaded in memory | CRITICAL |
| 31431002 | algif_aead disabled via modprobe.d | HIGH |
| 31431003 | auditd active and running | HIGH |
| 31431004 | CVE-2026-31431 sensor rules deployed | HIGH |

---

## Author

**Kislley Rodrigues**
Kislley Rodrigues (m0us3r)

---

## Acknowledgments

- **Taeyang Lee (Theori / Xint)** for the discovery, write-up and coordinated disclosure of CVE-2026-31431
- **Wazuh Team** for the open SIEM/XDR platform and Ambassador Program
- **Xint Research** for the technical depth at https://xint.io/blog/copy-fail-linux-distributions

---

*Detection rules, auditd sensor configuration and SCA policy validated on Wazuh 4.14.4, Ubuntu 24.04.2 LTS (kernel 6.8.0-106-generic) and Kali GNU/Linux 2026.1 (kernel 6.18.12+kali-amd64).*
