# Network Device CVE & Configuration Audit Report
*Generated on: 2026-10-15 10:51:46 by Vuln-Check-Net Engine*

---
## Device #1: arbor-tms-edge-01.example.vn

### 1. Device Metadata
| Property | Value |
| :--- | :--- |
| **Hostname** | `arbor-tms-edge-01.example.vn` |
| **Domain Name** | `example.vn` |
| **Vendor** | `NETSCOUT` |
| **OS Family** | `arbor_arbos` |
| **OS Version** | **`9.7.1`** |
| **Hardware Model** | `Arbor Sightline / TMS` |

### 2. Audit Executive Summary
| Metric | Count | Description |
| :--- | :--- | :--- |
| **Rules Evaluated** | 1 | Total vendor CVE rules tested |
| **Version In Range** | 1 | CVEs matching OS version (Necessary Condition) |
| :fire: **EXPLOITABLE (Action Required)** | **1** | Precondition active in config (Sufficient Condition) |
| :shield: **MITIGATED (False Positives Avoided)** | **0** | Feature disabled in config (Real Risk neutralized) |
| :warning: **In CISA KEV** | **1** | Known Exploited in the Wild / Ransomware campaigns |
| **Critical Real Risk** | 1 | Immediate remediation priority |
| **High Real Risk** | 0 | High remediation priority |

### 3. Audited Configuration Features
| Feature | State in Config | Security Significance |
| :--- | :--- | :--- |
| `http_server` | **ENABLED :warning:** | Attack surface exposed |
| `webvpn` | **DISABLED :white_check_mark:** | Attack surface closed |
| `ssl_vpn` | **DISABLED :white_check_mark:** | Attack surface closed |
| `snmp_server` | **ENABLED :warning:** | Attack surface exposed |
| `telnet` | **DISABLED :white_check_mark:** | Attack surface closed |
| `ssh` | **ENABLED :warning:** | Attack surface exposed |
| `bgp` | **ENABLED :warning:** | Attack surface exposed |
| `ospf` | **DISABLED :white_check_mark:** | Attack surface closed |
| `aaa` | **ENABLED :warning:** | Attack surface exposed |
| `smart_install` | **DISABLED :white_check_mark:** | Attack surface closed |
| `http_outside` | **DISABLED :white_check_mark:** | Attack surface closed |

### 4. Vulnerability Assessment Findings
| CVE ID | Title | Status | Real Risk | CVSS | KEV | Precondition Met? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [CVE-2020-24368](#cve-2020-24368) | NETSCOUT Arbor Sightline / TMS Web GUI OS Command Injection | **`EXPLOITABLE`** | **CRITICAL** | 8.8 | **YES (KEV)** | YES |

### 5. Technical Details & Remediation Playbook
#### <a id="cve-2020-24368"></a>CVE-2020-24368 - NETSCOUT Arbor Sightline / TMS Web GUI OS Command Injection
- **Status**: `EXPLOITABLE` (Vulnerable service active and reachable)
- **Real Operational Risk**: **CRITICAL** (CVSS: 8.8)
- **CISA KEV Alert**: Listed on CISA KEV (Date Added: 2022-03-25). Ransomware use: `Known`
- **CISA Required Action**: Apply updates per vendor instructions.
- **Affected OS Versions**: `Sightline < 9.8.0, ArbOS < 7.8.0`
- **Triggering Precondition**: HTTP / Web GUI service enabled (services http status set enabled)
- **Precondition Active on Device**: `YES`
- **Description**: Vulnerability in the Web GUI component of NETSCOUT Arbor Sightline / Peakflow allows unauthenticated remote attackers to execute arbitrary commands on the underlying OS.
- **Remediation / Hardening CLI Command**:
```bash
services http status set disabled  # or restrict HTTP access to dedicated management network
```
- **References**: https://nvd.nist.gov/vuln/detail/CVE-2020-24368

---
