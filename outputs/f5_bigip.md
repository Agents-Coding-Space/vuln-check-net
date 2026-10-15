# Network Device CVE & Configuration Audit Report
*Generated on: 2026-10-15 10:51:30 by Vuln-Check-Net Engine*

---
## Device #1: bigip-waf-prod01.example.vn

### 1. Device Metadata
| Property | Value |
| :--- | :--- |
| **Hostname** | `bigip-waf-prod01.example.vn` |
| **Domain Name** | `` |
| **Vendor** | `F5 Networks` |
| **OS Family** | `f5_bigip` |
| **OS Version** | **`17.1.1`** |
| **Hardware Model** | `BIG-IP LTM + ASM` |

### 2. Audit Executive Summary
| Metric | Count | Description |
| :--- | :--- | :--- |
| **Rules Evaluated** | 3 | Total vendor CVE rules tested |
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
| `bgp` | **DISABLED :white_check_mark:** | Attack surface closed |
| `ospf` | **DISABLED :white_check_mark:** | Attack surface closed |
| `aaa` | **DISABLED :white_check_mark:** | Attack surface closed |
| `smart_install` | **DISABLED :white_check_mark:** | Attack surface closed |
| `http_outside` | **DISABLED :white_check_mark:** | Attack surface closed |

### 4. Vulnerability Assessment Findings
| CVE ID | Title | Status | Real Risk | CVSS | KEV | Precondition Met? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [CVE-2023-46747](#cve-2023-46747) | F5 BIG-IP Configuration Utility (TMUI) Authentication Bypass & RCE | **`EXPLOITABLE`** | **CRITICAL** | 9.8 | **YES (KEV)** | YES |

### 5. Technical Details & Remediation Playbook
#### <a id="cve-2023-46747"></a>CVE-2023-46747 - F5 BIG-IP Configuration Utility (TMUI) Authentication Bypass & RCE
- **Status**: `EXPLOITABLE` (Vulnerable service active and reachable)
- **Real Operational Risk**: **CRITICAL** (CVSS: 9.8)
- **CISA KEV Alert**: Listed on CISA KEV (Date Added: 2023-10-31). Ransomware use: `Known`
- **CISA Required Action**: Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.
- **Affected OS Versions**: `BIG-IP 17.1.0 - 17.1.1, 16.1.0 - 16.1.4, 15.1.0 - 15.1.10`
- **Triggering Precondition**: HTTP Server / Management GUI enabled (sys httpd)
- **Precondition Active on Device**: `YES`
- **Description**: Authentication bypass vulnerability in the Traffic Management User Interface (TMUI) allows unauthenticated remote attackers with network access to execute arbitrary system commands via AJP request smuggling.
- **Remediation / Hardening CLI Command**:
```bash
tmsh modify sys httpd allow replace-all-with { 10.0.0.0/8 }  # or apply hotfix script K000137353
```
- **References**: https://my.f5.com/manage/s/article/K000137353

---
