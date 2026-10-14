# Network Device CVE & Configuration Audit Report
*Generated on: 2026-10-14 16:59:17 by Vuln-Check-Net Engine*

---
## Device #1: MCC-ASA

### 1. Device Metadata
| Property | Value |
| :--- | :--- |
| **Hostname** | `MCC-ASA` |
| **Domain Name** | `VNMCC.local` |
| **Vendor** | `Cisco` |
| **OS Family** | `Cisco ASA` |
| **OS Version** | **`9.20(3)`** |
| **Hardware Model** | `FPR-3105` |

### 2. Audit Executive Summary
| Metric | Count | Description |
| :--- | :--- | :--- |
| **Rules Evaluated** | 10 | Total vendor CVE rules tested |
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
| `snmp_server` | **DISABLED :white_check_mark:** | Attack surface closed |
| `telnet` | **DISABLED :white_check_mark:** | Attack surface closed |
| `ssh` | **ENABLED :warning:** | Attack surface exposed |
| `bgp` | **DISABLED :white_check_mark:** | Attack surface closed |
| `ospf` | **DISABLED :white_check_mark:** | Attack surface closed |
| `aaa` | **ENABLED :warning:** | Attack surface exposed |
| `smart_install` | **DISABLED :white_check_mark:** | Attack surface closed |
| `http_outside` | **ENABLED :warning:** | Attack surface exposed |

### 4. Vulnerability Assessment Findings
| CVE ID | Title | Status | Real Risk | CVSS | KEV | Precondition Met? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [CVE-2024-20353](#cve-2024-20353) | Cisco ASA/FTD Web Server Denial of Service (ArcaneDoor / Line Dancer) | **`EXPLOITABLE`** | **CRITICAL** | 8.6 | **YES (KEV)** | YES |

### 5. Technical Details & Remediation Playbook
#### <a id="cve-2024-20353"></a>CVE-2024-20353 - Cisco ASA/FTD Web Server Denial of Service (ArcaneDoor / Line Dancer)
- **Status**: `EXPLOITABLE` (Vulnerable service active and reachable)
- **Real Operational Risk**: **CRITICAL** (CVSS: 8.6)
- **CISA KEV Alert**: Listed on CISA KEV (Date Added: 2024-04-24). Ransomware use: `Known`
- **CISA Required Action**: Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.
- **Affected OS Versions**: `ASA 9.16 < 9.16.4(57), 9.18 < 9.18.4(22), 9.20 <= 9.20(3)`
- **Triggering Precondition**: HTTP Server or WebVPN enabled (http server enable / webvpn)
- **Precondition Active on Device**: `YES`
- **Description**: Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Server Denial of Service Vulnerability (ArcaneDoor / Line Dancer).
- **Remediation / Hardening CLI Command**:
```bash
no http 0.0.0.0 0.0.0.0 outside  # remove HTTP listening on external untrusted interfaces
```
- **References**: https://nvd.nist.gov/vuln/detail/CVE-2024-20353

---
