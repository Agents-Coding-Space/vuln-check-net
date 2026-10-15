# Network Device CVE & Configuration Audit Report
*Generated on: 2026-10-15 10:51:17 by Vuln-Check-Net Engine*

---
## Device #1: CORE-RTR-HN-01

### 1. Device Metadata
| Property | Value |
| :--- | :--- |
| **Hostname** | `CORE-RTR-HN-01` |
| **Domain Name** | `corp.example.vn` |
| **Vendor** | `Cisco` |
| **OS Family** | `Cisco IOS XE` |
| **OS Version** | **`17.6`** |
| **Hardware Model** | `Unknown` |

### 2. Audit Executive Summary
| Metric | Count | Description |
| :--- | :--- | :--- |
| **Rules Evaluated** | 4 | Total vendor CVE rules tested |
| **Version In Range** | 2 | CVEs matching OS version (Necessary Condition) |
| :fire: **EXPLOITABLE (Action Required)** | **2** | Precondition active in config (Sufficient Condition) |
| :shield: **MITIGATED (False Positives Avoided)** | **0** | Feature disabled in config (Real Risk neutralized) |
| :warning: **In CISA KEV** | **2** | Known Exploited in the Wild / Ransomware campaigns |
| **Critical Real Risk** | 2 | Immediate remediation priority |
| **High Real Risk** | 0 | High remediation priority |

### 3. Audited Configuration Features
| Feature | State in Config | Security Significance |
| :--- | :--- | :--- |
| `http_server` | **ENABLED :warning:** | Attack surface exposed |
| `webvpn` | **DISABLED :white_check_mark:** | Attack surface closed |
| `ssl_vpn` | **DISABLED :white_check_mark:** | Attack surface closed |
| `snmp_server` | **ENABLED :warning:** | Attack surface exposed |
| `telnet` | **ENABLED :warning:** | Attack surface exposed |
| `ssh` | **ENABLED :warning:** | Attack surface exposed |
| `bgp` | **DISABLED :white_check_mark:** | Attack surface closed |
| `ospf` | **ENABLED :warning:** | Attack surface exposed |
| `aaa` | **DISABLED :white_check_mark:** | Attack surface closed |
| `smart_install` | **DISABLED :white_check_mark:** | Attack surface closed |
| `http_outside` | **DISABLED :white_check_mark:** | Attack surface closed |

### 4. Vulnerability Assessment Findings
| CVE ID | Title | Status | Real Risk | CVSS | KEV | Precondition Met? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [CVE-2023-20198](#cve-2023-20198) | Cisco IOS XE Web UI Privilege Escalation | **`EXPLOITABLE`** | **CRITICAL** | 10.0 | **YES (KEV)** | YES |
| [CVE-2023-20273](#cve-2023-20273) | Cisco IOS XE Web UI Command Injection | **`EXPLOITABLE`** | **CRITICAL** | 7.2 | **YES (KEV)** | YES |

### 5. Technical Details & Remediation Playbook
#### <a id="cve-2023-20198"></a>CVE-2023-20198 - Cisco IOS XE Web UI Privilege Escalation
- **Status**: `EXPLOITABLE` (Vulnerable service active and reachable)
- **Real Operational Risk**: **CRITICAL** (CVSS: 10.0)
- **CISA KEV Alert**: Listed on CISA KEV (Date Added: 2023-10-16). Ransomware use: `Known`
- **CISA Required Action**: Apply updates per vendor instructions or disable the HTTP Server feature on internet-facing systems.
- **Affected OS Versions**: `IOS XE 16.1.1 through 17.12.1`
- **Triggering Precondition**: HTTP or HTTPS server enabled (ip http server / ip http secure-server)
- **Precondition Active on Device**: `YES`
- **Description**: Cisco IOS XE Web UI Feature Privilege Escalation Vulnerability leading to arbitrary level 15 user creation.
- **Remediation / Hardening CLI Command**:
```bash
no ip http server ; no ip http secure-server
```
- **References**: https://nvd.nist.gov/vuln/detail/CVE-2023-20198

#### <a id="cve-2023-20273"></a>CVE-2023-20273 - Cisco IOS XE Web UI Command Injection
- **Status**: `EXPLOITABLE` (Vulnerable service active and reachable)
- **Real Operational Risk**: **CRITICAL** (CVSS: 7.2)
- **CISA KEV Alert**: Listed on CISA KEV (Date Added: 2023-10-23). Ransomware use: `Known`
- **CISA Required Action**: Apply updates per vendor instructions.
- **Affected OS Versions**: `IOS XE 16.1.1 through 17.12.1`
- **Triggering Precondition**: HTTP or HTTPS server enabled (ip http server / ip http secure-server)
- **Precondition Active on Device**: `YES`
- **Description**: Cisco IOS XE Web UI Command Injection Vulnerability chained with privilege escalation for root access.
- **Remediation / Hardening CLI Command**:
```bash
no ip http server ; no ip http secure-server
```
- **References**: https://nvd.nist.gov/vuln/detail/CVE-2023-20273

---
