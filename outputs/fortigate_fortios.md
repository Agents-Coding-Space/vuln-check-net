# Network Device CVE & Configuration Audit Report
*Generated on: 2026-10-15 10:51:58 by Vuln-Check-Net Engine*

---
## Device #1: FGT-DC-PERIMETER-01

### 1. Device Metadata
| Property | Value |
| :--- | :--- |
| **Hostname** | `FGT-DC-PERIMETER-01` |
| **Domain Name** | `` |
| **Vendor** | `Fortinet` |
| **OS Family** | `Fortinet FortiOS` |
| **OS Version** | **`7.4.2`** |
| **Hardware Model** | `FG200F` |

### 2. Audit Executive Summary
| Metric | Count | Description |
| :--- | :--- | :--- |
| **Rules Evaluated** | 4 | Total vendor CVE rules tested |
| **Version In Range** | 1 | CVEs matching OS version (Necessary Condition) |
| :fire: **EXPLOITABLE (Action Required)** | **0** | Precondition active in config (Sufficient Condition) |
| :shield: **MITIGATED (False Positives Avoided)** | **1** | Feature disabled in config (Real Risk neutralized) |
| :warning: **In CISA KEV** | **1** | Known Exploited in the Wild / Ransomware campaigns |
| **Critical Real Risk** | 0 | Immediate remediation priority |
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
| `ospf` | **DISABLED :white_check_mark:** | Attack surface closed |
| `aaa` | **DISABLED :white_check_mark:** | Attack surface closed |
| `smart_install` | **DISABLED :white_check_mark:** | Attack surface closed |
| `http_outside` | **DISABLED :white_check_mark:** | Attack surface closed |

### 4. Vulnerability Assessment Findings
| CVE ID | Title | Status | Real Risk | CVSS | KEV | Precondition Met? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [CVE-2024-21762](#cve-2024-21762) | Fortinet FortiOS SSL-VPN Out-of-Bounds Write Remote Code Execution | **`MITIGATED`** | **LOW** | 9.8 | **YES (KEV)** | NO |

### 5. Technical Details & Remediation Playbook
#### <a id="cve-2024-21762"></a>CVE-2024-21762 - Fortinet FortiOS SSL-VPN Out-of-Bounds Write Remote Code Execution
- **Status**: `MITIGATED` (Feature inactive; vulnerability dormant/mitigated)
- **Real Operational Risk**: **LOW** (CVSS: 9.8)
- **CISA KEV Alert**: Listed on CISA KEV (Date Added: 2024-02-09). Ransomware use: `Known`
- **CISA Required Action**: Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.
- **Affected OS Versions**: `FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14`
- **Triggering Precondition**: SSL-VPN feature enabled (config vpn ssl settings -> set status enable)
- **Precondition Active on Device**: `NO`
- **Description**: Fortinet FortiOS Out-of-Bounds Write in SSL-VPN web portal allowing unauthenticated remote code execution.
- **Remediation / Hardening CLI Command**:
```bash
config vpn ssl settings -> unset status  # or upgrade to 7.4.3+ / 7.2.7+
```
- **References**: https://nvd.nist.gov/vuln/detail/CVE-2024-21762

---
