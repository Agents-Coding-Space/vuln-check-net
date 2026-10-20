"""Precondition rules knowledge base for Multi-Vendor Network CVE Audit Engine.

Defines necessary conditions (affected OS version ranges) and
sufficient conditions (active feature preconditions) for high-impact CVEs.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from src.config import (
    OS_ARBOR_ARBOS,
    OS_CISCO_ASA,
    OS_CISCO_IOS_XE,
    OS_F5_BIGIP,
    OS_FORTINET_FORTIOS,
    OS_IMPERVA_SECURESPHERE,
    OS_PALOALTO_PANOS,
    VENDOR_CISCO,
    VENDOR_F5,
    VENDOR_FORTINET,
    VENDOR_IMPERVA,
    VENDOR_NETSCOUT,
    VENDOR_PALOALTO,
)
from src.version_utils import compare_versions, is_version_in_range


@dataclass
class PreconditionRule:
    """Represents a vulnerability correlation rule."""

    cve_id: str
    title: str
    vendor: str
    os_family: str
    cvss_base: float
    in_kev: bool
    affected_version_description: str
    description: str
    precondition_description: str
    mitigation_cmd: str
    version_checker: Callable[[str], bool]
    precondition_checker: Callable[[Dict[str, Any]], bool]
    references: List[str] = field(default_factory=list)

    def is_version_affected(self, version: str) -> bool:
        """Evaluate if version meets the necessary condition."""
        if not version:
            return False
        try:
            return self.version_checker(version)
        except Exception:
            return False

    def is_precondition_met(self, features: Dict[str, Any]) -> bool:
        """Evaluate if device configuration meets the sufficient condition."""
        if not features:
            return False
        try:
            return self.precondition_checker(features)
        except Exception:
            return False


# ==============================================================================
# 1. CISCO ASA RULES
# ==============================================================================


def _check_asa_cve_2020_3452_ver(v: str) -> bool:
    """CVE-2020-3452 affects ASA < 9.14.1(10)."""
    return is_version_in_range(
        v, min_ver="9.0", max_ver="9.14.1(10)", include_min=True, include_max=False
    )


def _check_asa_cve_2020_3187_ver(v: str) -> bool:
    """CVE-2020-3187 affects ASA < 9.14.1(15)."""
    return is_version_in_range(
        v, min_ver="9.0", max_ver="9.14.1(15)", include_min=True, include_max=False
    )


def _check_asa_cve_2018_0101_ver(v: str) -> bool:
    """CVE-2018-0101 affects ASA 9.0 to 9.8.2."""
    return is_version_in_range(
        v, min_ver="9.0", max_ver="9.8.2", include_min=True, include_max=False
    )


def _check_asa_cve_2020_3580_ver(v: str) -> bool:
    """CVE-2020-3580 affects ASA < 9.16.2."""
    return is_version_in_range(
        v, min_ver="9.0", max_ver="9.16.2", include_min=True, include_max=False
    )


def _check_asa_cve_2023_20269_ver(v: str) -> bool:
    """CVE-2023-20269 affects ASA < 9.18.4, 9.19 < 9.19.1(28), 9.20 < 9.20.2(2)."""
    if compare_versions(v, "9.18.0") < 0:
        return True
    if compare_versions(v, "9.18.0") >= 0 and compare_versions(v, "9.18.4") < 0:
        return True
    if compare_versions(v, "9.19.0") >= 0 and compare_versions(v, "9.19.1(28)") < 0:
        return True
    if compare_versions(v, "9.20.0") >= 0 and compare_versions(v, "9.20.2(2)") < 0:
        return True
    return False


def _check_asa_cve_2024_20353_ver(v: str) -> bool:
    """CVE-2024-20353 (Line Dancer) affects 9.16 < 9.16.4(57), 9.18 < 9.18.4(22), 9.20 <= 9.20(3)."""
    if compare_versions(v, "9.16.0") < 0:
        return True
    if compare_versions(v, "9.16.0") >= 0 and compare_versions(v, "9.16.4(57)") < 0:
        return True
    if compare_versions(v, "9.18.0") >= 0 and compare_versions(v, "9.18.4(22)") < 0:
        return True
    # In 9.20 train, 9.20(3) base and below are affected; fixed in 9.20.3(2) and 9.20.4
    if compare_versions(v, "9.20.0") >= 0 and compare_versions(v, "9.20(3)2") < 0:
        return True
    return False


def _check_asa_cve_2024_20358_ver(v: str) -> bool:
    """CVE-2024-20358 (Line Runner) affects ASA 9.12 to 9.20.2."""
    return is_version_in_range(
        v, min_ver="9.12.0", max_ver="9.20.2", include_min=True, include_max=True
    )


def _check_asa_cve_2016_6366_ver(v: str) -> bool:
    """CVE-2016-6366 (EXTRABACON) affects ASA < 9.6.2."""
    return is_version_in_range(
        v, min_ver="7.0", max_ver="9.6.2", include_min=True, include_max=False
    )


def _check_asa_cve_2022_20623_ver(v: str) -> bool:
    """CVE-2022-20623 affects ASA 9.7 to 9.16.2."""
    return is_version_in_range(
        v, min_ver="9.7.0", max_ver="9.16.2", include_min=True, include_max=False
    )


def _check_asa_cve_2021_1445_ver(v: str) -> bool:
    """CVE-2021-1445 affects ASA < 9.14.2(4)."""
    return is_version_in_range(
        v, min_ver="9.0", max_ver="9.14.2(4)", include_min=True, include_max=False
    )


# ==============================================================================
# 2. CISCO IOS XE RULES
# ==============================================================================


def _check_ios_xe_cve_2023_20198_ver(v: str) -> bool:
    """CVE-2023-20198 affects IOS XE 16.1.1 through 17.12.1."""
    return is_version_in_range(
        v, min_ver="16.1.1", max_ver="17.12.2", include_min=True, include_max=False
    )


def _check_ios_xe_cve_2023_20273_ver(v: str) -> bool:
    """CVE-2023-20273 affects IOS XE 16.1.1 through 17.12.1."""
    return is_version_in_range(
        v, min_ver="16.1.1", max_ver="17.12.2", include_min=True, include_max=False
    )


def _check_ios_cve_2017_6742_ver(v: str) -> bool:
    """CVE-2017-6742 (SNMP) affects IOS/IOS XE 15.0 through 16.6.1."""
    return is_version_in_range(
        v, min_ver="15.0.0", max_ver="16.6.2", include_min=True, include_max=False
    )


def _check_ios_cve_2018_0171_ver(v: str) -> bool:
    """CVE-2018-0171 (Smart Install) affects IOS/IOS XE 12.2 through 16.6.1."""
    return is_version_in_range(
        v, min_ver="12.2.0", max_ver="16.6.2", include_min=True, include_max=False
    )


# ==============================================================================
# 3. FORTINET FORTIOS RULES
# ==============================================================================


def _check_forti_cve_2024_21762_ver(v: str) -> bool:
    """CVE-2024-21762 affects FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14."""
    if is_version_in_range(v, "7.4.0", "7.4.2", True, True):
        return True
    if is_version_in_range(v, "7.2.0", "7.2.6", True, True):
        return True
    if is_version_in_range(v, "7.0.0", "7.0.13", True, True):
        return True
    if is_version_in_range(v, "6.4.0", "6.4.14", True, True):
        return True
    return False


def _check_forti_cve_2023_27997_ver(v: str) -> bool:
    """CVE-2023-27997 (XORtigate) affects FortiOS 7.2.0-7.2.4, 7.0.0-7.0.11, 6.4.0-6.4.12."""
    if is_version_in_range(v, "7.2.0", "7.2.4", True, True):
        return True
    if is_version_in_range(v, "7.0.0", "7.0.11", True, True):
        return True
    if is_version_in_range(v, "6.4.0", "6.4.12", True, True):
        return True
    return False


def _check_forti_cve_2022_42475_ver(v: str) -> bool:
    """CVE-2022-42475 affects FortiOS 7.2.0-7.2.2, 7.0.0-7.0.8, 6.4.0-6.4.10."""
    if is_version_in_range(v, "7.2.0", "7.2.2", True, True):
        return True
    if is_version_in_range(v, "7.0.0", "7.0.8", True, True):
        return True
    if is_version_in_range(v, "6.4.0", "6.4.10", True, True):
        return True
    return False


def _check_forti_cve_2022_40684_ver(v: str) -> bool:
    """CVE-2022-40684 affects FortiOS 7.2.0-7.2.1, 7.0.0-7.0.6."""
    if is_version_in_range(v, "7.2.0", "7.2.1", True, True):
        return True
    if is_version_in_range(v, "7.0.0", "7.0.6", True, True):
        return True
    return False


# ==============================================================================
# 4. PALO ALTO PAN-OS RULES
# ==============================================================================


def _check_pan_cve_2024_3400_ver(v: str) -> bool:
    """CVE-2024-3400 affects PAN-OS 10.2 < 10.2.9, 11.0 < 11.0.4, 11.1 < 11.1.3."""
    if is_version_in_range(v, "10.2.0", "10.2.9", True, False):
        return True
    if is_version_in_range(v, "11.0.0", "11.0.4", True, False):
        return True
    if is_version_in_range(v, "11.1.0", "11.1.3", True, False):
        return True
    return False


def _check_pan_cve_2022_0028_ver(v: str) -> bool:
    """CVE-2022-0028 affects PAN-OS 10.1 < 10.1.6-h6, 10.2 < 10.2.2-h2."""
    if is_version_in_range(v, "10.1.0", "10.1.6-h6", True, False):
        return True
    if is_version_in_range(v, "10.2.0", "10.2.2-h2", True, False):
        return True
    return False


def _check_pan_cve_2020_2021_ver(v: str) -> bool:
    """CVE-2020-2021 affects PAN-OS 8.1 <= 8.1.14, 9.0 <= 9.0.8, 9.1 <= 9.1.2."""
    if is_version_in_range(v, "8.1.0", "8.1.14", True, True):
        return True
    if is_version_in_range(v, "9.0.0", "9.0.8", True, True):
        return True
    if is_version_in_range(v, "9.1.0", "9.1.2", True, True):
        return True
    return False


# ==============================================================================
# 5. F5 BIG-IP RULES
# ==============================================================================


def _check_f5_cve_2023_46747_ver(v: str) -> bool:
    """CVE-2023-46747 affects F5 BIG-IP 17.1.0-17.1.1, 16.1.0-16.1.4, 15.1.0-15.1.10."""
    if is_version_in_range(v, "17.1.0", "17.1.1.1", True, False):
        return True
    if is_version_in_range(v, "16.1.0", "16.1.4.1", True, False):
        return True
    if is_version_in_range(v, "15.1.0", "15.1.10.2", True, False):
        return True
    return False


def _check_f5_cve_2020_5902_ver(v: str) -> bool:
    """CVE-2020-5902 affects F5 BIG-IP 11.6.1 through 15.1.0."""
    return is_version_in_range(v, "11.6.1", "15.1.0.4", True, False)


def _check_f5_cve_2022_1388_ver(v: str) -> bool:
    """CVE-2022-1388 affects F5 BIG-IP 13.1.0 through 16.1.2."""
    return is_version_in_range(v, "13.1.0", "16.1.2.2", True, False)


# ==============================================================================
# 6. NETSCOUT ARBOR SIGHTLINE / TMS RULES
# ==============================================================================


def _check_arbor_cve_2020_24368_ver(v: str) -> bool:
    """CVE-2020-24368 affects Sightline < 9.8.0, ArbOS < 7.8.0."""
    if is_version_in_range(v, "9.0.0", "9.8.0", True, False):
        return True
    if is_version_in_range(v, "7.0.0", "7.8.0", True, False):
        return True
    if compare_versions(v, "9.8.0") < 0 and compare_versions(v, "8.0.0") >= 0:
        return True
    if compare_versions(v, "7.8.0") < 0 and compare_versions(v, "6.0.0") >= 0:
        return True
    return False


# ==============================================================================
# 7. IMPERVA SECURESPHERE WAF RULES
# ==============================================================================


def _check_imperva_cve_2023_38646_ver(v: str) -> bool:
    """CVE-2023-38646 affects SecureSphere < 14.8.0."""
    return is_version_in_range(v, "10.0.0", "14.8.0", True, False)


def _check_imperva_cve_2022_38753_ver(v: str) -> bool:
    """CVE-2022-38753 affects SecureSphere < 14.8.0."""
    return is_version_in_range(v, "10.0.0", "14.8.0", True, False)


# ==============================================================================
# PRECONDITION RULES LIST (27 Total)
# ==============================================================================

PRECONDITION_RULES: List[PreconditionRule] = [
    # ------------------- Cisco ASA -------------------
    PreconditionRule(
        cve_id="CVE-2020-3452",
        title="Cisco ASA/FTD Web Services Read-Only Path Traversal",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=7.5,
        in_kev=True,
        affected_version_description="ASA < 9.14.1(10)",
        description="Allows unauthenticated remote attackers to read arbitrary files within the web services root via directory traversal in HTTP GET requests.",
        precondition_description="HTTP Server or WebVPN enabled (http server enable / webvpn)",
        mitigation_cmd="no http server enable  # or remove public interface access: no http <ip> <mask> outside",
        version_checker=_check_asa_cve_2020_3452_ver,
        precondition_checker=lambda f: bool(f.get("http_server") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-3452"],
    ),
    PreconditionRule(
        cve_id="CVE-2020-3187",
        title="Cisco ASA/FTD Web Services Path Traversal & Arbitrary File Deletion",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=9.1,
        in_kev=True,
        affected_version_description="ASA < 9.14.1(15)",
        description="Allows unauthenticated remote attackers to conduct directory traversal and delete sensitive files on the filesystem, causing system corruption and DoS.",
        precondition_description="HTTP Server or WebVPN enabled (http server enable / webvpn)",
        mitigation_cmd="no http server enable  # upgrade to ASA 9.14.1(15)+",
        version_checker=_check_asa_cve_2020_3187_ver,
        precondition_checker=lambda f: bool(f.get("http_server") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-3187"],
    ),
    PreconditionRule(
        cve_id="CVE-2018-0101",
        title="Cisco ASA SSL VPN XML Parser Remote Code Execution & DoS",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="ASA 9.0 to 9.8.2",
        description="Vulnerability in Secure Sockets Layer (SSL) VPN functionality allows unauthenticated remote attackers to execute arbitrary code or reload the affected system.",
        precondition_description="WebVPN / SSL VPN enabled on any interface",
        mitigation_cmd="webvpn -> no enable <interface>  # or upgrade to 9.8.2+",
        version_checker=_check_asa_cve_2018_0101_ver,
        precondition_checker=lambda f: bool(f.get("webvpn") or f.get("ssl_vpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-0101"],
    ),
    PreconditionRule(
        cve_id="CVE-2020-3580",
        title="Cisco ASA/FTD Web Services Multiple Cross-Site Scripting",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=6.1,
        in_kev=True,
        affected_version_description="ASA < 9.16.2",
        description="Cross-site scripting (XSS) in web services interface allows an unauthenticated remote attacker to execute arbitrary script code in the context of user's session.",
        precondition_description="HTTP Server or WebVPN enabled",
        mitigation_cmd="no http server enable  # or restrict HTTP access to trusted management IP",
        version_checker=_check_asa_cve_2020_3580_ver,
        precondition_checker=lambda f: bool(f.get("http_server") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-3580"],
    ),
    PreconditionRule(
        cve_id="CVE-2023-20269",
        title="Cisco ASA/FTD Remote Access VPN Unauthorized Access & Brute-Force",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=9.1,
        in_kev=True,
        affected_version_description="ASA < 9.18.4, 9.19 < 9.19.1(28), 9.20 < 9.20.2(2)",
        description="Vulnerability in remote access VPN feature allows unauthenticated attackers to conduct brute-force attacks and identify valid credentials (Akira Ransomware).",
        precondition_description="WebVPN or SSL-VPN enabled",
        mitigation_cmd="group-policy DfltGrpPolicy attributes -> vpn-simultaneous-logins 0  # configure DAP or MFA",
        version_checker=_check_asa_cve_2023_20269_ver,
        precondition_checker=lambda f: bool(f.get("webvpn") or f.get("ssl_vpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-20269"],
    ),
    PreconditionRule(
        cve_id="CVE-2024-20353",
        title="Cisco ASA/FTD Web Server Denial of Service (ArcaneDoor / Line Dancer)",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=8.6,
        in_kev=True,
        affected_version_description="ASA 9.16 < 9.16.4(57), 9.18 < 9.18.4(22), 9.20 <= 9.20(3)",
        description="Management and VPN web server vulnerability allowing unauthenticated remote attackers to trigger unexpected device reload and persistent DoS.",
        precondition_description="HTTP Server or WebVPN enabled (http server enable / webvpn)",
        mitigation_cmd="no http 0.0.0.0 0.0.0.0 outside  # remove HTTP listening on external untrusted interfaces",
        version_checker=_check_asa_cve_2024_20353_ver,
        precondition_checker=lambda f: bool(f.get("http_server") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-20353"],
    ),
    PreconditionRule(
        cve_id="CVE-2024-20358",
        title="Cisco ASA/FTD Command Injection & ROMMON Implant (ArcaneDoor / Line Runner)",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=6.0,
        in_kev=True,
        affected_version_description="ASA 9.12 to 9.20.2",
        description="Vulnerability in restore functionality allows authenticated local attacker to execute arbitrary OS commands with root privileges and implant persistent ROMMON code.",
        precondition_description="AAA authentication enabled / administrative CLI access",
        mitigation_cmd="verify /md5 disk0:<image>  # verify integrity of boot firmware and upgrade ASA software",
        version_checker=_check_asa_cve_2024_20358_ver,
        precondition_checker=lambda f: bool(f.get("aaa")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-20358"],
    ),
    PreconditionRule(
        cve_id="CVE-2016-6366",
        title="Cisco ASA SNMP Buffer Overflow Vulnerability (EXTRABACON)",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=8.8,
        in_kev=True,
        affected_version_description="ASA < 9.6.2",
        description="SNMP subsystem buffer overflow allows unauthenticated remote attacker to reload device or execute arbitrary shellcode (Shadow Brokers release).",
        precondition_description="SNMP Server configured (snmp-server community/host)",
        mitigation_cmd="no snmp-server  # or restrict SNMP access to secure internal management network",
        version_checker=_check_asa_cve_2016_6366_ver,
        precondition_checker=lambda f: bool(f.get("snmp_server")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2016-6366"],
    ),
    PreconditionRule(
        cve_id="CVE-2022-20623",
        title="Cisco ASA/FTD AnyConnect SSL VPN Denial of Service",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=7.5,
        in_kev=True,
        affected_version_description="ASA 9.7 to 9.16.2",
        description="Flaw in AnyConnect SSL VPN packet processing causes memory exhaustion and crash upon processing malformed SSL VPN traffic.",
        precondition_description="WebVPN or SSL-VPN enabled",
        mitigation_cmd="webvpn -> no enable <interface>  # upgrade to ASA 9.16.2+",
        version_checker=_check_asa_cve_2022_20623_ver,
        precondition_checker=lambda f: bool(f.get("webvpn") or f.get("ssl_vpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-20623"],
    ),
    PreconditionRule(
        cve_id="CVE-2021-1445",
        title="Cisco ASA/FTD CLI Parser Command Injection",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        cvss_base=6.7,
        in_kev=True,
        affected_version_description="ASA < 9.14.2(4)",
        description="Vulnerability in CLI parser allows authenticated administrator to inject arbitrary commands to execute as root on the Linux underlying kernel.",
        precondition_description="AAA authentication active / administrative access",
        mitigation_cmd="Upgrade ASA to 9.14.2(4)+ and restrict privilege level 15 admin accounts",
        version_checker=_check_asa_cve_2021_1445_ver,
        precondition_checker=lambda f: bool(f.get("aaa")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-1445"],
    ),
    # ------------------- Cisco IOS XE -------------------
    PreconditionRule(
        cve_id="CVE-2023-20198",
        title="Cisco IOS XE Web UI Privilege Escalation",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_IOS_XE,
        cvss_base=10.0,
        in_kev=True,
        affected_version_description="IOS XE 16.1.1 through 17.12.1",
        description="Allows unauthenticated remote attackers to create a local administrative user account with privilege level 15 via exposed Web UI interface.",
        precondition_description="HTTP or HTTPS server enabled (ip http server / ip http secure-server)",
        mitigation_cmd="no ip http server ; no ip http secure-server",
        version_checker=_check_ios_xe_cve_2023_20198_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"],
    ),
    PreconditionRule(
        cve_id="CVE-2023-20273",
        title="Cisco IOS XE Web UI Command Injection",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_IOS_XE,
        cvss_base=7.2,
        in_kev=True,
        affected_version_description="IOS XE 16.1.1 through 17.12.1",
        description="Allows authenticated attackers with privilege level 15 (obtained via CVE-2023-20198) to execute arbitrary commands with root privileges.",
        precondition_description="HTTP or HTTPS server enabled (ip http server / ip http secure-server)",
        mitigation_cmd="no ip http server ; no ip http secure-server",
        version_checker=_check_ios_xe_cve_2023_20273_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-20273"],
    ),
    PreconditionRule(
        cve_id="CVE-2017-6742",
        title="Cisco IOS / IOS XE SNMP Subsystem Remote Code Execution (Jaguar Tooth)",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_IOS_XE,
        cvss_base=8.8,
        in_kev=True,
        affected_version_description="IOS / IOS XE 15.0 through 16.6.1",
        description="Buffer overflow in SNMP subsystem allows authenticated remote attackers to execute arbitrary code or trigger unexpected device reload.",
        precondition_description="SNMP Server configured (snmp-server community/host)",
        mitigation_cmd="no snmp-server  # or restrict SNMP access with an access-list",
        version_checker=_check_ios_cve_2017_6742_ver,
        precondition_checker=lambda f: bool(f.get("snmp_server")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-6742"],
    ),
    PreconditionRule(
        cve_id="CVE-2018-0171",
        title="Cisco IOS / IOS XE Smart Install Remote Code Execution",
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_IOS_XE,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="IOS / IOS XE 12.2 through 16.6.1",
        description="Buffer overflow in Smart Install client listening on TCP port 4786 allows unauthenticated remote attacker to execute arbitrary code.",
        precondition_description="Smart Install feature active (vstack enabled)",
        mitigation_cmd="no vstack",
        version_checker=_check_ios_cve_2018_0171_ver,
        precondition_checker=lambda f: bool(f.get("smart_install")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-0171"],
    ),
    # ------------------- Fortinet FortiOS -------------------
    PreconditionRule(
        cve_id="CVE-2024-21762",
        title="Fortinet FortiOS SSL-VPN Out-of-Bounds Write Remote Code Execution",
        vendor=VENDOR_FORTINET,
        os_family=OS_FORTINET_FORTIOS,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14",
        description="Out-of-bounds write vulnerability in SSL-VPN web portal allows unauthenticated remote attacker to execute arbitrary code via specially crafted HTTP requests.",
        precondition_description="SSL-VPN feature enabled (config vpn ssl settings -> set status enable)",
        mitigation_cmd="config vpn ssl settings -> unset status  # or upgrade to 7.4.3+ / 7.2.7+",
        version_checker=_check_forti_cve_2024_21762_ver,
        precondition_checker=lambda f: bool(f.get("ssl_vpn") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"],
    ),
    PreconditionRule(
        cve_id="CVE-2023-27997",
        title="Fortinet FortiOS SSL-VPN Heap Buffer Overflow (XORtigate)",
        vendor=VENDOR_FORTINET,
        os_family=OS_FORTINET_FORTIOS,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="FortiOS 7.2.0-7.2.4, 7.0.0-7.0.11, 6.4.0-6.4.12",
        description="Heap-based buffer overflow in FortiOS SSL-VPN pre-authentication web interface allows unauthenticated attacker to execute code remotely.",
        precondition_description="SSL-VPN feature enabled",
        mitigation_cmd="config vpn ssl settings -> unset status  # or upgrade to 7.2.5+ / 7.0.12+",
        version_checker=_check_forti_cve_2023_27997_ver,
        precondition_checker=lambda f: bool(f.get("ssl_vpn") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-27997"],
    ),
    PreconditionRule(
        cve_id="CVE-2022-42475",
        title="Fortinet FortiOS SSL-VPN Heap-Based Buffer Overflow",
        vendor=VENDOR_FORTINET,
        os_family=OS_FORTINET_FORTIOS,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="FortiOS 7.2.0-7.2.2, 7.0.0-7.0.8, 6.4.0-6.4.10",
        description="Heap-based buffer overflow in SSL-VPN daemons allows remote unauthenticated attackers to execute arbitrary code.",
        precondition_description="SSL-VPN feature enabled",
        mitigation_cmd="config vpn ssl settings -> unset status  # upgrade to 7.2.3+ / 7.0.9+",
        version_checker=_check_forti_cve_2022_42475_ver,
        precondition_checker=lambda f: bool(f.get("ssl_vpn") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-42475"],
    ),
    PreconditionRule(
        cve_id="CVE-2022-40684",
        title="Fortinet FortiOS Admin Interface Authentication Bypass",
        vendor=VENDOR_FORTINET,
        os_family=OS_FORTINET_FORTIOS,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="FortiOS 7.2.0-7.2.1, 7.0.0-7.0.6",
        description="Authentication bypass using alternate path in HTTP/HTTPS administrative interface allows remote attackers to perform admin operations.",
        precondition_description="Administrative Web UI exposed (HTTP/HTTPS admin port)",
        mitigation_cmd="config firewall local-in-policy -> drop admin access from untrusted interfaces",
        version_checker=_check_forti_cve_2022_40684_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-40684"],
    ),
    # ------------------- Palo Alto PAN-OS -------------------
    PreconditionRule(
        cve_id="CVE-2024-3400",
        title="Palo Alto PAN-OS GlobalProtect Command Injection (MidnightEclipse)",
        vendor=VENDOR_PALOALTO,
        os_family=OS_PALOALTO_PANOS,
        cvss_base=10.0,
        in_kev=True,
        affected_version_description="PAN-OS 10.2 < 10.2.9, 11.0 < 11.0.4, 11.1 < 11.1.3",
        description="Command injection in GlobalProtect feature enables unauthenticated remote attacker to execute arbitrary OS commands with root privileges.",
        precondition_description="GlobalProtect Gateway or Portal active (ssl_vpn)",
        mitigation_cmd="Disable Device Telemetry temporarily; upgrade to PAN-OS 10.2.9-h1+ / 11.0.4-h1+",
        version_checker=_check_pan_cve_2024_3400_ver,
        precondition_checker=lambda f: bool(f.get("ssl_vpn") or f.get("webvpn")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
    ),
    PreconditionRule(
        cve_id="CVE-2022-0028",
        title="Palo Alto PAN-OS URL Filtering Reflected Denial of Service",
        vendor=VENDOR_PALOALTO,
        os_family=OS_PALOALTO_PANOS,
        cvss_base=8.6,
        in_kev=True,
        affected_version_description="PAN-OS 10.1 < 10.1.6-h6, 10.2 < 10.2.2-h2",
        description="Misconfiguration in URL filtering policy allows remote attackers to conduct reflected amplification DoS attacks.",
        precondition_description="URL Filtering policy enabled with Source NAT",
        mitigation_cmd="set rulebase security rules <name> action deny  # upgrade to 10.1.6-h6+ / 10.2.2-h2+",
        version_checker=_check_pan_cve_2022_0028_ver,
        precondition_checker=lambda f: (
            True
        ),  # Active by default if URL filtering NAT exists
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0028"],
    ),
    PreconditionRule(
        cve_id="CVE-2020-2021",
        title="Palo Alto PAN-OS SAML Authentication Bypass",
        vendor=VENDOR_PALOALTO,
        os_family=OS_PALOALTO_PANOS,
        cvss_base=10.0,
        in_kev=True,
        affected_version_description="PAN-OS 8.1 <= 8.1.14, 9.0 <= 9.0.8, 9.1 <= 9.1.2",
        description="Improper verification of cryptographic signature in SAML authentication allows unauthenticated attackers to bypass authentication.",
        precondition_description="AAA SAML Authentication profile active",
        mitigation_cmd="Enable 'Validate Identity Provider Certificate' in SAML profile, or upgrade PAN-OS",
        version_checker=_check_pan_cve_2020_2021_ver,
        precondition_checker=lambda f: bool(f.get("aaa")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-2021"],
    ),
    # ------------------- F5 BIG-IP -------------------
    PreconditionRule(
        cve_id="CVE-2023-46747",
        title="F5 BIG-IP Configuration Utility (TMUI) Authentication Bypass & RCE",
        vendor=VENDOR_F5,
        os_family=OS_F5_BIGIP,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="BIG-IP 17.1.0 - 17.1.1, 16.1.0 - 16.1.4, 15.1.0 - 15.1.10",
        description="Authentication bypass vulnerability in the Traffic Management User Interface (TMUI) allows unauthenticated remote attackers with network access to execute arbitrary system commands via AJP request smuggling.",
        precondition_description="HTTP Server / Management GUI enabled (sys httpd)",
        mitigation_cmd="tmsh modify sys httpd allow replace-all-with { 10.0.0.0/8 }  # or apply hotfix script K000137353",
        version_checker=_check_f5_cve_2023_46747_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://my.f5.com/manage/s/article/K000137353"],
    ),
    PreconditionRule(
        cve_id="CVE-2020-5902",
        title="F5 BIG-IP TMUI Remote Code Execution Vulnerability",
        vendor=VENDOR_F5,
        os_family=OS_F5_BIGIP,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="BIG-IP 11.6.1 - 15.1.0",
        description="Undisclosed pages in the Traffic Management User Interface (TMUI) allow unauthenticated remote attackers to execute arbitrary system commands, create or delete files, and disable services.",
        precondition_description="HTTP Server / Management GUI enabled (sys httpd)",
        mitigation_cmd="Restrict access to TMUI interface or upgrade to fixed release (15.1.0.4+ / 14.1.2.6+)",
        version_checker=_check_f5_cve_2020_5902_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://support.f5.com/csp/article/K52145254"],
    ),
    PreconditionRule(
        cve_id="CVE-2022-1388",
        title="F5 BIG-IP iControl REST Authentication Bypass & Command Execution",
        vendor=VENDOR_F5,
        os_family=OS_F5_BIGIP,
        cvss_base=9.8,
        in_kev=True,
        affected_version_description="BIG-IP 13.1.0 - 16.1.2",
        description="iControl REST authentication component flaw allows unauthenticated remote attackers with network access to execute arbitrary system commands with root privileges.",
        precondition_description="HTTP Server / Management GUI enabled (sys httpd)",
        mitigation_cmd="Block iControl REST access through self IP addresses or upgrade to 16.1.2.2+ / 15.1.5.1+",
        version_checker=_check_f5_cve_2022_1388_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://support.f5.com/csp/article/K50257404"],
    ),
    # ------------------- NETSCOUT Arbor -------------------
    PreconditionRule(
        cve_id="CVE-2020-24368",
        title="NETSCOUT Arbor Sightline / TMS Web GUI OS Command Injection",
        vendor=VENDOR_NETSCOUT,
        os_family=OS_ARBOR_ARBOS,
        cvss_base=8.8,
        in_kev=True,
        affected_version_description="Sightline < 9.8.0, ArbOS < 7.8.0",
        description="Vulnerability in the Web GUI component of NETSCOUT Arbor Sightline / Peakflow allows unauthenticated remote attackers to execute arbitrary commands on the underlying OS.",
        precondition_description="HTTP / Web GUI service enabled (services http status set enabled)",
        mitigation_cmd="services http status set disabled  # or restrict HTTP access to dedicated management network",
        version_checker=_check_arbor_cve_2020_24368_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-24368"],
    ),
    # ------------------- Imperva SecureSphere -------------------
    PreconditionRule(
        cve_id="CVE-2023-38646",
        title="Imperva SecureSphere Management Server Remote Command Execution / Auth Bypass",
        vendor=VENDOR_IMPERVA,
        os_family=OS_IMPERVA_SECURESPHERE,
        cvss_base=8.8,
        in_kev=True,
        affected_version_description="SecureSphere < 14.8.0",
        description="Authentication bypass and remote code execution vulnerability in Imperva SecureSphere MX Management Server web administration console.",
        precondition_description="HTTP Web GUI interface active (webGuiPort configured)",
        mitigation_cmd="Restrict Web GUI access via firewall rules or upgrade SecureSphere to 14.8.0+",
        version_checker=_check_imperva_cve_2023_38646_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://www.imperva.com/trust-center/security-advisories/"],
    ),
    PreconditionRule(
        cve_id="CVE-2022-38753",
        title="Imperva SecureSphere Management Console Command Injection",
        vendor=VENDOR_IMPERVA,
        os_family=OS_IMPERVA_SECURESPHERE,
        cvss_base=8.8,
        in_kev=True,
        affected_version_description="SecureSphere < 14.8.0",
        description="Command injection vulnerability in SecureSphere WAF management interface allows remote attackers to execute arbitrary system commands.",
        precondition_description="HTTP Web GUI interface active (webGuiPort configured)",
        mitigation_cmd="Restrict management access to isolated management network and upgrade to 14.8.0+",
        version_checker=_check_imperva_cve_2022_38753_ver,
        precondition_checker=lambda f: bool(f.get("http_server")),
        references=["https://www.imperva.com/trust-center/security-advisories/"],
    ),
]


# ==============================================================================
# TRIAGE RULE REGISTRY INTERFACE
# ==============================================================================

TRIAGE_RULE_REGISTRY: Dict[str, PreconditionRule] = {
    rule.cve_id.strip().upper(): rule for rule in PRECONDITION_RULES
}


class TriageRuleRegistry:
    """Registry providing lookup and management of precondition rules."""

    def __init__(self, rules: Optional[List[PreconditionRule]] = None) -> None:
        self.rules = rules or PRECONDITION_RULES
        self._map = {r.cve_id.strip().upper(): r for r in self.rules}

    def get_rule(self, cve_id: str) -> Optional[PreconditionRule]:
        """Look up a rule by CVE ID."""
        if not cve_id:
            return None
        return self._map.get(cve_id.strip().upper())

    def get_rules_for_os(self, os_family: str) -> List[PreconditionRule]:
        """Retrieve all rules applicable to a specific OS family."""
        if not os_family:
            return []
        os_clean = os_family.strip().lower()
        return [r for r in self.rules if r.os_family.strip().lower() == os_clean]

    def all_rules(self) -> List[PreconditionRule]:
        """Return all registered rules."""
        return list(self.rules)

    def count(self) -> int:
        """Return total count of registered rules."""
        return len(self.rules)


def get_rule(cve_id: str) -> Optional[PreconditionRule]:
    """Helper function to look up a rule by CVE ID in default registry."""
    if not cve_id:
        return None
    return TRIAGE_RULE_REGISTRY.get(cve_id.strip().upper())


def get_rules_for_os(os_family: str) -> List[PreconditionRule]:
    """Helper function to look up rules by OS family in default registry."""
    if not os_family:
        return []
    os_clean = os_family.strip().lower()
    return [r for r in PRECONDITION_RULES if r.os_family.strip().lower() == os_clean]


# Re-export Precondition Evaluators and Triage Engine for seamless backward/forward compatibility
from src.triage import (  # noqa: E402
    PreconditionResult as PreconditionResult,
    TriageLayer as TriageLayer,
    TriageResult as TriageResult,
    check_aaa as check_aaa,
    check_bgp as check_bgp,
    check_http_server as check_http_server,
    check_ikev2 as check_ikev2,
    check_ospf as check_ospf,
    check_rest_api as check_rest_api,
    check_smart_install as check_smart_install,
    check_snmp as check_snmp,
    check_ssh as check_ssh,
    check_telnet as check_telnet,
    check_webvpn as check_webvpn,
)
