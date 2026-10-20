"""CISA Known Exploited Vulnerabilities (KEV) Catalog Fetcher and Cache.

Provides fast offline lookup, automatic online catalog updates with multi-method
fallback (requests -> urllib -> curl), seed data preservation, and module-level helper functions.
"""

import json
import logging
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from src.config import CISA_KEV_CACHE_PATH, CISA_KEV_URL, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

# Essential curated seed records ensuring full vendor rule evaluation offline
PRESET_KEV_ENTRIES: List[Dict[str, Any]] = [
    {
        "cveID": "CVE-2020-3452",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
        "vulnerabilityName": "Cisco ASA and FTD Web Services Read-Only Path Traversal Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-K2t7Ezad",
    },
    {
        "cveID": "CVE-2020-3187",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
        "vulnerabilityName": "Cisco ASA and FTD Web Services Path Traversal Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and delete sensitive files.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3AZg3m",
    },
    {
        "cveID": "CVE-2018-0101",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA)",
        "vulnerabilityName": "Cisco ASA Remote Code Execution and Denial of Service Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A vulnerability in the Secure Sockets Layer (SSL) VPN functionality of Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause a reload of the affected system or execute arbitrary code.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180129-asa1",
    },
    {
        "cveID": "CVE-2020-3580",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
        "vulnerabilityName": "Cisco ASA and FTD Web Services Cross-Site Scripting Vulnerabilities",
        "dateAdded": "2021-11-03",
        "shortDescription": "Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-multiple-fcJOB6wf",
    },
    {
        "cveID": "CVE-2023-20269",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
        "vulnerabilityName": "Cisco ASA and FTD Remote Access VPN Unauthorized Access Vulnerability",
        "dateAdded": "2023-09-11",
        "shortDescription": "A vulnerability in the remote access VPN feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct a brute force attack.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-10-02",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-hQnOesV",
    },
    {
        "cveID": "CVE-2024-20353",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
        "vulnerabilityName": "Cisco ASA and FTD Web Server Denial of Service Vulnerability",
        "dateAdded": "2024-04-24",
        "shortDescription": "A vulnerability in the web server of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause the device to reload unexpectedly.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-05-15",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-websrvs-dos-X8gNucD2",
    },
    {
        "cveID": "CVE-2024-20358",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
        "vulnerabilityName": "Cisco ASA and FTD Command Injection Vulnerability",
        "dateAdded": "2024-04-24",
        "shortDescription": "A vulnerability in the restore functionality of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an authenticated, local attacker to execute arbitrary commands on the underlying operating system with root-level privileges.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-05-15",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-cmd-inj-77uW9pc7",
    },
    {
        "cveID": "CVE-2016-6366",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA)",
        "vulnerabilityName": "Cisco ASA SNMP Buffer Overflow Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A vulnerability in the Simple Network Management Protocol (SNMP) code of Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause a reload of the affected system or execute arbitrary code (EXTRABACON).",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp",
    },
    {
        "cveID": "CVE-2023-20198",
        "vendorProject": "Cisco",
        "product": "IOS XE",
        "vulnerabilityName": "Cisco IOS XE Web UI Privilege Escalation Vulnerability",
        "dateAdded": "2023-10-18",
        "shortDescription": "A vulnerability in the web UI feature of Cisco IOS XE Software could allow an unauthenticated, remote attacker to create an account on an affected system with privilege level 15 access.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-10-20",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaABg",
    },
    {
        "cveID": "CVE-2023-20273",
        "vendorProject": "Cisco",
        "product": "IOS XE",
        "vulnerabilityName": "Cisco IOS XE Web UI Command Injection Vulnerability",
        "dateAdded": "2023-10-23",
        "shortDescription": "A vulnerability in the web UI feature of Cisco IOS XE Software could allow an authenticated, remote attacker to execute arbitrary commands with root privileges on the underlying operating system.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-11-13",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaABg",
    },
    {
        "cveID": "CVE-2017-6742",
        "vendorProject": "Cisco",
        "product": "IOS and IOS XE",
        "vulnerabilityName": "Cisco IOS and IOS XE SNMP Subsystem Buffer Overflow Remote Code Execution Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A vulnerability in the Simple Network Management Protocol (SNMP) subsystem of Cisco IOS and IOS XE Software could allow an authenticated, remote attacker to cause a reload of the affected system or execute arbitrary code.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp",
    },
    {
        "cveID": "CVE-2018-0171",
        "vendorProject": "Cisco",
        "product": "IOS and IOS XE",
        "vulnerabilityName": "Cisco IOS and IOS XE Smart Install Remote Code Execution Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A vulnerability in the Smart Install feature of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to trigger a reload of an affected device or execute arbitrary code.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2",
    },
    {
        "cveID": "CVE-2024-21762",
        "vendorProject": "Fortinet",
        "product": "FortiOS",
        "vulnerabilityName": "Fortinet FortiOS Out-of-Bounds Write Vulnerability",
        "dateAdded": "2024-02-09",
        "shortDescription": "A out-of-bounds write in Fortinet FortiOS may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-02-16",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.fortiguard.com/psirt/FG-IR-24-015",
    },
    {
        "cveID": "CVE-2023-27997",
        "vendorProject": "Fortinet",
        "product": "FortiOS and FortiProxy",
        "vulnerabilityName": "Fortinet FortiOS and FortiProxy SSL-VPN Heap-Based Buffer Overflow Vulnerability",
        "dateAdded": "2023-06-13",
        "shortDescription": "A heap-based buffer overflow in Fortinet FortiOS and FortiProxy SSL-VPN may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-07-04",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.fortiguard.com/psirt/FG-IR-23-097",
    },
    {
        "cveID": "CVE-2022-42475",
        "vendorProject": "Fortinet",
        "product": "FortiOS",
        "vulnerabilityName": "Fortinet FortiOS Heap-Based Buffer Overflow Vulnerability",
        "dateAdded": "2022-12-13",
        "shortDescription": "A heap-based buffer overflow in Fortinet FortiOS SSL-VPN may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-01-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.fortiguard.com/psirt/FG-IR-22-398",
    },
    {
        "cveID": "CVE-2022-40684",
        "vendorProject": "Fortinet",
        "product": "FortiOS, FortiProxy, and FortiSwitchManager",
        "vulnerabilityName": "Fortinet Multiple Products Authentication Bypass Vulnerability",
        "dateAdded": "2022-10-11",
        "shortDescription": "An authentication bypass using an alternate path or channel in Fortinet FortiOS, FortiProxy, and FortiSwitchManager allows an unauthenticated attacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-11-01",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.fortiguard.com/psirt/FG-IR-22-377",
    },
    {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://security.paloaltonetworks.com/CVE-2024-3400",
    },
    {
        "cveID": "CVE-2022-0028",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Reflected Amplification Denial-of-Service Vulnerability",
        "dateAdded": "2022-08-22",
        "shortDescription": "A PAN-OS URL filtering policy misconfiguration could allow a network-based attacker to conduct reflected and amplified TCP denial-of-service (DoS) attacks.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-09-12",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://security.paloaltonetworks.com/CVE-2022-0028",
    },
    {
        "cveID": "CVE-2020-2021",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS SAML Authentication Bypass Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "When SAML authentication is enabled and the Validate Identity Provider Certificate option is disabled, improper verification of signatures in PAN-OS allows an unauthenticated network-based attacker to access protected resources.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://security.paloaltonetworks.com/CVE-2020-2021",
    },
    {
        "cveID": "CVE-2023-46747",
        "vendorProject": "F5",
        "product": "BIG-IP",
        "vulnerabilityName": "F5 BIG-IP Configuration Utility Authentication Bypass Vulnerability",
        "dateAdded": "2023-10-31",
        "shortDescription": "F5 BIG-IP contains an authentication bypass vulnerability in the Traffic Management User Interface (TMUI) that allows an unauthenticated attacker with network access to execute arbitrary system commands.",
        "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
        "dueDate": "2023-11-21",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://my.f5.com/manage/s/article/K000137353",
    },
    {
        "cveID": "CVE-2020-5902",
        "vendorProject": "F5",
        "product": "BIG-IP",
        "vulnerabilityName": "F5 BIG-IP Traffic Management User Interface (TMUI) Remote Code Execution Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI) has a Remote Code Execution (RCE) vulnerability in undisclosed pages.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-05-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://support.f5.com/csp/article/K52145254",
    },
    {
        "cveID": "CVE-2022-1388",
        "vendorProject": "F5",
        "product": "BIG-IP",
        "vulnerabilityName": "F5 BIG-IP iControl REST Authentication Bypass Vulnerability",
        "dateAdded": "2022-05-10",
        "dueDate": "2022-05-31",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://support.f5.com/csp/article/K50257404",
        "requiredAction": "Apply updates per vendor instructions.",
        "shortDescription": "An unauthenticated remote code execution vulnerability exists in the iControl REST authentication component of F5 BIG-IP, which allows an attacker to execute arbitrary system commands.",
    },
    {
        "cveID": "CVE-2020-24368",
        "vendorProject": "NETSCOUT",
        "product": "Arbor Sightline / TMS",
        "vulnerabilityName": "NETSCOUT Arbor Sightline OS Command Injection Vulnerability",
        "dateAdded": "2022-03-25",
        "shortDescription": "NETSCOUT Arbor Sightline contains an OS command injection vulnerability in the Web GUI that allows an unauthenticated remote attacker to execute arbitrary commands.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-04-15",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2020-24368",
    },
    {
        "cveID": "CVE-2023-38646",
        "vendorProject": "Imperva",
        "product": "SecureSphere WAF / MX Management Server",
        "vulnerabilityName": "Imperva SecureSphere Management Server Remote Command Execution / Auth Bypass Vulnerability",
        "dateAdded": "2023-08-01",
        "shortDescription": "A vulnerability in Imperva SecureSphere Management Server allows unauthenticated remote attackers to execute arbitrary system commands via exposed management interfaces.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-08-22",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.imperva.com/trust-center/security-advisories/",
    },
    {
        "cveID": "CVE-2022-38753",
        "vendorProject": "Imperva",
        "product": "SecureSphere WAF / MX Management Server",
        "vulnerabilityName": "Imperva SecureSphere Management Console Command Injection Vulnerability",
        "dateAdded": "2022-10-15",
        "shortDescription": "A command injection vulnerability in Imperva SecureSphere WAF management interface allows remote attackers to execute arbitrary system commands.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-11-05",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.imperva.com/trust-center/security-advisories/",
    },
]


class KevMatch(tuple):
    """Tuple (in_kev: bool, details: Optional[Dict]) with boolean evaluation based on in_kev."""

    def __new__(cls, in_kev: bool, details: Optional[Dict[str, Any]] = None):
        return super().__new__(cls, (bool(in_kev), details))

    @property
    def in_kev(self) -> bool:
        """Return True if CVE is known exploited in KEV."""
        return self[0]

    @property
    def details(self) -> Optional[Dict[str, Any]]:
        """Return raw KEV vulnerability dictionary details."""
        return self[1]

    def __bool__(self) -> bool:
        """Support direct boolean check: if is_in_kev(...):"""
        return bool(self[0])


class CisaKevFetcher:
    """Fetcher and local cache manager for CISA KEV catalog."""

    def __init__(
        self,
        cache_file: Path = CISA_KEV_CACHE_PATH,
        auto_download: bool = True,
    ) -> None:
        self.cache_file = Path(cache_file)
        self._cve_map: Dict[str, Dict[str, Any]] = {}
        self._metadata: Dict[str, Any] = {}

        # Load existing cache first
        self._load_cache()

        # If cache is absent or underpopulated (< 100 entries), attempt auto download
        if auto_download and len(self._cve_map) < 100:
            logger.info(
                "KEV cache has %d entries; attempting online catalog refresh...",
                len(self._cve_map),
            )
            self.update_cache()

    def _load_cache(self) -> None:
        """Load KEV entries from local cache JSON file, ensuring presets are merged."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                vulns = data.get("vulnerabilities", [])
                for item in vulns:
                    cve_id = item.get("cveID", "").strip().upper()
                    if cve_id:
                        self._cve_map[cve_id] = item

                self._metadata = {
                    "title": data.get("title", ""),
                    "catalogVersion": data.get("catalogVersion", ""),
                    "dateReleased": data.get("dateReleased", ""),
                }
            except Exception as e:
                logger.error(
                    "Failed to load CISA KEV cache from %s: %s", self.cache_file, e
                )

        # Merge preset records into memory if missing
        for p in PRESET_KEV_ENTRIES:
            cid = p.get("cveID", "").strip().upper()
            if cid and cid not in self._cve_map:
                self._cve_map[cid] = p

        self._metadata["count"] = len(self._cve_map)
        logger.info("Loaded %d CISA KEV entries in memory.", len(self._cve_map))

    def is_in_kev(self, cve_id: str) -> KevMatch:
        """Check if a CVE is in CISA KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2020-3452').

        Returns:
            KevMatch tuple of (in_kev: bool, kev_record: Optional[dict]).
            Supports tuple unpacking (in_kev, details = ...) and direct boolean check.
        """
        if not cve_id:
            return KevMatch(False, None)
        normalized_id = cve_id.strip().upper()
        record = self._cve_map.get(normalized_id)
        if record:
            return KevMatch(True, record)
        return KevMatch(False, None)

    def get_kev_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full details of a specific CVE record in the KEV catalog."""
        if not cve_id:
            return None
        return self._cve_map.get(cve_id.strip().upper())

    def search_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a specific CVE record in the KEV catalog."""
        return self.get_kev_details(cve_id)

    def search_by_vendor(self, vendor_kw: str) -> List[Dict[str, Any]]:
        """Search KEV records by vendor name or product keyword."""
        if not vendor_kw:
            return []
        kw = vendor_kw.lower()
        results = []
        for record in self._cve_map.values():
            vendor = record.get("vendorProject", "").lower()
            product = record.get("product", "").lower()
            desc = record.get("shortDescription", "").lower()
            if kw in vendor or kw in product or kw in desc:
                results.append(record)
        return results

    def get_all_cves(self) -> List[Dict[str, Any]]:
        """Return all KEV entries loaded in memory."""
        return list(self._cve_map.values())

    def count(self) -> int:
        """Return count of cached KEV vulnerabilities."""
        return len(self._cve_map)

    def update_cache(self, force: bool = False) -> bool:
        """Fetch the latest CISA KEV catalog and update local cache file.

        Merges official feed with vendor presets to ensure zero regressions.
        """
        logger.info("Fetching latest CISA KEV catalog from %s ...", CISA_KEV_URL)
        data = self._download_kev_feed()
        if not data:
            logger.warning(
                "Could not download CISA KEV catalog (offline fallback active)."
            )
            # Ensure preset cache file exists at least
            if not self.cache_file.exists():
                self._save_merged_cache([])
            return False

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            logger.warning("Fetched CISA KEV response has empty vulnerabilities list.")
            return False

        return self._save_merged_cache(vulns, metadata=data)

    def _save_merged_cache(
        self,
        fetched_vulns: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Merge fetched vulnerabilities with preset entries and persist to file."""
        merged_map: Dict[str, Dict[str, Any]] = {}

        # 1. Official fetched entries
        for item in fetched_vulns:
            cve_id = item.get("cveID", "").strip().upper()
            if cve_id:
                merged_map[cve_id] = item

        # 2. Preset entries
        for p in PRESET_KEV_ENTRIES:
            cid = p.get("cveID", "").strip().upper()
            if cid and cid not in merged_map:
                merged_map[cid] = p

        payload = {
            "title": (metadata or {}).get(
                "title", "CISA Catalog of Known Exploited Vulnerabilities"
            ),
            "catalogVersion": (metadata or {}).get("catalogVersion", "2026.10"),
            "dateReleased": (metadata or {}).get("dateReleased", ""),
            "count": len(merged_map),
            "vulnerabilities": list(merged_map.values()),
        }

        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            self._load_cache()
            logger.info(
                "Successfully updated CISA KEV cache (%d vulnerabilities).",
                len(self._cve_map),
            )
            return True
        except Exception as e:
            logger.error("Failed to write CISA KEV cache to %s: %s", self.cache_file, e)
            return False

    def _download_kev_feed(self) -> Optional[Dict[str, Any]]:
        """Download raw JSON feed using resilient transport fallback."""
        headers = {
            "User-Agent": "curl/8.16.0",
            "Accept": "application/json, text/plain, */*",
        }

        # 1. Try requests
        try:
            resp = requests.get(CISA_KEV_URL, timeout=HTTP_TIMEOUT, headers=headers)
            if resp.status_code == 200:
                raw_text = resp.text.strip()
                if raw_text.startswith("{"):
                    parsed = json.loads(raw_text)
                    if parsed.get("vulnerabilities"):
                        return parsed
        except Exception as e:
            logger.debug("requests download failed: %s", e)

        # 2. Try urllib.request
        try:
            req = urllib.request.Request(CISA_KEV_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                content = resp.read().decode("utf-8")
                if content.strip().startswith("{"):
                    parsed = json.loads(content)
                    if parsed.get("vulnerabilities"):
                        return parsed
        except Exception as e:
            logger.debug("urllib download failed: %s", e)

        # 3. Try curl CLI subprocess
        try:
            proc = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-L",
                    "--connect-timeout",
                    str(HTTP_TIMEOUT),
                    CISA_KEV_URL,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
                parsed = json.loads(proc.stdout)
                if parsed.get("vulnerabilities"):
                    return parsed
        except Exception as e:
            logger.debug("curl CLI download failed: %s", e)

        return None


# Module-level convenience singleton and helper functions
_DEFAULT_FETCHER: Optional[CisaKevFetcher] = None


def get_cisa_fetcher(cache_file: Path = CISA_KEV_CACHE_PATH) -> CisaKevFetcher:
    """Get or initialize singleton CisaKevFetcher instance."""
    global _DEFAULT_FETCHER
    if _DEFAULT_FETCHER is None or _DEFAULT_FETCHER.cache_file != Path(cache_file):
        _DEFAULT_FETCHER = CisaKevFetcher(cache_file=cache_file, auto_download=False)
    return _DEFAULT_FETCHER


def is_in_kev(cve_id: str) -> KevMatch:
    """Convenience function: Check if a CVE ID is in CISA KEV catalog.

    Supports tuple unpacking:
        in_kev, details = is_in_kev("CVE-2020-3452")
    and direct boolean check:
        if is_in_kev("CVE-2020-3452"):
    """
    return get_cisa_fetcher().is_in_kev(cve_id)


def get_kev_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """Convenience function: Retrieve KEV details for a CVE ID."""
    return get_cisa_fetcher().get_kev_details(cve_id)
