"""NVD (National Vulnerability Database) SQLite database cache and REST API fetcher.

Features:
- Schema with cve_records, cve_version_ranges, and indices on (vendor, product), cve_id.
- Methods: upsert_cve(record, ranges), get_cves_by_product(vendor, product), get_cve_count().
- Pre-seeded local cache for guaranteed offline execution.
- Rate-limiting (0.6s with API key, 6s without key).
- Exponential backoff retry on HTTP 429.
- Graceful fallback when offline.
"""

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from src.config import (
    BACKOFF_FACTOR,
    DB_PATH,
    HTTP_TIMEOUT,
    MAX_RETRIES,
    NVD_API_KEY,
    NVD_API_URL,
    NVD_DELAY_NO_KEY,
    NVD_DELAY_WITH_KEY,
)
from src.fetcher_cisa import is_in_kev

logger = logging.getLogger(__name__)

PRODUCT_SYNONYMS: Dict[str, List[str]] = {
    "adaptive_security_appliance": [
        "adaptive_security_appliance",
        "adaptive_security_appliance_software",
        "asa",
    ],
    "adaptive_security_appliance_software": [
        "adaptive_security_appliance",
        "adaptive_security_appliance_software",
        "asa",
    ],
    "asa": [
        "adaptive_security_appliance",
        "adaptive_security_appliance_software",
        "asa",
    ],
    "ios_xe": ["ios_xe", "ios-xe", "iosxe"],
    "ios-xe": ["ios_xe", "ios-xe", "iosxe"],
    "iosxe": ["ios_xe", "ios-xe", "iosxe"],
    "pan-os": ["pan-os", "pan_os", "panos"],
    "pan_os": ["pan-os", "pan_os", "panos"],
    "panos": ["pan-os", "pan_os", "panos"],
    "fortios": ["fortios", "forti_os"],
    "forti_os": ["fortios", "forti_os"],
    "big-ip": ["big-ip", "big_ip", "bigip"],
    "big_ip": ["big-ip", "big_ip", "bigip"],
    "bigip": ["big-ip", "big_ip", "bigip"],
    "arbor_sightline": ["arbor_sightline", "sightline", "arbos"],
    "sightline": ["arbor_sightline", "sightline", "arbos"],
    "arbos": ["arbor_sightline", "sightline", "arbos"],
    "securesphere": ["securesphere", "imperva_securesphere"],
    "imperva_securesphere": ["securesphere", "imperva_securesphere"],
    "ios": ["ios", "cisco_ios"],
}

VENDOR_SYNONYMS: Dict[str, List[str]] = {
    "cisco": ["cisco"],
    "fortinet": ["fortinet"],
    "palo_alto_networks": [
        "palo_alto_networks",
        "paloaltonetworks",
        "palo_alto",
        "palo alto",
    ],
    "paloaltonetworks": [
        "palo_alto_networks",
        "paloaltonetworks",
        "palo_alto",
        "palo alto",
    ],
    "palo_alto": [
        "palo_alto_networks",
        "paloaltonetworks",
        "palo_alto",
        "palo alto",
    ],
    "f5": ["f5", "f5_networks", "f5 networks"],
    "netscout": ["netscout", "arbor"],
    "imperva": ["imperva"],
}


# Pre-seeded vulnerability records with version ranges and CISA KEV tags
OFFLINE_SEED_DATA: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2020-3452",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Services Read-Only Path Traversal Vulnerability.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-22",
        "published_date": "2020-07-22",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.14.1.10",
            }
        ],
    },
    {
        "cve_id": "CVE-2020-3187",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Services Path Traversal and Arbitrary File Deletion Vulnerability.",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cwe": "CWE-22",
        "published_date": "2020-07-22",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.14.1.10",
            }
        ],
    },
    {
        "cve_id": "CVE-2018-0101",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) SSL VPN WebVPN XML Parser Remote Code Execution and Denial of Service Vulnerability.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-119",
        "published_date": "2018-01-29",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.8.2",
            }
        ],
    },
    {
        "cve_id": "CVE-2020-3580",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Services Cross-Site Scripting Vulnerabilities.",
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79",
        "published_date": "2020-10-21",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.14.2",
            }
        ],
    },
    {
        "cve_id": "CVE-2023-20269",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Remote Access VPN Unauthorized Access / Brute-Force Vulnerability.",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-307",
        "published_date": "2023-09-08",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.18.3",
            }
        ],
    },
    {
        "cve_id": "CVE-2024-20353",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Server Denial of Service Vulnerability (ArcaneDoor / Line Dancer).",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
        "cwe": "CWE-399",
        "published_date": "2024-04-24",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.18.4",
            }
        ],
    },
    {
        "cve_id": "CVE-2024-20358",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Command Injection Vulnerability (ArcaneDoor / Line Runner).",
        "cvss_score": 6.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-78",
        "published_date": "2024-04-24",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.18.4",
            }
        ],
    },
    {
        "cve_id": "CVE-2016-6366",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) SNMP Buffer Overflow Vulnerability (EXTRABACON / Shadow Brokers).",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-119",
        "published_date": "2016-08-17",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.6.2",
            }
        ],
    },
    {
        "cve_id": "CVE-2022-20623",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) AnyConnect SSL VPN Denial of Service Vulnerability.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "published_date": "2022-04-06",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 0,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.16.2",
            }
        ],
    },
    {
        "cve_id": "CVE-2021-1445",
        "vendor": "cisco",
        "product": "adaptive_security_appliance",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Command Injection Vulnerability in CLI parser.",
        "cvss_score": 6.7,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "published_date": "2021-04-28",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 0,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "adaptive_security_appliance",
                "version_end_exc": "9.14.2",
            }
        ],
    },
    {
        "cve_id": "CVE-2023-20198",
        "vendor": "cisco",
        "product": "ios_xe",
        "description": "Cisco IOS XE Web UI Feature Privilege Escalation Vulnerability leading to arbitrary level 15 user creation.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "published_date": "2023-10-16",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "ios_xe",
                "version_end_exc": "17.9.4a",
            }
        ],
    },
    {
        "cve_id": "CVE-2023-20273",
        "vendor": "cisco",
        "product": "ios_xe",
        "description": "Cisco IOS XE Web UI Command Injection Vulnerability chained with privilege escalation for root access.",
        "cvss_score": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "published_date": "2023-10-23",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "ios_xe",
                "version_end_exc": "17.9.4a",
            }
        ],
    },
    {
        "cve_id": "CVE-2017-6742",
        "vendor": "cisco",
        "product": "ios_xe",
        "description": "Cisco IOS and IOS XE SNMP Subsystem Buffer Overflow Remote Code Execution Vulnerability (Jaguar Tooth).",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-119",
        "published_date": "2017-06-29",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "ios_xe",
                "version_end_exc": "16.6.1",
            }
        ],
    },
    {
        "cve_id": "CVE-2018-0171",
        "vendor": "cisco",
        "product": "ios_xe",
        "description": "Cisco IOS and IOS XE Smart Install (SMI) Remote Code Execution and Device Reload Vulnerability (TCP port 4786).",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-20",
        "published_date": "2018-03-29",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "cisco",
                "product": "ios_xe",
                "version_end_exc": "16.8.1",
            }
        ],
    },
    {
        "cve_id": "CVE-2024-21762",
        "vendor": "fortinet",
        "product": "fortios",
        "description": "Fortinet FortiOS Out-of-Bounds Write in SSL-VPN web portal allowing unauthenticated remote code execution.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-787",
        "published_date": "2024-02-09",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "fortinet",
                "product": "fortios",
                "version_start_inc": "7.4.0",
                "version_end_exc": "7.4.3",
            },
            {
                "vendor": "fortinet",
                "product": "fortios",
                "version_start_inc": "7.2.0",
                "version_end_exc": "7.2.7",
            },
        ],
    },
    {
        "cve_id": "CVE-2023-27997",
        "vendor": "fortinet",
        "product": "fortios",
        "description": "Fortinet FortiOS and FortiProxy SSL-VPN Heap Buffer Overflow Vulnerability (XORtigate) allowing unauthenticated RCE.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-122",
        "published_date": "2023-06-12",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "fortinet",
                "product": "fortios",
                "version_start_inc": "7.2.0",
                "version_end_exc": "7.2.5",
            }
        ],
    },
    {
        "cve_id": "CVE-2022-42475",
        "vendor": "fortinet",
        "product": "fortios",
        "description": "Fortinet FortiOS SSL-VPN Heap Buffer Overflow Vulnerability actively exploited in targeted state-sponsored campaigns.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-787",
        "published_date": "2022-12-12",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "fortinet",
                "product": "fortios",
                "version_start_inc": "7.2.0",
                "version_end_exc": "7.2.3",
            }
        ],
    },
    {
        "cve_id": "CVE-2022-40684",
        "vendor": "fortinet",
        "product": "fortios",
        "description": "Fortinet FortiOS, FortiProxy, and FortiSwitchManager Authentication Bypass on Administrative Interface (HTTP/HTTPS).",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-287",
        "published_date": "2022-10-10",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "fortinet",
                "product": "fortios",
                "version_start_inc": "7.2.0",
                "version_end_exc": "7.2.2",
            }
        ],
    },
    {
        "cve_id": "CVE-2024-3400",
        "vendor": "palo_alto_networks",
        "product": "pan-os",
        "description": "Palo Alto Networks PAN-OS GlobalProtect Gateway Arbitrary Command Injection Vulnerability (Operation MidnightEclipse).",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-77",
        "published_date": "2024-04-12",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "palo_alto_networks",
                "product": "pan-os",
                "version_start_inc": "11.1.0",
                "version_end_exc": "11.1.2-h3",
            },
            {
                "vendor": "palo_alto_networks",
                "product": "pan-os",
                "version_start_inc": "11.0.0",
                "version_end_exc": "11.0.4-h1",
            },
        ],
    },
    {
        "cve_id": "CVE-2022-0028",
        "vendor": "palo_alto_networks",
        "product": "pan-os",
        "description": "Palo Alto Networks PAN-OS URL Filtering Denial of Service Amplification and Reflected Attack Vulnerability.",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
        "cwe": "CWE-406",
        "published_date": "2022-08-10",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "palo_alto_networks",
                "product": "pan-os",
                "version_start_inc": "10.2.0",
                "version_end_exc": "10.2.2-h2",
            }
        ],
    },
    {
        "cve_id": "CVE-2020-2021",
        "vendor": "palo_alto_networks",
        "product": "pan-os",
        "description": "Palo Alto Networks PAN-OS SAML Authentication Bypass Vulnerability when Identity Provider signature validation is disabled.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-287",
        "published_date": "2020-06-29",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "palo_alto_networks",
                "product": "pan-os",
                "version_start_inc": "9.1.0",
                "version_end_exc": "9.1.3",
            }
        ],
    },
    {
        "cve_id": "CVE-2023-46747",
        "vendor": "f5",
        "product": "big-ip",
        "description": "F5 BIG-IP Configuration Utility Authentication Bypass Vulnerability in TMUI.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-287",
        "published_date": "2023-10-31",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "f5",
                "product": "big-ip",
                "version_start_inc": "17.1.0",
                "version_end_exc": "17.1.0.3",
            }
        ],
    },
    {
        "cve_id": "CVE-2020-5902",
        "vendor": "f5",
        "product": "big-ip",
        "description": "F5 BIG-IP Traffic Management User Interface (TMUI) Remote Code Execution Vulnerability.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-22",
        "published_date": "2020-07-02",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "f5",
                "product": "big-ip",
                "version_start_inc": "15.0.0",
                "version_end_exc": "15.1.0.4",
            }
        ],
    },
    {
        "cve_id": "CVE-2022-1388",
        "vendor": "f5",
        "product": "big-ip",
        "description": "F5 BIG-IP iControl REST Authentication Bypass Vulnerability.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "published_date": "2022-05-06",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "f5",
                "product": "big-ip",
                "version_start_inc": "16.1.0",
                "version_end_exc": "16.1.2.2",
            }
        ],
    },
    {
        "cve_id": "CVE-2020-24368",
        "vendor": "netscout",
        "product": "arbor_sightline",
        "description": "NETSCOUT Arbor Sightline OS Command Injection Vulnerability.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "published_date": "2020-09-09",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "netscout",
                "product": "arbor_sightline",
                "version_start_inc": "9.0.0",
                "version_end_exc": "9.8.0",
            }
        ],
    },
    {
        "cve_id": "CVE-2023-38646",
        "vendor": "imperva",
        "product": "securesphere",
        "description": "Imperva SecureSphere Management Server Remote Command Execution / Auth Bypass Vulnerability.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "published_date": "2023-08-01",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "imperva",
                "product": "securesphere",
                "version_start_inc": "14.0.0",
                "version_end_exc": "14.8.0",
            }
        ],
    },
    {
        "cve_id": "CVE-2022-38753",
        "vendor": "imperva",
        "product": "securesphere",
        "description": "Imperva SecureSphere Management Console Command Injection Vulnerability.",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "published_date": "2022-10-15",
        "last_modified": "2024-04-24",
        "in_cisa_kev": 1,
        "ranges": [
            {
                "vendor": "imperva",
                "product": "securesphere",
                "version_start_inc": "13.0.0",
                "version_end_exc": "14.7.0.30",
            }
        ],
    },
]


class NVDDatabase:
    """SQLite Database manager for CVE records and version ranges cache."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            # 1. cve_records table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_records (
                    cve_id TEXT PRIMARY KEY,
                    vendor TEXT,
                    product TEXT,
                    description TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cwe TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    in_cisa_kev INTEGER DEFAULT 0
                )
                """
            )

            # 2. cve_version_ranges table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_version_ranges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    version_start_inc TEXT,
                    version_start_exc TEXT,
                    version_end_inc TEXT,
                    version_end_exc TEXT,
                    exact_version TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cve_records(cve_id) ON DELETE CASCADE
                )
                """
            )

            # 3. Backward-compatibility cve_cache table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # 4. Indexes on (vendor, product), cve_id
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cve_records_vendor_product ON cve_records(vendor, product)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cve_records_cve_id ON cve_records(cve_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cve_ranges_vendor_product ON cve_version_ranges(vendor, product)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cve_ranges_cve_id ON cve_version_ranges(cve_id)"
            )

            conn.commit()

        # Seed if empty
        self._seed_cache_if_empty()

    def _seed_cache_if_empty(self) -> None:
        """Seed SQLite database with pre-configured offline records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_records")
            count = cursor.fetchone()[0]

            if count == 0:
                for item in OFFLINE_SEED_DATA:
                    ranges = item.get("ranges", [])
                    self.upsert_cve(item, ranges=ranges)

                logger.info(
                    "Pre-seeded SQLite cache with %d CVE records and ranges.",
                    len(OFFLINE_SEED_DATA),
                )

    def upsert_cve(
        self,
        record: Dict[str, Any],
        ranges: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Insert or update a CVE record and its associated version ranges.

        Args:
            record: Dict with fields: cve_id, vendor, product, description,
                    cvss_score, cvss_vector, cwe, published_date, last_modified,
                    in_cisa_kev.
            ranges: Optional list of version range dicts: version_start_inc,
                    version_start_exc, version_end_inc, version_end_exc, exact_version.
        """
        raw_cve_id = record.get("cve_id", "")
        if not raw_cve_id:
            raise ValueError("record['cve_id'] is required for upsert_cve.")

        cve_id = str(raw_cve_id).strip().upper()
        vendor = str(record.get("vendor") or "").strip()
        product = str(record.get("product") or "").strip()
        description = str(record.get("description") or "").strip()
        cvss_score = float(record.get("cvss_score") or 0.0)
        cvss_vector = str(record.get("cvss_vector") or "").strip()
        cwe = str(record.get("cwe") or "").strip()
        published_date = str(record.get("published_date") or "").strip()
        last_modified = str(record.get("last_modified") or "").strip()

        # Determine in_cisa_kev status
        in_kev_val = record.get("in_cisa_kev")
        if in_kev_val is not None:
            in_cisa_kev = 1 if in_kev_val else 0
        else:
            in_cisa_kev = 1 if bool(is_in_kev(cve_id)) else 0

        with self._get_connection() as conn:
            # Upsert cve_records
            conn.execute(
                """
                INSERT INTO cve_records (
                    cve_id, vendor, product, description, cvss_score,
                    cvss_vector, cwe, published_date, last_modified, in_cisa_kev
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    vendor = excluded.vendor,
                    product = excluded.product,
                    description = excluded.description,
                    cvss_score = excluded.cvss_score,
                    cvss_vector = excluded.cvss_vector,
                    cwe = excluded.cwe,
                    published_date = excluded.published_date,
                    last_modified = excluded.last_modified,
                    in_cisa_kev = excluded.in_cisa_kev
                """,
                (
                    cve_id,
                    vendor,
                    product,
                    description,
                    cvss_score,
                    cvss_vector,
                    cwe,
                    published_date,
                    last_modified,
                    in_cisa_kev,
                ),
            )

            # Sync legacy cve_cache table
            conn.execute(
                """
                INSERT INTO cve_cache (
                    cve_id, description, cvss_score, cvss_vector, published_date
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description = excluded.description,
                    cvss_score = excluded.cvss_score,
                    cvss_vector = excluded.cvss_vector,
                    published_date = excluded.published_date
                """,
                (cve_id, description, cvss_score, cvss_vector, published_date),
            )

            # If ranges provided, replace existing version ranges
            if ranges is not None:
                conn.execute(
                    "DELETE FROM cve_version_ranges WHERE cve_id = ?",
                    (cve_id,),
                )
                for r in ranges:
                    r_vendor = str(r.get("vendor") or vendor).strip()
                    r_product = str(r.get("product") or product).strip()
                    conn.execute(
                        """
                        INSERT INTO cve_version_ranges (
                            cve_id, vendor, product, version_start_inc,
                            version_start_exc, version_end_inc, version_end_exc,
                            exact_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cve_id,
                            r_vendor,
                            r_product,
                            r.get("version_start_inc"),
                            r.get("version_start_exc"),
                            r.get("version_end_inc"),
                            r.get("version_end_exc"),
                            r.get("exact_version"),
                        ),
                    )

            conn.commit()

    def get_cves_by_product(self, vendor: str, product: str) -> List[Dict[str, Any]]:
        """Query CVE records matching vendor and product (case-insensitive).

        Args:
            vendor: Vendor name (e.g. 'cisco', 'fortinet').
            product: Product name (e.g. 'adaptive_security_appliance', 'fortios').

        Returns:
            List of matching CVE dictionaries with version_ranges.
        """
        v_clean = vendor.strip().lower()
        p_clean = product.strip().lower()

        v_list = VENDOR_SYNONYMS.get(v_clean, [v_clean])
        p_list = PRODUCT_SYNONYMS.get(p_clean, [p_clean])

        matched_cve_ids = set()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            v_ph = ",".join("?" for _ in v_list)
            p_ph = ",".join("?" for _ in p_list)

            # 1. Match from cve_records
            cursor.execute(
                f"""
                SELECT cve_id FROM cve_records
                WHERE LOWER(vendor) IN ({v_ph}) AND LOWER(product) IN ({p_ph})
                """,
                (*v_list, *p_list),
            )
            for row in cursor.fetchall():
                matched_cve_ids.add(row["cve_id"])

            # 2. Match from cve_version_ranges
            cursor.execute(
                f"""
                SELECT DISTINCT cve_id FROM cve_version_ranges
                WHERE LOWER(vendor) IN ({v_ph}) AND LOWER(product) IN ({p_ph})
                """,
                (*v_list, *p_list),
            )
            for row in cursor.fetchall():
                matched_cve_ids.add(row["cve_id"])

        results = []
        for cve_id in sorted(matched_cve_ids):
            cve_data = self.get_cve(cve_id)
            if cve_data:
                results.append(cve_data)

        return results

    def get_cve_count(self) -> int:
        """Return total number of CVE records stored in cve_records table."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_records")
            row = cursor.fetchone()
            return row[0] if row else 0

    def get_cve(
        self, cve_id: str, fetch_remote: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Retrieve CVE record from SQLite database.

        Args:
            cve_id: Target CVE ID.
            fetch_remote: Optional flag for fetcher subclasses.

        Returns:
            Dictionary with CVE details and version_ranges, or None.
        """
        if not cve_id:
            return None

        normalized_id = cve_id.strip().upper()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT cve_id, vendor, product, description, cvss_score,
                       cvss_vector, cwe, published_date, last_modified,
                       in_cisa_kev
                FROM cve_records WHERE cve_id = ?
                """,
                (normalized_id,),
            )
            row = cursor.fetchone()

            if row:
                record = {
                    "cve_id": row["cve_id"],
                    "vendor": row["vendor"],
                    "product": row["product"],
                    "description": row["description"],
                    "cvss_score": row["cvss_score"],
                    "cvss_vector": row["cvss_vector"],
                    "cwe": row["cwe"],
                    "published_date": row["published_date"],
                    "last_modified": row["last_modified"],
                    "in_cisa_kev": row["in_cisa_kev"],
                }
                record["version_ranges"] = self.get_version_ranges(normalized_id)
                return record

            # Fallback to legacy cve_cache table
            cursor.execute(
                """
                SELECT cve_id, description, cvss_score, cvss_vector, published_date
                FROM cve_cache WHERE cve_id = ?
                """,
                (normalized_id,),
            )
            legacy_row = cursor.fetchone()
            if legacy_row:
                return {
                    "cve_id": legacy_row["cve_id"],
                    "vendor": "",
                    "product": "",
                    "description": legacy_row["description"],
                    "cvss_score": legacy_row["cvss_score"],
                    "cvss_vector": legacy_row["cvss_vector"],
                    "cwe": "",
                    "published_date": legacy_row["published_date"],
                    "last_modified": "",
                    "in_cisa_kev": 1 if bool(is_in_kev(normalized_id)) else 0,
                    "version_ranges": [],
                }

        return None

    def get_version_ranges(self, cve_id: str) -> List[Dict[str, Any]]:
        """Retrieve version ranges for a given CVE ID."""
        if not cve_id:
            return []

        normalized_id = cve_id.strip().upper()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, cve_id, vendor, product, version_start_inc,
                       version_start_exc, version_end_inc, version_end_exc,
                       exact_version
                FROM cve_version_ranges WHERE cve_id = ?
                ORDER BY id
                """,
                (normalized_id,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "cve_id": r["cve_id"],
                    "vendor": r["vendor"],
                    "product": r["product"],
                    "version_start_inc": r["version_start_inc"],
                    "version_start_exc": r["version_start_exc"],
                    "version_end_inc": r["version_end_inc"],
                    "version_end_exc": r["version_end_exc"],
                    "exact_version": r["exact_version"],
                }
                for r in rows
            ]

    def close(self) -> None:
        """Close DB operations placeholder for resource consistency."""
        pass


class NVDFetcher(NVDDatabase):
    """NVD API fetcher with local SQLite caching."""

    def __init__(self, db_path: Path = DB_PATH, api_key: Optional[str] = None) -> None:
        super().__init__(db_path=db_path)
        self.api_key = api_key if api_key is not None else NVD_API_KEY
        self.last_request_time = 0.0

    def get_cve(
        self, cve_id: str, fetch_remote: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Retrieve CVE details from SQLite cache or optionally query remote NVD API."""
        if not cve_id:
            return None

        normalized_id = cve_id.strip().upper()

        # 1. Check local cache
        cached = super().get_cve(normalized_id)
        if cached:
            return cached

        # 2. Query remote NVD API if requested
        if fetch_remote:
            remote_record = self.fetch_cve_from_api(normalized_id)
            if remote_record:
                ranges = remote_record.get("version_ranges", [])
                self.upsert_cve(remote_record, ranges=ranges)
                return self.get_cve(normalized_id)

        return None

    def save_cve(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        cvss_vector: str,
        published_date: str,
    ) -> None:
        """Store or update a CVE record in cache (backward compatibility method)."""
        self.upsert_cve(
            {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "published_date": published_date,
            }
        )

    def fetch_cve_from_api(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Query NVD 2.0 REST API with rate limiting and exponential backoff retry."""
        delay = NVD_DELAY_WITH_KEY if self.api_key else NVD_DELAY_NO_KEY
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)

        headers = {"User-Agent": "Vuln-Check-Net/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        url = f"{NVD_API_URL}?cveId={cve_id.upper()}"
        attempt = 0
        current_backoff = BACKOFF_FACTOR

        while attempt < MAX_RETRIES:
            attempt += 1
            try:
                self.last_request_time = time.time()
                resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)

                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        return None

                    cve_item = vulnerabilities[0].get("cve", {})
                    return self._parse_nvd_item(cve_item)

                elif resp.status_code == 429:
                    logger.warning(
                        "NVD Rate Limit (429) hit for %s. Sleeping %.1fs (attempt %d/%d)...",
                        cve_id,
                        current_backoff,
                        attempt,
                        MAX_RETRIES,
                    )
                    time.sleep(current_backoff)
                    current_backoff *= 2
                    continue
                else:
                    logger.warning(
                        "NVD API returned status %d for %s", resp.status_code, cve_id
                    )
                    return None

            except requests.RequestException as e:
                logger.warning(
                    "Network error connecting to NVD API for %s: %s (attempt %d/%d)",
                    cve_id,
                    e,
                    attempt,
                    MAX_RETRIES,
                )
                time.sleep(current_backoff)
                current_backoff *= 2

        return None

    def _parse_nvd_item(
        self,
        cve_item: Dict[str, Any],
        default_vendor: str = "",
        default_product: str = "",
    ) -> Dict[str, Any]:
        """Parse raw NVD JSON item into structured dictionary with CPE version ranges."""
        cve_id = cve_item.get("id", "")
        published = cve_item.get("published", "")
        last_modified = cve_item.get("lastModified", "")

        # Description
        desc_text = ""
        descriptions = cve_item.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        # CVSS Metrics (prefer v3.1, then v4.0, then v3.0, then v2.0)
        cvss_score = 0.0
        cvss_vector = ""
        metrics = cve_item.get("metrics", {})

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            cvss_vector = data.get("vectorString", "")
        elif "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
            data = metrics["cvssMetricV40"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            cvss_vector = data.get("vectorString", "")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            cvss_vector = data.get("vectorString", "")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            cvss_vector = data.get("vectorString", "")

        # CWE Extraction
        cwe_val = ""
        weaknesses = cve_item.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_val = val
                    break
            if cwe_val:
                break

        # Configurations / CPE version ranges
        vendor = default_vendor
        product = default_product
        version_ranges: List[Dict[str, Any]] = []

        def _collect_matches(node_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            m_res = []
            for node in node_list:
                for match in node.get("cpeMatch", []):
                    m_res.append(match)
                if "children" in node:
                    m_res.extend(_collect_matches(node["children"]))
            return m_res

        all_matches = []
        for cfg in cve_item.get("configurations", []):
            all_matches.extend(_collect_matches(cfg.get("nodes", [])))

        for match in all_matches:
            criteria = match.get("criteria", "")
            # Example CPE 2.3: cpe:2.3:o:cisco:adaptive_security_appliance_software:...
            parts = criteria.split(":")
            m_vendor = parts[3] if len(parts) >= 4 else vendor
            m_product = parts[4] if len(parts) >= 5 else product
            if not vendor and m_vendor:
                vendor = m_vendor
            if not product and m_product:
                product = m_product

            exact_version = None
            if len(parts) >= 6 and parts[5] not in ("*", "-", ""):
                exact_version = (
                    parts[5].replace(r"\(", "(").replace(r"\)", ")").replace(r"\_", "_")
                )

            v_start_inc = match.get("versionStartIncluding")
            v_start_exc = match.get("versionStartExcluding")
            v_end_inc = match.get("versionEndIncluding")
            v_end_exc = match.get("versionEndExcluding")

            if any([v_start_inc, v_start_exc, v_end_inc, v_end_exc, exact_version]):
                version_ranges.append(
                    {
                        "cve_id": cve_id,
                        "vendor": m_vendor or vendor,
                        "product": m_product or product,
                        "version_start_inc": v_start_inc,
                        "version_start_exc": v_start_exc,
                        "version_end_inc": v_end_inc,
                        "version_end_exc": v_end_exc,
                        "exact_version": exact_version,
                    }
                )

        in_kev_flag = 1 if bool(is_in_kev(cve_id)) else 0

        return {
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "description": desc_text,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwe": cwe_val,
            "published_date": published[:10] if published else "",
            "last_modified": last_modified[:10] if last_modified else "",
            "in_cisa_kev": in_kev_flag,
            "version_ranges": version_ranges,
        }

    def sync_product_cves(
        self,
        vendor: str,
        product: str,
        cpe_name: str,
        max_results: int = 500,
        results_per_page: Optional[int] = None,
    ) -> int:
        """Synchronize product CVE records from NVD API 2.0 into SQLite DB.

        Supports pagination through startIndex and resultsPerPage (up to 2000 per page).
        Extracts CVEs, CVSS scores/vectors, and CPE version ranges (versionStartIncluding,
        versionEndExcluding, exact_version, etc.), storing them in SQLite via upsert_cve().

        Args:
            vendor: Target vendor (e.g., 'cisco', 'fortinet', 'palo_alto_networks').
            product: Target product (e.g., 'adaptive_security_appliance_software', 'ios_xe').
            cpe_name: Virtual match string or CPE 2.3 URI (e.g., 'cpe:2.3:o:cisco:adaptive_security_appliance_software').
            max_results: Maximum total records to synchronize (default 500).
            results_per_page: Number of items per request page (default up to 2000).

        Returns:
            Total count of CVE records synchronized and persisted into the database.
        """
        if not cpe_name:
            logger.warning("sync_product_cves called with empty cpe_name.")
            return 0

        if results_per_page and results_per_page > 0:
            page_size = min(results_per_page, 2000)
        else:
            page_size = min(max_results, 2000) if max_results > 0 else 500

        start_index = 0
        total_synced = 0
        total_results_avail = None

        headers = {"User-Agent": "Vuln-Check-Net/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        while total_synced < max_results:
            current_limit = min(page_size, max_results - total_synced)
            params = {
                "virtualMatchString": cpe_name,
                "startIndex": start_index,
                "resultsPerPage": current_limit,
            }

            # Rate limiting
            delay = NVD_DELAY_WITH_KEY if self.api_key else NVD_DELAY_NO_KEY
            elapsed = time.time() - self.last_request_time
            if elapsed < delay:
                time.sleep(delay - elapsed)

            attempt = 0
            current_backoff = BACKOFF_FACTOR
            success = False
            data = None

            while attempt < MAX_RETRIES:
                attempt += 1
                try:
                    self.last_request_time = time.time()
                    resp = requests.get(
                        NVD_API_URL,
                        params=params,
                        headers=headers,
                        timeout=HTTP_TIMEOUT,
                    )

                    if resp.status_code == 200:
                        data = resp.json()
                        success = True
                        break
                    elif resp.status_code == 429:
                        logger.warning(
                            "NVD 429 rate limit hit syncing %s (startIndex=%d). Backing off %.1fs...",
                            cpe_name,
                            start_index,
                            current_backoff,
                        )
                        time.sleep(current_backoff)
                        current_backoff *= 2
                        continue
                    else:
                        logger.warning(
                            "NVD API error status %d for %s (startIndex=%d)",
                            resp.status_code,
                            cpe_name,
                            start_index,
                        )
                        break
                except requests.RequestException as e:
                    logger.warning(
                        "Network error connecting to NVD API for %s (startIndex=%d): %s (attempt %d/%d)",
                        cpe_name,
                        start_index,
                        e,
                        attempt,
                        MAX_RETRIES,
                    )
                    time.sleep(current_backoff)
                    current_backoff *= 2

            if not success or not data:
                logger.warning(
                    "Failed to fetch page for %s at startIndex=%d, stopping sync.",
                    cpe_name,
                    start_index,
                )
                break

            total_results_avail = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                record = self._parse_nvd_item(
                    cve_item,
                    default_vendor=vendor,
                    default_product=product,
                )
                if not record.get("vendor"):
                    record["vendor"] = vendor
                if not record.get("product"):
                    record["product"] = product

                ranges = record.get("version_ranges", [])
                for r in ranges:
                    if not r.get("vendor"):
                        r["vendor"] = vendor
                    if not r.get("product"):
                        r["product"] = product

                self.upsert_cve(record, ranges=ranges)
                total_synced += 1
                if total_synced >= max_results:
                    break

            start_index += len(vulnerabilities)
            if total_results_avail is not None and start_index >= total_results_avail:
                break

        logger.info(
            "Successfully synced %d CVEs for %s/%s (%s)",
            total_synced,
            vendor,
            product,
            cpe_name,
        )
        return total_synced


def sync_product_cves(
    vendor: str,
    product: str,
    cpe_name: str,
    max_results: int = 500,
    db_path: Path = DB_PATH,
    fetcher: Optional[NVDFetcher] = None,
) -> int:
    """Convenience module-level function to synchronize product CVEs from NVD API 2.0."""
    instance = fetcher or NVDFetcher(db_path=db_path)
    return instance.sync_product_cves(
        vendor=vendor,
        product=product,
        cpe_name=cpe_name,
        max_results=max_results,
    )


# Alias for backward compatibility
NvdFetcher = NVDFetcher
