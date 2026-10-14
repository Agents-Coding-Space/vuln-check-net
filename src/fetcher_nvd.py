"""NVD (National Vulnerability Database) REST API fetcher and SQLite cache.

Features:
- Persistent SQLite caching in data/vuln_cache.db.
- Pre-seeded local cache for guaranteed offline execution.
- Rate-limiting (0.6s with API key, 6s without key).
- Exponential backoff retry on HTTP 429.
- Graceful fallback when offline.
"""

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

logger = logging.getLogger(__name__)


# Initial seed data for offline reliability
OFFLINE_SEED_DATA: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2020-3452",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Services Read-Only Path Traversal Vulnerability.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "published_date": "2020-07-22",
    },
    {
        "cve_id": "CVE-2020-3187",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Services Path Traversal and Arbitrary File Deletion Vulnerability.",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "published_date": "2020-07-22",
    },
    {
        "cve_id": "CVE-2018-0101",
        "description": "Cisco Adaptive Security Appliance (ASA) SSL VPN WebVPN XML Parser Remote Code Execution and Denial of Service Vulnerability.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2018-01-29",
    },
    {
        "cve_id": "CVE-2020-3580",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Services Cross-Site Scripting Vulnerabilities.",
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "published_date": "2020-10-21",
    },
    {
        "cve_id": "CVE-2023-20269",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Remote Access VPN Unauthorized Access / Brute-Force Vulnerability.",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "published_date": "2023-09-08",
    },
    {
        "cve_id": "CVE-2024-20353",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Web Server Denial of Service Vulnerability (ArcaneDoor / Line Dancer).",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
        "published_date": "2024-04-24",
    },
    {
        "cve_id": "CVE-2024-20358",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Command Injection Vulnerability (ArcaneDoor / Line Runner).",
        "cvss_score": 6.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "published_date": "2024-04-24",
    },
    {
        "cve_id": "CVE-2016-6366",
        "description": "Cisco Adaptive Security Appliance (ASA) SNMP Buffer Overflow Vulnerability (EXTRABACON / Shadow Brokers).",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2016-08-17",
    },
    {
        "cve_id": "CVE-2022-20623",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) AnyConnect SSL VPN Denial of Service Vulnerability.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "published_date": "2022-04-06",
    },
    {
        "cve_id": "CVE-2021-1445",
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Command Injection Vulnerability in CLI parser.",
        "cvss_score": 6.7,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2021-04-28",
    },
    {
        "cve_id": "CVE-2023-20198",
        "description": "Cisco IOS XE Web UI Feature Privilege Escalation Vulnerability leading to arbitrary level 15 user creation.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "published_date": "2023-10-16",
    },
    {
        "cve_id": "CVE-2023-20273",
        "description": "Cisco IOS XE Web UI Command Injection Vulnerability chained with privilege escalation for root access.",
        "cvss_score": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2023-10-23",
    },
    {
        "cve_id": "CVE-2017-6742",
        "description": "Cisco IOS and IOS XE SNMP Subsystem Buffer Overflow Remote Code Execution Vulnerability (Jaguar Tooth).",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2017-06-29",
    },
    {
        "cve_id": "CVE-2018-0171",
        "description": "Cisco IOS and IOS XE Smart Install (SMI) Remote Code Execution and Device Reload Vulnerability (TCP port 4786).",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2018-03-29",
    },
    {
        "cve_id": "CVE-2024-21762",
        "description": "Fortinet FortiOS Out-of-Bounds Write in SSL-VPN web portal allowing unauthenticated remote code execution.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2024-02-09",
    },
    {
        "cve_id": "CVE-2023-27997",
        "description": "Fortinet FortiOS and FortiProxy SSL-VPN Heap Buffer Overflow Vulnerability (XORtigate) allowing unauthenticated RCE.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2023-06-12",
    },
    {
        "cve_id": "CVE-2022-42475",
        "description": "Fortinet FortiOS SSL-VPN Heap Buffer Overflow Vulnerability actively exploited in targeted state-sponsored campaigns.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2022-12-12",
    },
    {
        "cve_id": "CVE-2022-40684",
        "description": "Fortinet FortiOS, FortiProxy, and FortiSwitchManager Authentication Bypass on Administrative Interface (HTTP/HTTPS).",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published_date": "2022-10-10",
    },
    {
        "cve_id": "CVE-2024-3400",
        "description": "Palo Alto Networks PAN-OS GlobalProtect Gateway Arbitrary Command Injection Vulnerability (Operation MidnightEclipse).",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "published_date": "2024-04-12",
    },
    {
        "cve_id": "CVE-2022-0028",
        "description": "Palo Alto Networks PAN-OS URL Filtering Denial of Service Amplification and Reflected Attack Vulnerability.",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
        "published_date": "2022-08-10",
    },
    {
        "cve_id": "CVE-2020-2021",
        "description": "Palo Alto Networks PAN-OS SAML Authentication Bypass Vulnerability when Identity Provider signature validation is disabled.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "published_date": "2020-06-29",
    },
]


class NvdFetcher:
    """Fetcher and SQLite cache manager for NVD vulnerability data."""

    def __init__(self, db_path: Path = DB_PATH, api_key: Optional[str] = None) -> None:
        self.db_path = Path(db_path)
        self.api_key = api_key if api_key is not None else NVD_API_KEY
        self.last_request_time = 0.0
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize SQLite database and seed initial vulnerability data."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
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
            conn.commit()

        # Seed initial entries if table is empty
        self._seed_cache_if_empty()

    def _seed_cache_if_empty(self) -> None:
        """Seed the SQLite database with offline vulnerability records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_cache")
            count = cursor.fetchone()[0]
            if count == 0:
                for item in OFFLINE_SEED_DATA:
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO cve_cache
                        (cve_id, description, cvss_score, cvss_vector, published_date)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item["cve_id"],
                            item["description"],
                            item["cvss_score"],
                            item["cvss_vector"],
                            item["published_date"],
                        ),
                    )
                conn.commit()
                logger.info("Pre-seeded SQLite cache with %d CVE records.", len(OFFLINE_SEED_DATA))

    def get_cve(self, cve_id: str, fetch_remote: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve CVE details from SQLite cache or optionally query remote NVD API.

        Args:
            cve_id: Target CVE ID (e.g., 'CVE-2020-3452').
            fetch_remote: If True and not in cache, try fetching from NVD API.

        Returns:
            Dictionary containing CVE information, or None if not found.
        """
        if not cve_id:
            return None

        normalized_id = cve_id.strip().upper()

        # 1. Check local cache
        cached = self._get_from_cache(normalized_id)
        if cached:
            return cached

        # 2. Query remote NVD API if requested
        if fetch_remote:
            remote_record = self.fetch_cve_from_api(normalized_id)
            if remote_record:
                self.save_cve(
                    cve_id=normalized_id,
                    description=remote_record.get("description", ""),
                    cvss_score=remote_record.get("cvss_score", 0.0),
                    cvss_vector=remote_record.get("cvss_vector", ""),
                    published_date=remote_record.get("published_date", ""),
                )
                return remote_record

        return None

    def _get_from_cache(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up record in SQLite cve_cache table."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT cve_id, description, cvss_score, cvss_vector, published_date, cached_at
                    FROM cve_cache WHERE cve_id = ?
                    """,
                    (cve_id,),
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "cve_id": row["cve_id"],
                        "description": row["description"],
                        "cvss_score": row["cvss_score"],
                        "cvss_vector": row["cvss_vector"],
                        "published_date": row["published_date"],
                        "cached_at": row["cached_at"],
                    }
        except Exception as e:
            logger.error("SQLite query error for %s: %s", cve_id, e)
        return None

    def save_cve(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        cvss_vector: str,
        published_date: str,
    ) -> None:
        """Store or update a CVE record in the SQLite cache."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cve_cache
                    (cve_id, description, cvss_score, cvss_vector, published_date)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (cve_id.upper(), description, cvss_score, cvss_vector, published_date),
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to save CVE %s to SQLite cache: %s", cve_id, e)

    def fetch_cve_from_api(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Query NVD 2.0 REST API with rate limiting and exponential backoff retry.

        Args:
            cve_id: CVE ID string.

        Returns:
            Dictionary with parsed CVE details or None if failed.
        """
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

    def _parse_nvd_item(self, cve_item: Dict[str, Any]) -> Dict[str, Any]:
        """Parse raw NVD JSON item into structured dictionary."""
        cve_id = cve_item.get("id", "")
        published = cve_item.get("published", "")

        # Description
        desc_text = ""
        descriptions = cve_item.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        # CVSS Metrics (prefer v3.1, then v3.0, then v2.0)
        cvss_score = 0.0
        cvss_vector = ""
        metrics = cve_item.get("metrics", {})

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
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

        return {
            "cve_id": cve_id,
            "description": desc_text,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "published_date": published[:10] if published else "",
        }
