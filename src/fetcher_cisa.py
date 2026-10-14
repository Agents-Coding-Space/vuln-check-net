"""CISA Known Exploited Vulnerabilities (KEV) Catalog Fetcher and Cache.

Provides fast offline lookup and optional online catalog updates.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.config import CISA_KEV_CACHE_PATH, CISA_KEV_URL, HTTP_TIMEOUT

logger = logging.getLogger(__name__)


class CisaKevFetcher:
    """Fetcher and local cache manager for CISA KEV catalog."""

    def __init__(self, cache_file: Path = CISA_KEV_CACHE_PATH) -> None:
        self.cache_file = Path(cache_file)
        self._cve_map: Dict[str, Dict[str, Any]] = {}
        self._metadata: Dict[str, Any] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """Load KEV entries from local cache JSON file."""
        if not self.cache_file.exists():
            logger.warning("CISA KEV cache file not found at %s", self.cache_file)
            return

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
                "count": len(self._cve_map),
            }
            logger.info("Loaded %d CISA KEV entries from cache.", len(self._cve_map))
        except Exception as e:
            logger.error("Failed to load CISA KEV cache: %s", e)

    def is_in_kev(self, cve_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if a CVE is in CISA KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2020-3452').

        Returns:
            Tuple of (in_kev: bool, kev_record: Optional[dict]).
        """
        if not cve_id:
            return False, None
        normalized_id = cve_id.strip().upper()
        record = self._cve_map.get(normalized_id)
        if record:
            return True, record
        return False, None

    def search_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a specific CVE record in the KEV catalog."""
        in_kev, record = self.is_in_kev(cve_id)
        return record if in_kev else None

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
        """Fetch the latest CISA KEV catalog from official endpoint and update cache.

        Args:
            force: If True, overwrite local cache even if existing data is present.

        Returns:
            True if catalog was successfully downloaded and cached, False otherwise.
        """
        logger.info("Fetching latest CISA KEV catalog from %s ...", CISA_KEV_URL)
        try:
            resp = requests.get(
                CISA_KEV_URL,
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": "Vuln-Check-Net/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    logger.warning("Fetched CISA KEV response has empty vulnerabilities list.")
                    return False

                # Ensure directory exists and write
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.cache_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

                # Refresh in-memory map
                self._load_cache()
                logger.info(
                    "Successfully updated CISA KEV cache (%d vulnerabilities).",
                    len(self._cve_map),
                )
                return True
            else:
                logger.warning(
                    "CISA KEV fetch failed with status HTTP %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
                return False
        except Exception as e:
            logger.warning("Could not download CISA KEV catalog (offline fallback active): %s", e)
            return False
