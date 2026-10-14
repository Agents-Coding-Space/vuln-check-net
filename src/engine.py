"""Correlation Engine for Multi-Vendor Network CVE Audit.

Evaluates necessary conditions (affected OS version) and sufficient
conditions (feature preconditions enabled) to classify vulnerabilities
into EXPLOITABLE vs MITIGATED.
"""

import logging
from typing import Any, Dict, List, Optional

from src.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_INFO,
    RISK_LOW,
    RISK_MEDIUM,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    STATUS_NOT_AFFECTED,
)
from src.fetcher_cisa import CisaKevFetcher
from src.fetcher_nvd import NvdFetcher
from src.rules import PRECONDITION_RULES, PreconditionRule

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Core assessment engine correlating device configuration with vulnerability rules."""

    def __init__(
        self,
        cisa_fetcher: Optional[CisaKevFetcher] = None,
        nvd_fetcher: Optional[NvdFetcher] = None,
        rules: Optional[List[PreconditionRule]] = None,
    ) -> None:
        self.cisa_fetcher = cisa_fetcher or CisaKevFetcher()
        self.nvd_fetcher = nvd_fetcher or NvdFetcher()
        self.rules = rules or PRECONDITION_RULES

    def evaluate_device(self, parsed_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a full correlation audit on a parsed network device configuration.

        Args:
            parsed_config: Output dictionary from ConfigParser.parse().

        Returns:
            Dictionary containing audit results and statistical summary.
        """
        vendor = parsed_config.get("vendor", "Unknown")
        os_family = parsed_config.get("os_family", "Unknown")
        version = parsed_config.get("version", "")
        features = parsed_config.get("features", {})
        hostname = parsed_config.get("hostname", "UNKNOWN")
        model = parsed_config.get("model", "Unknown")
        domain_name = parsed_config.get("domain_name", "")

        evaluated_vulns: List[Dict[str, Any]] = []

        total_rules = 0
        total_affected = 0
        exploitable_count = 0
        mitigated_count = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        kev_count = 0

        for rule in self.rules:
            # Match vendor and OS family
            if not self._is_os_match(rule.os_family, os_family):
                continue

            total_rules += 1

            # Condition 1 (Necessary): Is version affected?
            version_affected = rule.is_version_affected(version)
            if not version_affected:
                continue

            total_affected += 1

            # Condition 2 (Sufficient): Is precondition feature enabled?
            precondition_met = rule.is_precondition_met(features)
            status = STATUS_EXPLOITABLE if precondition_met else STATUS_MITIGATED

            # Enrich with NVD data (cached/offline)
            nvd_info = self.nvd_fetcher.get_cve(rule.cve_id)
            cvss_base = rule.cvss_base
            cvss_vector = ""
            description = rule.description

            if nvd_info:
                if nvd_info.get("cvss_score"):
                    cvss_base = float(nvd_info["cvss_score"])
                if nvd_info.get("cvss_vector"):
                    cvss_vector = nvd_info["cvss_vector"]
                if nvd_info.get("description"):
                    description = nvd_info["description"]

            # Enrich with CISA KEV data
            in_kev, kev_record = self.cisa_fetcher.is_in_kev(rule.cve_id)
            kev_data = {}
            if in_kev and kev_record:
                kev_count += 1
                kev_data = {
                    "vulnerability_name": kev_record.get("vulnerabilityName", ""),
                    "date_added": kev_record.get("dateAdded", ""),
                    "required_action": kev_record.get("requiredAction", ""),
                    "due_date": kev_record.get("dueDate", ""),
                    "ransomware_campaign": kev_record.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    ),
                    "notes": kev_record.get("notes", ""),
                }

            # Calculate Real Risk Rating based on status, CVSS, and KEV
            real_risk = self._calculate_real_risk(
                status=status,
                cvss_score=cvss_base,
                in_kev=in_kev,
            )

            # Update counters
            if status == STATUS_EXPLOITABLE:
                exploitable_count += 1
                if real_risk == RISK_CRITICAL:
                    critical_count += 1
                elif real_risk == RISK_HIGH:
                    high_count += 1
                elif real_risk == RISK_MEDIUM:
                    medium_count += 1
                else:
                    low_count += 1
            else:
                mitigated_count += 1
                low_count += 1

            vuln_entry = {
                "cve_id": rule.cve_id,
                "title": rule.title,
                "vendor": rule.vendor,
                "os_family": rule.os_family,
                "status": status,
                "real_risk": real_risk,
                "base_score": cvss_base,
                "cvss_vector": cvss_vector,
                "in_kev": in_kev,
                "kev_details": kev_data,
                "precondition_description": rule.precondition_description,
                "precondition_met": precondition_met,
                "mitigation_cmd": rule.mitigation_cmd,
                "description": description,
                "affected_versions": rule.affected_version_description,
                "references": rule.references,
            }
            evaluated_vulns.append(vuln_entry)

        # Sort: EXPLOITABLE first, then by base_score descending
        evaluated_vulns.sort(
            key=lambda x: (
                0 if x["status"] == STATUS_EXPLOITABLE else 1,
                -x["base_score"],
            )
        )

        return {
            "device_info": {
                "hostname": hostname,
                "domain_name": domain_name,
                "vendor": vendor,
                "os_family": os_family,
                "version": version,
                "model": model,
                "features": features,
            },
            "summary": {
                "total_rules_evaluated": total_rules,
                "total_affected_versions": total_affected,
                "exploitable_count": exploitable_count,
                "mitigated_count": mitigated_count,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "in_kev_count": kev_count,
            },
            "vulnerabilities": evaluated_vulns,
        }

    def evaluate_version_only(
        self, vendor: str, os_family: str, version: str
    ) -> List[Dict[str, Any]]:
        """Evaluate vulnerabilities purely by OS version when no config is supplied.

        Status is marked as UNVERIFIED (POTENTIAL) and assumes default worst-case.
        """
        results: List[Dict[str, Any]] = []
        for rule in self.rules:
            if not self._is_os_match(rule.os_family, os_family):
                continue
            if not rule.is_version_affected(version):
                continue

            in_kev, kev_record = self.cisa_fetcher.is_in_kev(rule.cve_id)
            nvd_info = self.nvd_fetcher.get_cve(rule.cve_id)
            cvss_base = nvd_info["cvss_score"] if nvd_info else rule.cvss_base

            results.append(
                {
                    "cve_id": rule.cve_id,
                    "title": rule.title,
                    "status": "POTENTIAL (Config Needed)",
                    "real_risk": self._calculate_real_risk(
                        status=STATUS_EXPLOITABLE, cvss_score=cvss_base, in_kev=in_kev
                    ),
                    "base_score": cvss_base,
                    "in_kev": in_kev,
                    "precondition_description": rule.precondition_description,
                    "mitigation_cmd": rule.mitigation_cmd,
                    "description": rule.description,
                    "affected_versions": rule.affected_version_description,
                }
            )

        results.sort(key=lambda x: -x["base_score"])
        return results

    def _is_os_match(self, rule_os: str, device_os: str) -> bool:
        """Check if rule OS family matches device OS family."""
        if not device_os or device_os == "Unknown":
            return False
        return rule_os.strip().lower() == device_os.strip().lower()

    def _calculate_real_risk(
        self, status: str, cvss_score: float, in_kev: bool
    ) -> str:
        """Compute real operational risk based on condition fulfillment, CVSS, and KEV."""
        if status == STATUS_MITIGATED:
            # If vulnerable feature is disabled, direct exploitation is blocked
            return RISK_LOW

        # If EXPLOITABLE
        if in_kev or cvss_score >= 9.0:
            return RISK_CRITICAL
        elif cvss_score >= 7.0:
            return RISK_HIGH
        elif cvss_score >= 4.0:
            return RISK_MEDIUM
        else:
            return RISK_LOW
