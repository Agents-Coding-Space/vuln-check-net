"""Triage and Correlation Engine for Multi-Vendor Network CVE Audit.

Performs 100% CVE lookup against NVD Database, correlates necessary conditions
(affected OS version range) and sufficient conditions (configuration preconditions),
and classifies vulnerabilities into EXPLOITABLE, MITIGATED, and POTENTIAL.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.config import (
    OS_ARBOR_ARBOS,
    OS_CISCO_ASA,
    OS_CISCO_IOS_CLASSIC,
    OS_CISCO_IOS_XE,
    OS_F5_BIGIP,
    OS_FORTINET_FORTIOS,
    OS_IMPERVA_SECURESPHERE,
    OS_PALOALTO_PANOS,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    STATUS_POTENTIAL,
)
from src.fetcher_cisa import CisaKevFetcher
from src.fetcher_nvd import NVDFetcher, PRODUCT_SYNONYMS
from src.parser import ConfigParser
from src.rules import PRECONDITION_RULES, PreconditionRule
from src.triage import TriageLayer
from src.version_utils import is_version_in_range

logger = logging.getLogger(__name__)


def map_os_to_nvd_vendor_product(vendor: str, os_family: str) -> Tuple[str, str, str]:
    """Map device vendor and OS family to NVD database vendor, product, and version format.

    Args:
        vendor: Detected vendor string (e.g. 'Cisco', 'Fortinet').
        os_family: Detected OS family string (e.g. 'Cisco ASA', 'Fortinet FortiOS').

    Returns:
        Tuple of (nvd_vendor, nvd_product, os_type_hint).
    """
    os_clean = (os_family or "").strip().lower()
    v_clean = (vendor or "").strip().lower()

    if os_clean == OS_CISCO_ASA.lower() or "asa" in os_clean:
        return "cisco", "adaptive_security_appliance_software", "cisco_asa"

    if (
        os_clean == OS_CISCO_IOS_XE.lower()
        or "ios xe" in os_clean
        or "ios_xe" in os_clean
    ):
        return "cisco", "ios_xe", "ios_xe"

    if (
        os_clean == OS_CISCO_IOS_CLASSIC.lower()
        or "ios classic" in os_clean
        or os_clean == "ios"
    ):
        return "cisco", "ios", "ios"

    if (
        os_clean == OS_FORTINET_FORTIOS.lower()
        or "fortios" in os_clean
        or "forti" in os_clean
    ):
        return "fortinet", "fortios", "fortios"

    if (
        os_clean == OS_PALOALTO_PANOS.lower()
        or "pan-os" in os_clean
        or "panos" in os_clean
        or "palo" in os_clean
    ):
        return "palo_alto_networks", "pan-os", "panos"

    if (
        os_clean == OS_F5_BIGIP.lower()
        or "big-ip" in os_clean
        or "bigip" in os_clean
        or "f5" in v_clean
    ):
        return "f5", "big-ip", "semver"

    if (
        os_clean == OS_ARBOR_ARBOS.lower()
        or "arbor" in os_clean
        or "arbos" in os_clean
        or "netscout" in v_clean
    ):
        return "netscout", "arbor_sightline", "semver"

    if (
        os_clean == OS_IMPERVA_SECURESPHERE.lower()
        or "securesphere" in os_clean
        or "imperva" in v_clean
    ):
        return "imperva", "securesphere", "semver"

    # Generic fallbacks
    return v_clean or "unknown", os_clean or "unknown", "semver"


class ScanResult(dict):
    """Rich container for scan output supporting both object and dict-like access."""

    def __init__(
        self,
        device_info: Dict[str, Any],
        summary: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        filename: str = "",
        raw_config: str = "",
    ) -> None:
        super().__init__(
            device_info=device_info,
            summary=summary,
            vulnerabilities=vulnerabilities,
            filename=filename,
            raw_config=raw_config,
        )
        self.device_info = device_info
        self.summary = summary
        self.vulnerabilities = vulnerabilities
        self.filename = filename
        self.raw_config = raw_config

    def to_dict(self) -> Dict[str, Any]:
        """Convert result into standard dictionary."""
        return dict(self)

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)
        if key == "device_info":
            self.device_info = value
        elif key == "summary":
            self.summary = value
        elif key == "vulnerabilities":
            self.vulnerabilities = value
        elif key == "filename":
            self.filename = value
        elif key == "raw_config":
            self.raw_config = value
        else:
            setattr(self, key, value)

    def __repr__(self) -> str:
        hostname = self.device_info.get("hostname", "UNKNOWN")
        total_vulns = len(self.vulnerabilities)
        exp = self.summary.get("exploitable_count", 0)
        return (
            f"<ScanResult host={hostname} total_vulns={total_vulns} exploitable={exp}>"
        )


class CorrelationEngine:
    """Core triage & correlation engine assessing network CVEs against configuration context."""

    def __init__(
        self,
        cisa_fetcher: Optional[CisaKevFetcher] = None,
        nvd_fetcher: Optional[NVDFetcher] = None,
        rules: Optional[List[PreconditionRule]] = None,
        parser: Optional[ConfigParser] = None,
        triage_layer: Optional[TriageLayer] = None,
    ) -> None:
        self.cisa_fetcher = cisa_fetcher or CisaKevFetcher()
        self.nvd_fetcher = nvd_fetcher or NVDFetcher()
        self.rules = rules or PRECONDITION_RULES
        self.rule_map: Dict[str, PreconditionRule] = {
            r.cve_id.strip().upper(): r for r in self.rules
        }
        self.parser = parser or ConfigParser()
        self.triage_layer = triage_layer or TriageLayer(rule_registry=self.rule_map)

    def scan_config(self, config_text: str, filename: str = "") -> ScanResult:
        """Scan raw network device configuration and triage 100% of applicable NVD CVEs.

        Args:
            config_text: Full running configuration text.
            filename: Optional source configuration filename.

        Returns:
            ScanResult containing full audit summary, device metadata, and evaluated CVEs.
        """
        parsed = self.parser.parse(config_text)
        return self.evaluate_device(parsed, config_text=config_text, filename=filename)

    def evaluate_device(
        self,
        parsed_config: Dict[str, Any],
        config_text: str = "",
        filename: str = "",
    ) -> ScanResult:
        """Perform full correlation audit on a parsed network device configuration.

        Queries 100% of CVEs from NVD database for the device product, filters
        those whose version ranges affect the device, and applies the Triage Layer
        to classify them as EXPLOITABLE, MITIGATED, or POTENTIAL.

        Args:
            parsed_config: Output dictionary from ConfigParser.parse().
            config_text: Optional raw configuration text for evidence extraction.
            filename: Optional source filename.

        Returns:
            ScanResult instance with complete audit report.
        """
        vendor = parsed_config.get("vendor", "Unknown")
        os_family = parsed_config.get("os_family", "Unknown")
        version = parsed_config.get("version", "")
        features = parsed_config.get("features", {})
        hostname = parsed_config.get("hostname", "UNKNOWN")
        model = parsed_config.get("model", "Unknown")
        domain_name = parsed_config.get("domain_name", "")

        # Map device to NVD product and version format hint
        nvd_vendor, nvd_product, os_type = map_os_to_nvd_vendor_product(
            vendor, os_family
        )

        # 1. Query full CVE set from NVD database
        nvd_cves = self.nvd_fetcher.get_cves_by_product(nvd_vendor, nvd_product)
        cve_candidates: Dict[str, Dict[str, Any]] = {
            c["cve_id"].strip().upper(): c for c in nvd_cves
        }

        # 2. Merge any curated rule for this OS family if not already present
        for rule in self.rules:
            if self._is_os_match(rule.os_family, os_family):
                cve_id_clean = rule.cve_id.strip().upper()
                if cve_id_clean not in cve_candidates:
                    cve_candidates[cve_id_clean] = {
                        "cve_id": rule.cve_id,
                        "vendor": rule.vendor,
                        "product": nvd_product,
                        "description": rule.description,
                        "cvss_score": rule.cvss_base,
                        "cvss_vector": "",
                        "cwe": "",
                        "published_date": "",
                        "last_modified": "",
                        "in_cisa_kev": 1 if rule.in_kev else 0,
                        "version_ranges": [],
                    }

        # Allowed product synonyms for filtering CPE version ranges
        synonyms = PRODUCT_SYNONYMS.get(nvd_product, [nvd_product])
        allowed_products = {p.strip().lower() for p in synonyms}

        evaluated_vulns: List[Dict[str, Any]] = []

        total_cves_checked = len(cve_candidates)
        total_affected = 0
        exploitable_count = 0
        mitigated_count = 0
        potential_count = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        kev_count = 0

        for cve_id, cve_item in cve_candidates.items():
            rule = self.rule_map.get(cve_id)

            # Condition 1 (Necessary): Is device version in affected range?
            version_affected = False

            # Check curated rule version logic if rule exists and matches OS
            if rule and self._is_os_match(rule.os_family, os_family):
                if rule.is_version_affected(version):
                    version_affected = True

            # Also check NVD version ranges
            if not version_affected:
                ranges = cve_item.get("version_ranges", [])
                for r in ranges:
                    r_prod = (r.get("product") or "").strip().lower()
                    if allowed_products and r_prod and r_prod not in allowed_products:
                        continue
                    if is_version_in_range(
                        version,
                        v_start_inc=r.get("version_start_inc"),
                        v_start_exc=r.get("version_start_exc"),
                        v_end_inc=r.get("version_end_inc"),
                        v_end_exc=r.get("version_end_exc"),
                        exact_version=r.get("exact_version"),
                        os_type=os_type,
                    ):
                        version_affected = True
                        break

            if not version_affected:
                continue

            total_affected += 1

            # Condition 2: Run Triage Layer
            triage_res = self.triage_layer.evaluate(
                cve_item=cve_item,
                features=features,
                config_text=config_text,
            )
            status = triage_res.status
            feature_evidence = triage_res.feature_evidence
            mitigation_reason = triage_res.mitigation_reason
            precondition_met = triage_res.precondition_met

            # Enrich with NVD details and CVSS scores
            cvss_score = float(
                cve_item.get("cvss_score") or getattr(rule, "cvss_base", 0.0) or 0.0
            )
            cvss_vector = cve_item.get("cvss_vector") or ""
            description = cve_item.get("description") or getattr(
                rule, "description", ""
            )
            title = (
                getattr(rule, "title", None)
                or f"{cve_id} - {cve_item.get('product', nvd_product)} Vulnerability"
            )
            affected_versions = (
                getattr(rule, "affected_version_description", "")
                or "Identified via NVD CPE Version Range"
            )
            references = getattr(rule, "references", None) or [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            ]
            mitigation_cmd = (
                getattr(rule, "mitigation_cmd", "") or triage_res.mitigation_cmd
            )

            # Enrich with CISA KEV data
            in_kev, kev_record = self.cisa_fetcher.is_in_kev(cve_id)
            if not in_kev and cve_item.get("in_cisa_kev"):
                in_kev = True
            if not in_kev and rule and rule.in_kev:
                in_kev = True

            kev_data = {}
            if in_kev:
                kev_count += 1
                if kev_record:
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
                else:
                    kev_data = {
                        "vulnerability_name": title,
                        "date_added": "CISA KEV Catalog",
                        "required_action": "Apply vendor mitigation or upgrade OS",
                        "due_date": "",
                        "ransomware_campaign": "Reported active exploitation",
                        "notes": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }

            # Calculate Operational Real Risk Rating
            real_risk = self._calculate_real_risk(
                status=status,
                cvss_score=cvss_score,
                in_kev=in_kev,
            )

            # Update statistical counters
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
            elif status == STATUS_MITIGATED:
                mitigated_count += 1
                low_count += 1
            else:  # POTENTIAL
                potential_count += 1
                if real_risk == RISK_CRITICAL:
                    critical_count += 1
                elif real_risk == RISK_HIGH:
                    high_count += 1
                elif real_risk == RISK_MEDIUM:
                    medium_count += 1
                else:
                    low_count += 1

            vuln_entry = {
                "cve_id": cve_id,
                "title": title,
                "vendor": getattr(rule, "vendor", None)
                or cve_item.get("vendor", vendor),
                "product": cve_item.get("product", nvd_product),
                "os_family": os_family,
                "status": status,
                "triage_status": status,
                "real_risk": real_risk,
                "base_score": cvss_score,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cwe": cve_item.get("cwe", ""),
                "in_kev": in_kev,
                "in_cisa_kev": in_kev,
                "kev_details": kev_data,
                "precondition_description": triage_res.precondition_name,
                "precondition_met": precondition_met,
                "feature_evidence": feature_evidence,
                "mitigation_reason": mitigation_reason,
                "mitigation_cmd": mitigation_cmd,
                "description": description,
                "affected_versions": affected_versions,
                "references": references,
            }
            evaluated_vulns.append(vuln_entry)

        # Sort: EXPLOITABLE first (0), POTENTIAL next (1), MITIGATED last (2); then by base_score descending
        status_priority = {
            STATUS_EXPLOITABLE: 0,
            STATUS_POTENTIAL: 1,
            STATUS_MITIGATED: 2,
        }
        evaluated_vulns.sort(
            key=lambda x: (
                status_priority.get(x["status"], 3),
                -x["base_score"],
            )
        )

        device_info_dict = {
            "hostname": hostname,
            "domain_name": domain_name,
            "vendor": vendor,
            "os_family": os_family,
            "version": version,
            "model": model,
            "features": features,
            "filename": filename,
        }

        summary_dict = {
            "total_rules_evaluated": total_cves_checked,
            "total_cves_checked": total_cves_checked,
            "total_affected_versions": total_affected,
            "exploitable_count": exploitable_count,
            "mitigated_count": mitigated_count,
            "potential_count": potential_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "in_kev_count": kev_count,
        }

        return ScanResult(
            device_info=device_info_dict,
            summary=summary_dict,
            vulnerabilities=evaluated_vulns,
            filename=filename,
            raw_config=config_text,
        )

    def evaluate_version_only(
        self, vendor: str, os_family: str, version: str
    ) -> List[Dict[str, Any]]:
        """Evaluate vulnerabilities purely by OS version when no config is supplied.

        Queries the full NVD product database, identifies affected CVEs,
        and marks them as POTENTIAL (Affected by Version).
        """
        nvd_vendor, nvd_product, os_type = map_os_to_nvd_vendor_product(
            vendor, os_family
        )

        nvd_cves = self.nvd_fetcher.get_cves_by_product(nvd_vendor, nvd_product)
        cve_candidates: Dict[str, Dict[str, Any]] = {
            c["cve_id"].strip().upper(): c for c in nvd_cves
        }

        # Merge curated rules
        for rule in self.rules:
            if self._is_os_match(rule.os_family, os_family):
                cve_id_clean = rule.cve_id.strip().upper()
                if cve_id_clean not in cve_candidates:
                    cve_candidates[cve_id_clean] = {
                        "cve_id": rule.cve_id,
                        "vendor": rule.vendor,
                        "product": nvd_product,
                        "description": rule.description,
                        "cvss_score": rule.cvss_base,
                        "cvss_vector": "",
                        "cwe": "",
                        "in_cisa_kev": 1 if rule.in_kev else 0,
                        "version_ranges": [],
                    }

        synonyms = PRODUCT_SYNONYMS.get(nvd_product, [nvd_product])
        allowed_products = {p.strip().lower() for p in synonyms}

        results: List[Dict[str, Any]] = []

        for cve_id, cve_item in cve_candidates.items():
            rule = self.rule_map.get(cve_id)
            version_affected = False

            if rule and self._is_os_match(rule.os_family, os_family):
                if rule.is_version_affected(version):
                    version_affected = True

            if not version_affected:
                for r in cve_item.get("version_ranges", []):
                    r_prod = (r.get("product") or "").strip().lower()
                    if allowed_products and r_prod and r_prod not in allowed_products:
                        continue
                    if is_version_in_range(
                        version,
                        v_start_inc=r.get("version_start_inc"),
                        v_start_exc=r.get("version_start_exc"),
                        v_end_inc=r.get("version_end_inc"),
                        v_end_exc=r.get("version_end_exc"),
                        exact_version=r.get("exact_version"),
                        os_type=os_type,
                    ):
                        version_affected = True
                        break

            if not version_affected:
                continue

            cvss_score = float(
                cve_item.get("cvss_score") or getattr(rule, "cvss_base", 0.0) or 0.0
            )
            in_kev, _ = self.cisa_fetcher.is_in_kev(cve_id)
            if not in_kev and (
                cve_item.get("in_cisa_kev") or getattr(rule, "in_kev", False)
            ):
                in_kev = True

            title = (
                getattr(rule, "title", None)
                or f"{cve_id} - {cve_item.get('product', nvd_product)} Vulnerability"
            )
            affected_versions = (
                getattr(rule, "affected_version_description", "")
                or "Identified via NVD CPE Range"
            )
            pre_desc = getattr(
                rule,
                "precondition_description",
                "Requires running configuration for triage evaluation",
            )
            mit_cmd = getattr(rule, "mitigation_cmd", "# Review device configuration")
            desc = cve_item.get("description") or getattr(rule, "description", "")

            results.append(
                {
                    "cve_id": cve_id,
                    "title": title,
                    "status": "POTENTIAL (Config Needed)",
                    "triage_status": STATUS_POTENTIAL,
                    "real_risk": self._calculate_real_risk(
                        status=STATUS_EXPLOITABLE,
                        cvss_score=cvss_score,
                        in_kev=in_kev,
                    ),
                    "base_score": cvss_score,
                    "cvss_score": cvss_score,
                    "in_kev": in_kev,
                    "in_cisa_kev": in_kev,
                    "precondition_description": pre_desc,
                    "mitigation_cmd": mit_cmd,
                    "description": desc,
                    "affected_versions": affected_versions,
                }
            )

        results.sort(key=lambda x: -x["base_score"])
        return results

    def _is_os_match(self, rule_os: str, device_os: str) -> bool:
        """Check if rule OS family matches device OS family."""
        if not device_os or device_os == "Unknown":
            return False
        return rule_os.strip().lower() == device_os.strip().lower()

    def _calculate_real_risk(self, status: str, cvss_score: float, in_kev: bool) -> str:
        """Compute real operational risk based on triage condition, CVSS score, and KEV."""
        if status == STATUS_MITIGATED:
            # When vulnerable feature is disabled, direct exploitation is prevented
            return RISK_LOW

        if in_kev or cvss_score >= 9.0:
            return RISK_CRITICAL
        elif cvss_score >= 7.0:
            return RISK_HIGH
        elif cvss_score >= 4.0:
            return RISK_MEDIUM
        else:
            return RISK_LOW


# Alias for Triage Engine
TriageEngine = CorrelationEngine


def scan_config(config_text: str, filename: str = "") -> ScanResult:
    """Convenience module function to scan and triage device configuration.

    Args:
        config_text: Raw network device configuration text.
        filename: Optional source file name.

    Returns:
        ScanResult containing parsed metadata and triaged CVEs.
    """
    engine = CorrelationEngine()
    return engine.scan_config(config_text=config_text, filename=filename)
