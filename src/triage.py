"""Triage Layer and Precondition Evaluators for Network CVE Audit.

Evaluates configuration context (features active/inactive and raw config evidence)
to classify affected CVEs into:
- EXPLOITABLE: Feature is confirmed ENABLED (sufficient condition met).
- MITIGATED: Feature is confirmed DISABLED in configuration.
- POTENTIAL: CVE affects core OS / protocol stack with no specific feature requirement
  or no precondition rule currently modeled (Affected by Version).
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

from src.config import (
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    STATUS_POTENTIAL,
)

logger = logging.getLogger(__name__)


class PreconditionResult(NamedTuple):
    """Result of evaluating a specific feature precondition."""

    is_met: bool
    evidence: str
    reason: str


@dataclass
class TriageResult:
    """Consolidated triage evaluation output for a single CVE."""

    status: str
    precondition_name: str
    precondition_met: Optional[bool]
    feature_evidence: str
    mitigation_reason: str
    mitigation_cmd: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "triage_status": self.status,
            "status": self.status,
            "precondition_name": self.precondition_name,
            "precondition_met": self.precondition_met,
            "feature_evidence": self.feature_evidence,
            "mitigation_reason": self.mitigation_reason,
            "mitigation_cmd": self.mitigation_cmd,
        }


def extract_evidence_lines(
    pattern: str,
    config_text: str,
    max_lines: int = 3,
) -> str:
    """Extract snippet lines from configuration text matching a regex pattern."""
    if not config_text:
        return ""
    matches: List[str] = []
    regex = re.compile(pattern, re.IGNORECASE)
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            continue
        if regex.search(stripped):
            matches.append(stripped)
            if len(matches) >= max_lines:
                break
    return " | ".join(matches)


# ==============================================================================
# PRECONDITION EVALUATORS
# ==============================================================================


def check_webvpn(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for WebVPN, SSL-VPN, and AnyConnect/GlobalProtect."""
    active = bool(features.get("webvpn") or features.get("ssl_vpn"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*webvpn\b|^\s*config\s+vpn\s+ssl\b|set\s+status\s+enable|gateway\s+GlobalProtect|portal\s+GlobalProtect|anyconnect-essentials)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "WebVPN / SSL-VPN service is enabled on device"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng WebVPN/SSL-VPN không kích hoạt trong cấu hình (WebVPN/SSL-VPN disabled)"
        return PreconditionResult(False, "", reason)


def check_http_server(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for HTTP/HTTPS server and Web management UI."""
    active = bool(features.get("http_server") or features.get("http_outside"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*http\s+server\s+enable|^\s*ip\s+http\s+(?:secure-)?server|sys\s+httpd|services\s+http\s+status\s+set\s+enabled|webGuiPort|allowaccess.*https?)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "HTTP/HTTPS Server or Web management interface is enabled"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng HTTP/HTTPS Server hoặc Web UI không kích hoạt trong cấu hình (HTTP/HTTPS Server disabled)"
        return PreconditionResult(False, "", reason)


def check_rest_api(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for REST API, iControl REST, and management APIs."""
    active = bool(features.get("rest_api") or features.get("http_server"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(rest-api|rest_api|icontrol|mgmt-api|^\s*http\s+server\s+enable|sys\s+httpd)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "REST API / HTTP management interface is active"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng REST API không kích hoạt trong cấu hình (REST API disabled)"
        return PreconditionResult(False, "", reason)


def check_ssh(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for SSH administrative access."""
    active = bool(features.get("ssh"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*ip\s+ssh\b|^\s*ssh\s+|allowaccess.*ssh|transport\s+input.*ssh)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "SSH administrative service is active"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng SSH không kích hoạt trong cấu hình (SSH disabled)"
        return PreconditionResult(False, "", reason)


def check_telnet(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for Telnet service."""
    active = bool(features.get("telnet"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*telnet\s+|allowaccess.*telnet|transport\s+input.*telnet)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "Telnet service is active"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng Telnet không kích hoạt trong cấu hình (Telnet disabled)"
        return PreconditionResult(False, "", reason)


def check_snmp(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for SNMP Server service."""
    active = bool(features.get("snmp_server"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*snmp-server\b|^\s*snmp\b|allowaccess.*snmp)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "SNMP Server service is configured and active"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng SNMP không kích hoạt trong cấu hình (SNMP service disabled)"
        return PreconditionResult(False, "", reason)


def check_bgp(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for BGP routing protocol."""
    active = bool(features.get("bgp"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*router\s+bgp\b|config\s+router\s+bgp)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "BGP routing is configured and active"
        return PreconditionResult(True, evidence, "")
    else:
        reason = (
            "Giao thức định tuyến BGP không kích hoạt trong cấu hình (BGP disabled)"
        )
        return PreconditionResult(False, "", reason)


def check_ospf(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for OSPF routing protocol."""
    active = bool(features.get("ospf"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*router\s+ospf\b|config\s+router\s+ospf)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "OSPF routing is configured and active"
        return PreconditionResult(True, evidence, "")
    else:
        reason = (
            "Giao thức định tuyến OSPF không kích hoạt trong cấu hình (OSPF disabled)"
        )
        return PreconditionResult(False, "", reason)


def check_ikev2(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for IKEv2 / IPsec VPN services."""
    active = bool(features.get("ikev2") or features.get("ipsec") or features.get("vpn"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(crypto\s+(?:ikev2|ipsec|isakmp)|config\s+vpn\s+ipsec)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "IKEv2 / IPsec VPN service is configured"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng IKEv2 / IPsec VPN không kích hoạt trong cấu hình (IKEv2/IPsec disabled)"
        return PreconditionResult(False, "", reason)


def check_smart_install(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for Cisco Smart Install (vstack)."""
    active = bool(features.get("smart_install"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*vstack\b)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "Cisco Smart Install (vstack) client is active"
        return PreconditionResult(True, evidence, "")
    else:
        reason = (
            "Tính năng Cisco Smart Install không kích hoạt trong cấu hình (no vstack)"
        )
        return PreconditionResult(False, "", reason)


def check_aaa(
    features: Dict[str, Any],
    config_text: str = "",
) -> PreconditionResult:
    """Precondition evaluator for AAA / SAML authentication."""
    active = bool(features.get("aaa"))
    evidence = ""
    reason = ""

    if config_text:
        ev_lines = extract_evidence_lines(
            r"(^\s*aaa\s+new-model|authentication-profile|services\s+aaa|^\s*aaa\s+authentication)",
            config_text,
        )
        if ev_lines:
            evidence = f"Config: {ev_lines}"
            active = True

    if active:
        if not evidence:
            evidence = "AAA / SAML authentication is configured"
        return PreconditionResult(True, evidence, "")
    else:
        reason = "Tính năng AAA / SAML Authentication không kích hoạt trong cấu hình"
        return PreconditionResult(False, "", reason)


# Precondition Evaluators Dictionary
PRECONDITION_EVALUATORS: Dict[
    str, Callable[[Dict[str, Any], str], PreconditionResult]
] = {
    "webvpn": check_webvpn,
    "ssl_vpn": check_webvpn,
    "http_server": check_http_server,
    "rest_api": check_rest_api,
    "ssh": check_ssh,
    "telnet": check_telnet,
    "snmp": check_snmp,
    "snmp_server": check_snmp,
    "bgp": check_bgp,
    "ospf": check_ospf,
    "ikev2": check_ikev2,
    "ipsec": check_ikev2,
    "smart_install": check_smart_install,
    "aaa": check_aaa,
}


# ==============================================================================
# KEYWORD & CWE PATTERN MATCHING RULES
# ==============================================================================

# Pattern rules mapping CVE descriptions/CWE to specific precondition evaluators
PATTERN_RULES: List[
    Tuple[str, str, str, Callable[[Dict[str, Any], str], PreconditionResult]]
] = [
    # (regex_pattern, feature_key, precondition_description, evaluator_func)
    (
        r"\b(webvpn|ssl[- ]vpn|anyconnect|globalprotect|clientless[- ]vpn|openconnect|remote[- ]access[- ]vpn)\b",
        "webvpn",
        "WebVPN / SSL-VPN or Remote Access VPN enabled",
        check_webvpn,
    ),
    (
        r"\b(rest[- ]api|icontrol[- ]rest|management[- ]api|json[- ]rpc)\b",
        "rest_api",
        "REST API / Management API service active",
        check_rest_api,
    ),
    (
        r"\b(web[- ]ui|web[- ]based|http[- ]server|https[- ]server|web[- ]server|management[- ]interface|web[- ]portal|admin[- ]interface|traffic[- ]management[- ]user[- ]interface|tmui|admin[- ]portal|web[- ]gui|admin[- ]web|web\s+services)\b",
        "http_server",
        "HTTP/HTTPS Server or Web management interface enabled",
        check_http_server,
    ),
    (
        r"\b(smart[- ]install|smi\b|port\s+4786|vstack)\b",
        "smart_install",
        "Cisco Smart Install (vstack) active on TCP 4786",
        check_smart_install,
    ),
    (
        r"\b(snmp|simple network management protocol|extrabacon|jaguar\s+tooth)\b",
        "snmp",
        "SNMP Server service configured and active",
        check_snmp,
    ),
    (
        r"\b(ssh|secure\s+shell)\b",
        "ssh",
        "SSH administrative service enabled",
        check_ssh,
    ),
    (
        r"\b(telnet)\b",
        "telnet",
        "Telnet administrative service enabled",
        check_telnet,
    ),
    (
        r"\b(bgp|border\s+gateway\s+protocol)\b",
        "bgp",
        "BGP routing protocol active",
        check_bgp,
    ),
    (
        r"\b(ospf|open\s+shortest\s+path\s+first)\b",
        "ospf",
        "OSPF routing protocol active",
        check_ospf,
    ),
    (
        r"\b(ikev[12]|internet\s+key\s+exchange|ipsec|ike\s+daemon|isakmp)\b",
        "ikev2",
        "IKE / IPsec VPN service active",
        check_ikev2,
    ),
    (
        r"\b(saml|radius|tacacs\+?|aaa\s+authentication|user\s+authentication)\b",
        "aaa",
        "AAA / SAML authentication service configured",
        check_aaa,
    ),
]


# ==============================================================================
# TRIAGE LAYER ENGINE
# ==============================================================================


class TriageLayer:
    """Evaluates vulnerability context and assigns triage status with supporting evidence."""

    def __init__(self, rule_registry: Optional[Dict[str, Any]] = None) -> None:
        self.rule_registry = rule_registry or {}

    def set_rule_registry(self, rule_registry: Dict[str, Any]) -> None:
        """Update or set the rule registry map."""
        self.rule_registry = rule_registry

    def evaluate(
        self,
        cve_item: Dict[str, Any],
        features: Dict[str, Any],
        config_text: str = "",
    ) -> TriageResult:
        """Perform triage assessment on a version-matched CVE.

        Args:
            cve_item: Vulnerability dictionary (cve_id, description, title, etc.).
            features: Parsed device features dictionary.
            config_text: Optional raw configuration text for evidence extraction.

        Returns:
            TriageResult with status (EXPLOITABLE, MITIGATED, POTENTIAL) and evidence/reason.
        """
        cve_id = cve_item.get("cve_id", "").strip().upper()
        description = cve_item.get("description", "")
        title = cve_item.get("title", "")
        cwe = cve_item.get("cwe", "")
        text_corpus = f"{cve_id} {title} {description} {cwe}".lower()

        # Step 1: Check curated rule registry first (exact CVE ID match)
        rule = self.rule_registry.get(cve_id)
        if rule:
            precondition_desc = getattr(
                rule, "precondition_description", "Precondition Rule"
            )
            mitigation_cmd = getattr(rule, "mitigation_cmd", "")

            # If rule has its own precondition checker function
            checker = getattr(rule, "is_precondition_met", None)
            if callable(checker):
                met = checker(features)
            elif callable(getattr(rule, "precondition_checker", None)):
                met = rule.precondition_checker(features)
            else:
                met = False

            # Extract evidence or reason based on met status
            if met:
                evidence = self._find_evidence_for_rule(cve_id, features, config_text)
                return TriageResult(
                    status=STATUS_EXPLOITABLE,
                    precondition_name=precondition_desc,
                    precondition_met=True,
                    feature_evidence=evidence,
                    mitigation_reason="",
                    mitigation_cmd=mitigation_cmd,
                )
            else:
                reason = f"Tính năng không kích hoạt trong cấu hình ({precondition_desc} disabled)"
                return TriageResult(
                    status=STATUS_MITIGATED,
                    precondition_name=precondition_desc,
                    precondition_met=False,
                    feature_evidence="",
                    mitigation_reason=reason,
                    mitigation_cmd=mitigation_cmd,
                )

        # Step 2: Keyword and CWE pattern matching against NVD vulnerability metadata
        for pattern, feature_key, pre_desc, evaluator in PATTERN_RULES:
            if re.search(pattern, text_corpus, re.IGNORECASE):
                eval_res = evaluator(features, config_text)
                if eval_res.is_met:
                    return TriageResult(
                        status=STATUS_EXPLOITABLE,
                        precondition_name=pre_desc,
                        precondition_met=True,
                        feature_evidence=eval_res.evidence,
                        mitigation_reason="",
                        mitigation_cmd=f"# Review and harden configuration for feature: {feature_key}",
                    )
                else:
                    return TriageResult(
                        status=STATUS_MITIGATED,
                        precondition_name=pre_desc,
                        precondition_met=False,
                        feature_evidence="",
                        mitigation_reason=eval_res.reason,
                        mitigation_cmd="",
                    )

        # Step 3: No specific feature precondition requirement modeled -> POTENTIAL
        return TriageResult(
            status=STATUS_POTENTIAL,
            precondition_name="OS Core / Protocol Stack",
            precondition_met=None,
            feature_evidence="",
            mitigation_reason="Không yêu cầu tính năng đặc thù hoặc chưa có luật cấu hình (Affected by Version only)",
            mitigation_cmd="# Upgrade to a patched release to remediate OS core vulnerability",
        )

    def _find_evidence_for_rule(
        self,
        cve_id: str,
        features: Dict[str, Any],
        config_text: str,
    ) -> str:
        """Find best evidence string for a curated rule."""
        cve_id_clean = cve_id.upper()

        if cve_id_clean in (
            "CVE-2020-3452",
            "CVE-2020-3187",
            "CVE-2020-3580",
            "CVE-2024-20353",
            "CVE-2023-20198",
            "CVE-2023-20273",
            "CVE-2022-40684",
            "CVE-2023-46747",
            "CVE-2020-5902",
            "CVE-2020-24368",
            "CVE-2023-38646",
            "CVE-2022-38753",
        ):
            res = check_http_server(features, config_text)
            return (
                res.evidence
                or "HTTP Server / Web UI service is active in configuration"
            )

        if cve_id_clean in (
            "CVE-2018-0101",
            "CVE-2023-20269",
            "CVE-2022-20623",
            "CVE-2024-21762",
            "CVE-2023-27997",
            "CVE-2022-42475",
            "CVE-2024-3400",
        ):
            res = check_webvpn(features, config_text)
            return res.evidence or "WebVPN / SSL-VPN service is active in configuration"

        if cve_id_clean in ("CVE-2016-6366", "CVE-2017-6742"):
            res = check_snmp(features, config_text)
            return res.evidence or "SNMP service is active in configuration"

        if cve_id_clean == "CVE-2018-0171":
            res = check_smart_install(features, config_text)
            return res.evidence or "Smart Install (vstack) is active in configuration"

        if cve_id_clean in ("CVE-2024-20358", "CVE-2021-1445", "CVE-2020-2021"):
            res = check_aaa(features, config_text)
            return res.evidence or "AAA / SAML authentication service is active"

        if cve_id_clean == "CVE-2022-1388":
            res = check_rest_api(features, config_text)
            return res.evidence or "iControl REST / HTTP management interface is active"

        return "Feature is enabled according to parsed configuration"
