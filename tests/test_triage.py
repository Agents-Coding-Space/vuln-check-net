"""Unit tests for Triage Layer, Precondition Evaluators, and scan_config."""

import pytest
from src.config import (
    OS_CISCO_ASA,
    OS_CISCO_IOS_XE,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    STATUS_POTENTIAL,
    VENDOR_CISCO,
)
from src.engine import CorrelationEngine, ScanResult, scan_config
from src.rules import PRECONDITION_RULES, TriageRuleRegistry, get_rule, get_rules_for_os
from src.triage import (
    TriageLayer,
    TriageResult,
    check_aaa,
    check_bgp,
    check_http_server,
    check_ikev2,
    check_ospf,
    check_rest_api,
    check_smart_install,
    check_snmp,
    check_ssh,
    check_telnet,
    check_webvpn,
)


# ==============================================================================
# 1. PRECONDITION EVALUATOR TESTS
# ==============================================================================

def test_check_webvpn():
    # Enabled via features dict
    res = check_webvpn({"webvpn": True})
    assert res.is_met is True
    assert "WebVPN" in res.evidence

    # Enabled via ssl_vpn feature
    res = check_webvpn({"ssl_vpn": True})
    assert res.is_met is True

    # Enabled via config text
    res = check_webvpn({}, config_text="webvpn\n enable outside\n")
    assert res.is_met is True
    assert "webvpn" in res.evidence.lower()

    # Disabled
    res = check_webvpn({"webvpn": False, "ssl_vpn": False})
    assert res.is_met is False
    assert "không kích hoạt" in res.reason


def test_check_http_server():
    # Enabled via features
    res = check_http_server({"http_server": True})
    assert res.is_met is True
    assert "HTTP" in res.evidence

    # Enabled via config text
    res = check_http_server({}, config_text="http server enable\nhttp 0 0 outside")
    assert res.is_met is True
    assert "http server enable" in res.evidence

    # Disabled
    res = check_http_server({"http_server": False})
    assert res.is_met is False
    assert "không kích hoạt" in res.reason


def test_check_rest_api():
    res = check_rest_api({"rest_api": True})
    assert res.is_met is True

    res = check_rest_api({"http_server": True})
    assert res.is_met is True

    res = check_rest_api({}, config_text="rest-api enable")
    assert res.is_met is True

    res = check_rest_api({"rest_api": False, "http_server": False})
    assert res.is_met is False


def test_check_ssh_and_telnet():
    # SSH
    res_ssh_on = check_ssh({"ssh": True})
    assert res_ssh_on.is_met is True
    res_ssh_off = check_ssh({"ssh": False})
    assert res_ssh_off.is_met is False

    # Telnet
    res_tel_on = check_telnet({"telnet": True})
    assert res_tel_on.is_met is True
    res_tel_off = check_telnet({"telnet": False})
    assert res_tel_off.is_met is False


def test_check_snmp():
    res_on = check_snmp({"snmp_server": True})
    assert res_on.is_met is True

    res_cfg = check_snmp({}, config_text="snmp-server community public RO")
    assert res_cfg.is_met is True

    res_off = check_snmp({"snmp_server": False})
    assert res_off.is_met is False


def test_check_routing_and_crypto():
    # BGP
    assert check_bgp({"bgp": True}).is_met is True
    assert check_bgp({"bgp": False}).is_met is False

    # OSPF
    assert check_ospf({"ospf": True}).is_met is True
    assert check_ospf({"ospf": False}).is_met is False

    # IKEv2 / IPsec
    assert check_ikev2({"ikev2": True}).is_met is True
    assert check_ikev2({"ipsec": True}).is_met is True
    assert check_ikev2({"ikev2": False, "ipsec": False}).is_met is False

    # Smart Install
    assert check_smart_install({"smart_install": True}).is_met is True
    assert check_smart_install({"smart_install": False}).is_met is False

    # AAA
    assert check_aaa({"aaa": True}).is_met is True
    assert check_aaa({"aaa": False}).is_met is False


# ==============================================================================
# 2. TRIAGE LAYER EVALUATE TESTS
# ==============================================================================

def test_triage_layer_curated_rule():
    registry = {r.cve_id.upper(): r for r in PRECONDITION_RULES}
    triage = TriageLayer(rule_registry=registry)

    # CVE-2023-20198 requires http_server
    cve_item = {"cve_id": "CVE-2023-20198", "title": "Cisco IOS XE Web UI"}

    # Feature ON -> EXPLOITABLE
    res_exp = triage.evaluate(cve_item, {"http_server": True})
    assert res_exp.status == STATUS_EXPLOITABLE
    assert res_exp.precondition_met is True
    assert "HTTP" in res_exp.feature_evidence

    # Feature OFF -> MITIGATED
    res_mit = triage.evaluate(cve_item, {"http_server": False})
    assert res_mit.status == STATUS_MITIGATED
    assert res_mit.precondition_met is False
    assert "không kích hoạt" in res_mit.mitigation_reason


def test_triage_layer_keyword_pattern_matching():
    triage = TriageLayer()

    # Generic NVD CVE with WebVPN keyword in description
    vpn_cve = {
        "cve_id": "CVE-2099-9999",
        "title": "Buffer Overflow in WebVPN Portal",
        "description": "A heap overflow vulnerability exists in the WebVPN remote access service.",
        "cwe": "CWE-119",
    }
    # When WebVPN is ON -> EXPLOITABLE
    res1 = triage.evaluate(vpn_cve, {"webvpn": True})
    assert res1.status == STATUS_EXPLOITABLE
    assert res1.precondition_met is True

    # When WebVPN is OFF -> MITIGATED
    res2 = triage.evaluate(vpn_cve, {"webvpn": False})
    assert res2.status == STATUS_MITIGATED
    assert res2.precondition_met is False


def test_triage_layer_core_os_potential():
    triage = TriageLayer()

    # Core OS / Packet processing bug with no special feature requirement
    core_cve = {
        "cve_id": "CVE-2099-1111",
        "title": "IPv6 Fragment Processing Denial of Service",
        "description": "An issue in IPv6 fragment reassembly allows an attacker to cause kernel crash.",
        "cwe": "CWE-399",
    }
    res = triage.evaluate(core_cve, {"http_server": True, "webvpn": True})
    assert res.status == STATUS_POTENTIAL
    assert res.precondition_met is None
    assert "Affected by Version" in res.mitigation_reason


# ==============================================================================
# 3. SCAN RESULT & SCAN_CONFIG INTEGRATION TESTS
# ==============================================================================

SAMPLE_CONFIG_ASA = """
! Cisco ASA Sample Configuration
hostname TEST-EDGE-ASA
domain-name lab.corp
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
http server enable
http 0.0.0.0 0.0.0.0 outside
no webvpn
no snmp-server
ssh 10.0.0.0 255.0.0.0 inside
!
"""


def test_scan_config_full_nvd_lookup():
    result = scan_config(SAMPLE_CONFIG_ASA, filename="asa_sample.cfg")

    assert isinstance(result, ScanResult)
    assert isinstance(result, dict)  # Dict-like compatibility
    assert result.filename == "asa_sample.cfg"

    # Device Info
    info = result.device_info
    assert info["hostname"] == "TEST-EDGE-ASA"
    assert info["vendor"] == VENDOR_CISCO
    assert info["os_family"] == OS_CISCO_ASA

    # Summary
    summary = result.summary
    assert summary["total_cves_checked"] > 100
    assert summary["total_affected_versions"] >= 1
    assert summary["exploitable_count"] >= 1
    assert summary["mitigated_count"] >= 1
    assert summary["potential_count"] >= 1

    # Vulnerabilities
    vulns = result.vulnerabilities
    assert len(vulns) >= 5

    # Check that statuses include EXPLOITABLE, MITIGATED, and POTENTIAL
    statuses = {v["status"] for v in vulns}
    assert STATUS_EXPLOITABLE in statuses
    assert STATUS_MITIGATED in statuses
    assert STATUS_POTENTIAL in statuses

    # Check evidence & reason fields
    for v in vulns:
        assert "triage_status" in v
        assert "feature_evidence" in v
        assert "mitigation_reason" in v
        assert "real_risk" in v
        if v["status"] == STATUS_EXPLOITABLE:
            assert len(v["feature_evidence"]) > 0
        elif v["status"] == STATUS_MITIGATED:
            assert len(v["mitigation_reason"]) > 0


def test_triage_rule_registry_helpers():
    registry = TriageRuleRegistry()
    assert registry.count() == 27

    rule = get_rule("CVE-2024-20353")
    assert rule is not None
    assert "ArcaneDoor" in rule.title

    asa_rules = get_rules_for_os(OS_CISCO_ASA)
    assert len(asa_rules) == 10

    ios_rules = get_rules_for_os(OS_CISCO_IOS_XE)
    assert len(ios_rules) == 4
