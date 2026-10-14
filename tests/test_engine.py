"""Unit tests for CorrelationEngine."""

import pytest
from src.config import (
    OS_CISCO_ASA,
    OS_CISCO_IOS_XE,
    OS_FORTINET_FORTIOS,
    OS_PALOALTO_PANOS,
    RISK_CRITICAL,
    RISK_LOW,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    VENDOR_CISCO,
    VENDOR_FORTINET,
    VENDOR_PALOALTO,
)
from src.engine import CorrelationEngine


@pytest.fixture
def engine():
    return CorrelationEngine()


def test_correlation_exploitable_when_precondition_met(engine):
    # IOS XE 17.3.1 with http_server=True should trigger CVE-2023-20198 as EXPLOITABLE
    mock_dev = {
        "vendor": VENDOR_CISCO,
        "os_family": OS_CISCO_IOS_XE,
        "version": "17.3.1",
        "hostname": "EDGE-ROUTER",
        "model": "ASR1001-X",
        "domain_name": "lab.local",
        "features": {
            "http_server": True,
            "snmp_server": False,
            "smart_install": False,
        },
    }
    report = engine.evaluate_device(mock_dev)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2023-20198" in vulns
    v_item = vulns["CVE-2023-20198"]
    assert v_item["status"] == STATUS_EXPLOITABLE
    assert v_item["real_risk"] == RISK_CRITICAL
    assert v_item["in_kev"] is True
    assert v_item["precondition_met"] is True


def test_correlation_mitigated_when_precondition_disabled(engine):
    # IOS XE 17.3.1 with http_server=False should mark CVE-2023-20198 as MITIGATED
    mock_dev = {
        "vendor": VENDOR_CISCO,
        "os_family": OS_CISCO_IOS_XE,
        "version": "17.3.1",
        "hostname": "EDGE-ROUTER",
        "model": "ASR1001-X",
        "domain_name": "lab.local",
        "features": {
            "http_server": False,
            "snmp_server": False,
            "smart_install": False,
        },
    }
    report = engine.evaluate_device(mock_dev)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2023-20198" in vulns
    v_item = vulns["CVE-2023-20198"]
    assert v_item["status"] == STATUS_MITIGATED
    assert v_item["real_risk"] == RISK_LOW
    assert v_item["precondition_met"] is False


def test_correlation_fortinet_ssl_vpn(engine):
    # FortiOS 7.2.4 with ssl_vpn=True
    mock_dev = {
        "vendor": VENDOR_FORTINET,
        "os_family": OS_FORTINET_FORTIOS,
        "version": "7.2.4",
        "hostname": "FGT-01",
        "model": "FG-100F",
        "features": {
            "ssl_vpn": True,
            "http_server": False,
        },
    }
    report = engine.evaluate_device(mock_dev)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    # CVE-2024-21762 & CVE-2023-27997 affect 7.2.4
    assert "CVE-2024-21762" in vulns
    assert vulns["CVE-2024-21762"]["status"] == STATUS_EXPLOITABLE
    assert "CVE-2023-27997" in vulns
    assert vulns["CVE-2023-27997"]["status"] == STATUS_EXPLOITABLE


def test_correlation_panos_globalprotect(engine):
    # PAN-OS 10.2.3 with ssl_vpn=True (GlobalProtect)
    mock_dev = {
        "vendor": VENDOR_PALOALTO,
        "os_family": OS_PALOALTO_PANOS,
        "version": "10.2.3",
        "hostname": "PA-500",
        "features": {
            "ssl_vpn": True,
            "http_server": True,
        },
    }
    report = engine.evaluate_device(mock_dev)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2024-3400" in vulns
    assert vulns["CVE-2024-3400"]["status"] == STATUS_EXPLOITABLE
    assert vulns["CVE-2024-3400"]["real_risk"] == RISK_CRITICAL


def test_evaluate_version_only(engine):
    results = engine.evaluate_version_only(
        vendor=VENDOR_CISCO,
        os_family=OS_CISCO_ASA,
        version="9.20(3)",
    )
    cve_ids = [r["cve_id"] for r in results]
    assert "CVE-2024-20353" in cve_ids
