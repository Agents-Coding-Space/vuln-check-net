"""Integration test scanning real network device running-config files."""

from pathlib import Path
import openpyxl
import pytest

from src.config import (
    OS_ARBOR_ARBOS,
    OS_CISCO_ASA,
    OS_CISCO_IOS_XE,
    OS_F5_BIGIP,
    OS_FORTINET_FORTIOS,
    OS_IMPERVA_SECURESPHERE,
    OS_PALOALTO_PANOS,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    VENDOR_CISCO,
    VENDOR_F5,
    VENDOR_FORTINET,
    VENDOR_IMPERVA,
    VENDOR_NETSCOUT,
    VENDOR_PALOALTO,
)
from src.engine import CorrelationEngine
from src.parser import ConfigParser
from src.reporter import Reporter

ASA_CONFIG_PATH = Path("F:/WORK/NCS_Downloads/Network config/Firewall ASA1.txt")
CISCO_IOS_XE_PATH = Path("F:/WORK/NCS_Downloads/cisco_ios_xe_sample_config.txt")
FORTIGATE_PATH = Path("F:/WORK/NCS_Downloads/fortigate_fortios_sample_config.txt")
PALOALTO_PATH = Path("F:/WORK/NCS_Downloads/paloalto_panos_sample_config.txt")
F5_BIGIP_PATH = Path("F:/WORK/NCS_Downloads/f5_bigip_asm_waf_sample_config.txt")
ARBOR_PATH = Path("F:/WORK/NCS_Downloads/arbor_sightline_tms_sample_config.txt")
IMPERVA_PATH = Path("F:/WORK/NCS_Downloads/imperva_waf_sample_config.txt")


@pytest.mark.skipif(not ASA_CONFIG_PATH.exists(), reason="Real ASA config file not accessible")
def test_real_asa_firewall_audit():
    with open(ASA_CONFIG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    # 1. Parse configuration
    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["hostname"] == "MCC-ASA"
    assert parsed["vendor"] == VENDOR_CISCO
    assert parsed["os_family"] == OS_CISCO_ASA
    assert parsed["version"] == "9.20(3)"
    assert parsed["model"] == "FPR-3105"
    assert parsed["domain_name"] == "VNMCC.local"

    features = parsed["features"]
    assert features["http_server"] is True
    assert features["http_outside"] is True
    assert features["webvpn"] is False
    assert features["snmp_server"] is False

    # 2. Correlate with Engine
    engine = CorrelationEngine()
    audit_report = engine.evaluate_device(parsed)

    summary = audit_report["summary"]
    assert summary["total_affected_versions"] >= 1
    assert summary["exploitable_count"] >= 1
    assert summary["in_kev_count"] >= 1

    vulns = {v["cve_id"]: v for v in audit_report["vulnerabilities"]}
    assert "CVE-2024-20353" in vulns

    line_dancer = vulns["CVE-2024-20353"]
    assert line_dancer["status"] == STATUS_EXPLOITABLE
    assert line_dancer["in_kev"] is True
    assert line_dancer["precondition_met"] is True
    assert line_dancer["real_risk"] == "CRITICAL"

    # 3. Test Reporting
    reporter = Reporter()
    test_md = Path("outputs/test_integration_report.md")
    test_xlsx = Path("outputs/test_integration_report.xlsx")
    test_json = Path("outputs/test_integration_report.json")

    reporter.export_markdown(audit_report, test_md)
    reporter.export_excel(audit_report, test_xlsx)
    reporter.export_json(audit_report, test_json)

    assert test_md.exists() and test_md.stat().st_size > 0
    assert test_xlsx.exists() and test_xlsx.stat().st_size > 0
    assert test_json.exists() and test_json.stat().st_size > 0

    # Validate Excel sheets
    wb = openpyxl.load_workbook(test_xlsx)
    sheet_names = wb.sheetnames
    assert "Executive Summary" in sheet_names
    assert "Vulnerabilities" in sheet_names
    wb.close()

    # Clean up test artifacts
    if test_md.exists():
        test_md.unlink()
    if test_xlsx.exists():
        test_xlsx.unlink()
    if test_json.exists():
        test_json.unlink()


@pytest.mark.skipif(not CISCO_IOS_XE_PATH.exists(), reason="Cisco IOS XE config not accessible")
def test_cisco_ios_xe_sample_audit():
    with open(CISCO_IOS_XE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["vendor"] == VENDOR_CISCO
    assert parsed["os_family"] == OS_CISCO_IOS_XE
    assert parsed["version"] == "17.6"
    assert parsed["hostname"] == "CORE-RTR-HN-01"
    assert parsed["features"]["http_server"] is True

    engine = CorrelationEngine()
    report = engine.evaluate_device(parsed)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2023-20198" in vulns
    assert vulns["CVE-2023-20198"]["status"] == STATUS_EXPLOITABLE
    assert vulns["CVE-2023-20198"]["in_kev"] is True

    assert "CVE-2023-20273" in vulns
    assert vulns["CVE-2023-20273"]["status"] == STATUS_EXPLOITABLE
    assert vulns["CVE-2023-20273"]["in_kev"] is True


@pytest.mark.skipif(not FORTIGATE_PATH.exists(), reason="FortiGate config not accessible")
def test_fortigate_fortios_sample_audit():
    with open(FORTIGATE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["vendor"] == VENDOR_FORTINET
    assert parsed["os_family"] == OS_FORTINET_FORTIOS
    assert parsed["version"] == "7.4.2"
    assert parsed["hostname"] == "FGT-DC-PERIMETER-01"
    assert parsed["model"] == "FG200F"

    engine = CorrelationEngine()
    report = engine.evaluate_device(parsed)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2024-21762" in vulns
    assert vulns["CVE-2024-21762"]["status"] == STATUS_MITIGATED


@pytest.mark.skipif(not PALOALTO_PATH.exists(), reason="Palo Alto config not accessible")
def test_paloalto_panos_sample_audit():
    with open(PALOALTO_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["vendor"] == VENDOR_PALOALTO
    assert parsed["os_family"] == OS_PALOALTO_PANOS
    assert parsed["version"] == "11.0.2"
    assert parsed["hostname"] == "PA-3220-EDGE-FW01"
    assert parsed["model"] == "PA-3220"

    features = parsed["features"]
    assert features["http_server"] is True
    assert features["telnet"] is True
    assert features["snmp_server"] is True
    assert features["ssh"] is True

    engine = CorrelationEngine()
    report = engine.evaluate_device(parsed)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2024-3400" in vulns
    assert vulns["CVE-2024-3400"]["status"] == STATUS_MITIGATED


@pytest.mark.skipif(not F5_BIGIP_PATH.exists(), reason="F5 BIG-IP config not accessible")
def test_f5_bigip_sample_audit():
    with open(F5_BIGIP_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["vendor"] == VENDOR_F5
    assert parsed["os_family"] == OS_F5_BIGIP
    assert parsed["version"] == "17.1.1"
    assert parsed["hostname"] == "bigip-waf-prod01.example.vn"

    features = parsed["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True
    assert features["snmp_server"] is True

    engine = CorrelationEngine()
    report = engine.evaluate_device(parsed)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2023-46747" in vulns
    assert vulns["CVE-2023-46747"]["status"] == STATUS_EXPLOITABLE
    assert vulns["CVE-2023-46747"]["in_kev"] is True


@pytest.mark.skipif(not ARBOR_PATH.exists(), reason="Arbor Sightline config not accessible")
def test_arbor_sightline_sample_audit():
    with open(ARBOR_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["vendor"] == VENDOR_NETSCOUT
    assert parsed["os_family"] == OS_ARBOR_ARBOS
    assert parsed["version"] == "9.7.1"
    assert parsed["hostname"] == "arbor-tms-edge-01.example.vn"

    features = parsed["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True
    assert features["snmp_server"] is True
    assert features["bgp"] is True

    engine = CorrelationEngine()
    report = engine.evaluate_device(parsed)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2020-24368" in vulns
    assert vulns["CVE-2020-24368"]["status"] == STATUS_EXPLOITABLE
    assert vulns["CVE-2020-24368"]["in_kev"] is True


@pytest.mark.skipif(not IMPERVA_PATH.exists(), reason="Imperva config not accessible")
def test_imperva_securesphere_sample_audit():
    with open(IMPERVA_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["vendor"] == VENDOR_IMPERVA
    assert parsed["os_family"] == OS_IMPERVA_SECURESPHERE
    assert parsed["version"] == "14.7.0.20"
    assert parsed["hostname"] == "impv-mx-hn-01.example.vn"

    features = parsed["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True
    assert features["snmp_server"] is True

    engine = CorrelationEngine()
    report = engine.evaluate_device(parsed)
    vulns = {v["cve_id"]: v for v in report["vulnerabilities"]}

    assert "CVE-2023-38646" in vulns
    assert vulns["CVE-2023-38646"]["status"] == STATUS_EXPLOITABLE
    assert vulns["CVE-2023-38646"]["in_kev"] is True
