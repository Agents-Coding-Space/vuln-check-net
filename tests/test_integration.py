"""Integration test scanning real network device running-config file."""

import os
from pathlib import Path
import openpyxl
import pytest

from src.config import STATUS_EXPLOITABLE
from src.engine import CorrelationEngine
from src.parser import ConfigParser
from src.reporter import Reporter

REAL_CONFIG_PATH = Path("F:/WORK/NCS_Downloads/Network config/Firewall ASA1.txt")


@pytest.mark.skipif(not REAL_CONFIG_PATH.exists(), reason="Real ASA config file not accessible")
def test_real_asa_firewall_audit():
    with open(REAL_CONFIG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    # 1. Parse configuration
    parser = ConfigParser()
    parsed = parser.parse(config_text)

    assert parsed["hostname"] == "MCC-ASA"
    assert parsed["vendor"] == "Cisco"
    assert parsed["os_family"] == "Cisco ASA"
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
