"""Unit tests for Reporter module including Rich summary table, Breakdown, and Triage filters."""

from pathlib import Path
import pytest
from rich.console import Console

from src.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    STATUS_POTENTIAL,
)
from src.reporter import Reporter


@pytest.fixture
def sample_scan_result():
    return {
        "device_info": {
            "hostname": "EDGE-TEST-ROUTER",
            "domain_name": "lab.security.vn",
            "vendor": "Cisco",
            "os_family": "Cisco IOS XE",
            "version": "17.6.1",
            "model": "ASR-1001-HX",
            "features": {
                "http_server": True,
                "webvpn": False,
                "snmp_server": True,
            },
            "filename": "edge_router.cfg",
        },
        "summary": {
            "total_cves_checked": 500,
            "total_affected_versions": 4,
            "exploitable_count": 2,
            "mitigated_count": 1,
            "potential_count": 1,
            "in_kev_count": 2,
            "critical_count": 1,
            "high_count": 2,
            "medium_count": 1,
            "low_count": 0,
        },
        "vulnerabilities": [
            {
                "cve_id": "CVE-2023-20198",
                "title": "Cisco IOS XE Web UI Privilege Escalation",
                "vendor": "Cisco",
                "product": "ios_xe",
                "os_family": "Cisco IOS XE",
                "status": STATUS_EXPLOITABLE,
                "triage_status": STATUS_EXPLOITABLE,
                "real_risk": RISK_CRITICAL,
                "base_score": 10.0,
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "in_kev": True,
                "precondition_description": "HTTP / HTTPS server enabled",
                "precondition_met": True,
                "feature_evidence": "Config: ip http server | ip http secure-server",
                "mitigation_reason": "Tính năng HTTP Server kích hoạt và phơi nhiễm",
                "mitigation_cmd": "no ip http server",
                "description": "Critical vulnerability in Cisco IOS XE Web UI",
                "affected_versions": "17.6.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"],
            },
            {
                "cve_id": "CVE-2021-1623",
                "title": "Cisco IOS XE SNMP Memory Leak",
                "vendor": "Cisco",
                "product": "ios_xe",
                "os_family": "Cisco IOS XE",
                "status": STATUS_EXPLOITABLE,
                "triage_status": STATUS_EXPLOITABLE,
                "real_risk": RISK_HIGH,
                "base_score": 7.5,
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "in_kev": False,
                "precondition_description": "SNMP Server enabled",
                "precondition_met": True,
                "feature_evidence": "Config: snmp-server community public RO",
                "mitigation_reason": "SNMP Server kích hoạt",
                "mitigation_cmd": "no snmp-server",
                "description": "SNMP service flaw",
                "affected_versions": "17.6.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1623"],
            },
            {
                "cve_id": "CVE-2020-3566",
                "title": "Cisco IOS XE WebVPN Flaw",
                "vendor": "Cisco",
                "product": "ios_xe",
                "os_family": "Cisco IOS XE",
                "status": STATUS_MITIGATED,
                "triage_status": STATUS_MITIGATED,
                "real_risk": RISK_LOW,
                "base_score": 8.6,
                "cvss_score": 8.6,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "in_kev": False,
                "precondition_description": "WebVPN feature enabled",
                "precondition_met": False,
                "feature_evidence": "",
                "mitigation_reason": "Tính năng WebVPN không kích hoạt trong cấu hình",
                "mitigation_cmd": "# Service already disabled",
                "description": "WebVPN memory disclosure",
                "affected_versions": "17.6.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-3566"],
            },
            {
                "cve_id": "CVE-2023-44487",
                "title": "HTTP/2 Rapid Reset Attack",
                "vendor": "Cisco",
                "product": "ios_xe",
                "os_family": "Cisco IOS XE",
                "status": STATUS_POTENTIAL,
                "triage_status": STATUS_POTENTIAL,
                "real_risk": RISK_HIGH,
                "base_score": 7.5,
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "in_kev": True,
                "precondition_description": "Core protocol stack vulnerability",
                "precondition_met": None,
                "feature_evidence": "",
                "mitigation_reason": "Affected by Version; Core OS flaw",
                "mitigation_cmd": "# Upgrade device OS",
                "description": "Rapid reset DDoS attack",
                "affected_versions": "17.6.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
            },
        ],
    }


def test_reporter_get_breakdown(sample_scan_result):
    reporter = Reporter()
    b = reporter.get_breakdown(sample_scan_result)

    assert b["total_cves_checked"] == 500
    assert b["total_nvd_matched"] == 4
    assert b["exploitable_count"] == 2
    assert b["mitigated_count"] == 1
    assert b["potential_count"] == 1
    assert b["kev_count"] == 2
    assert b["critical_count"] == 1
    assert b["high_count"] == 2


def test_reporter_filter_vulnerabilities(sample_scan_result):
    reporter = Reporter()
    vulns = sample_scan_result["vulnerabilities"]

    # 1. Filter: all
    f_all = reporter.filter_vulnerabilities(vulns, filter_triage="all")
    assert len(f_all) == 4
    # EXPLOITABLE items are grouped at the top
    assert f_all[0]["status"] == STATUS_EXPLOITABLE
    assert f_all[1]["status"] == STATUS_EXPLOITABLE

    # 2. Filter: exploitable
    f_exp = reporter.filter_vulnerabilities(vulns, filter_triage="exploitable")
    assert len(f_exp) == 2
    assert all(v["status"] == STATUS_EXPLOITABLE for v in f_exp)

    # 3. Filter: mitigated
    f_mit = reporter.filter_vulnerabilities(vulns, filter_triage="mitigated")
    assert len(f_mit) == 1
    assert f_mit[0]["cve_id"] == "CVE-2020-3566"

    # 4. Filter: potential
    f_pot = reporter.filter_vulnerabilities(vulns, filter_triage="potential")
    assert len(f_pot) == 1
    assert f_pot[0]["cve_id"] == "CVE-2023-44487"

    # 5. Filter: kev_only
    f_kev = reporter.filter_vulnerabilities(vulns, kev_only=True)
    assert len(f_kev) == 2
    assert {v["cve_id"] for v in f_kev} == {"CVE-2023-20198", "CVE-2023-44487"}

    # 6. Combined filter: exploitable + kev_only
    f_comb = reporter.filter_vulnerabilities(vulns, filter_triage="exploitable", kev_only=True)
    assert len(f_comb) == 1
    assert f_comb[0]["cve_id"] == "CVE-2023-20198"


def test_reporter_build_breakdown_table(sample_scan_result):
    reporter = Reporter()
    table = reporter.build_breakdown_table(sample_scan_result)

    assert "Breakdown" in table.title
    col_names = [c.header for c in table.columns]
    assert "Assessment Layer / Metric" in col_names
    assert "Count" in col_names


def test_reporter_build_summary_table(sample_scan_result):
    reporter = Reporter()
    table = reporter.build_summary_table(sample_scan_result)

    col_names = [c.header for c in table.columns]
    assert "CVE ID" in col_names
    assert "Triage" in col_names
    assert "Real Risk" in col_names
    assert "CVSS" in col_names
    assert "CISA KEV" in col_names

    # Check filtering parameter inside table
    t_exp = reporter.build_summary_table(sample_scan_result, filter_triage="exploitable")
    assert "EXPLOITABLE" in t_exp.title


def test_reporter_print_device_audit_console_capture(sample_scan_result):
    reporter = Reporter()
    console = Console(record=True, width=120)

    reporter.print_device_audit(sample_scan_result, console=console)
    output = console.export_text()

    assert "Authoritative Data Source: NIST NVD API 2.0 (Local SQLite Cache) + CISA KEV Feed" in output
    assert "EDGE-TEST-ROUTER" in output
    assert "NVD & Triage Intelligence Breakdown" in output
    assert "[EXPLOITABLE]" in output
    assert "[!] KEV" in output


def test_reporter_markdown_export(sample_scan_result, tmp_path):
    reporter = Reporter()
    out_file = tmp_path / "test_report.md"
    reporter.export_markdown(sample_scan_result, out_file)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    assert "Authoritative Data Source" in content
    assert "Total NVD Matched" in content
    assert "[EXPLOITABLE]" in content
    assert "[!] KEV" in content
    assert "Triage Reason" in content
    assert "Feature Evidence" in content
    assert "Config: ip http server" in content


def test_reporter_excel_export(sample_scan_result, tmp_path):
    import openpyxl

    reporter = Reporter()
    out_file = tmp_path / "test_report.xlsx"
    reporter.export_excel(sample_scan_result, out_file)

    assert out_file.exists()
    wb = openpyxl.load_workbook(out_file)
    ws_vuln = wb["Vulnerabilities"]

    headers = [cell.value for cell in ws_vuln[1]]
    assert "Triage Status" in headers
    assert "CISA KEV ([!] KEV)" in headers

    # Row 2 status check
    status_col_idx = headers.index("Triage Status") + 1
    assert ws_vuln.cell(row=2, column=status_col_idx).value == "[EXPLOITABLE]"
    wb.close()
