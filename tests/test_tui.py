"""Pilot tests for Vuln-Check-Net Textual TUI Application."""

from pathlib import Path
import pytest
from textual.widgets import Button, DataTable, Input, Markdown, Static, TabbedContent

from src.config import OUTPUTS_DIR
from src.tui.app import VulnCheckApp

ASA_PATH = Path("F:/WORK/NCS_Downloads/Network config/Firewall ASA1.txt")
IOS_XE_PATH = Path("F:/WORK/NCS_Downloads/cisco_ios_xe_sample_config.txt")


@pytest.mark.asyncio
async def test_tui_app_launch_and_tabs():
    """Verify TUI launches cleanly with default layout and KEV catalog loaded."""
    app = VulnCheckApp()
    async with app.run_test() as pilot:
        tabs = pilot.app.query_one("#main-tabs", TabbedContent)
        assert tabs.active == "tab-audit"

        # Check initial empty state in Tab 1
        audit_table = pilot.app.query_one("#audit-datatable", DataTable)
        assert audit_table.row_count == 0

        # Check KEV catalog preloaded in Tab 3
        kev_table = pilot.app.query_one("#table-kev", DataTable)
        assert kev_table.row_count >= 20


@pytest.mark.asyncio
async def test_tui_audit_sample_asa():
    """Verify loading and auditing ASA Firewall running-config."""
    if not ASA_PATH.exists():
        pytest.skip("ASA configuration sample file not present on filesystem")

    app = VulnCheckApp()
    async with app.run_test() as pilot:
        btn_asa = pilot.app.query_one("#btn-sample-asa", Button)
        btn_asa.press()
        await pilot.pause()

        audit_table = pilot.app.query_one("#audit-datatable", DataTable)
        assert audit_table.row_count >= 1

        meta_card = pilot.app.query_one("#device-metadata-card", Static)
        meta_text = str(meta_card.render())
        assert "MCC-ASA" in meta_text
        assert "Cisco ASA" in meta_text

        metric_exp = pilot.app.query_one("#metric-exploitable", Static)
        assert "EXPLOITABLE" in str(metric_exp.render())

        detail = pilot.app.query_one("#detail-content", Markdown)
        detail_text = detail.source
        assert "CVE-2024-20353" in detail_text
        assert "Precondition" in detail_text
        assert "Mitigation" in detail_text


@pytest.mark.asyncio
async def test_tui_audit_sample_ios_xe():
    """Verify loading and auditing Cisco IOS XE sample configuration."""
    if not IOS_XE_PATH.exists():
        pytest.skip("IOS XE configuration sample file not present on filesystem")

    app = VulnCheckApp()
    async with app.run_test() as pilot:
        btn_ios = pilot.app.query_one("#btn-sample-iosxe", Button)
        btn_ios.press()
        await pilot.pause()

        audit_table = pilot.app.query_one("#audit-datatable", DataTable)
        assert audit_table.row_count >= 2

        meta_card = pilot.app.query_one("#device-metadata-card", Static)
        meta_text = str(meta_card.render())
        assert "Cisco IOS XE" in meta_text

        metric_exp = pilot.app.query_one("#metric-exploitable", Static)
        assert "2" in str(metric_exp.render())


@pytest.mark.asyncio
async def test_tui_version_lookup():
    """Verify Tab 2 Fast Version Lookup functionality."""
    app = VulnCheckApp()
    async with app.run_test() as pilot:
        pilot.app.action_tab_lookup()
        await pilot.pause()
        tabs = pilot.app.query_one("#main-tabs", TabbedContent)
        assert tabs.active == "tab-lookup"

        # Check IOS XE preset
        preset_ios = pilot.app.query_one("#btn-preset-iosxe", Button)
        preset_ios.press()
        await pilot.pause()

        lookup_table = pilot.app.query_one("#table-lookup-vulns", DataTable)
        assert lookup_table.row_count >= 2

        detail = pilot.app.query_one("#lookup-detail-panel", Static)
        detail_text = str(detail.render())
        assert "CVE-2023-20198" in detail_text
        assert "Precondition Required" in detail_text


@pytest.mark.asyncio
async def test_tui_kev_explorer():
    """Verify Tab 3 CISA KEV Explorer search and filtering."""
    app = VulnCheckApp()
    async with app.run_test() as pilot:
        pilot.app.action_tab_kev()
        await pilot.pause()
        tabs = pilot.app.query_one("#main-tabs", TabbedContent)
        assert tabs.active == "tab-kev"

        kev_table = pilot.app.query_one("#table-kev", DataTable)
        total_initial = kev_table.row_count
        assert total_initial >= 20

        # Filter by keyword
        search_input = pilot.app.query_one("#input-kev-search", Input)
        search_input.value = "Fortinet"
        btn_search = pilot.app.query_one("#btn-kev-search", Button)
        btn_search.press()
        await pilot.pause()

        assert 0 < kev_table.row_count < total_initial

        # Reset filter
        btn_reset = pilot.app.query_one("#btn-kev-reset", Button)
        btn_reset.press()
        await pilot.pause()
        assert kev_table.row_count == total_initial

        # Ransomware filter button
        btn_ransom = pilot.app.query_one("#btn-filter-ransomware", Button)
        btn_ransom.press()
        await pilot.pause()
        assert 0 < kev_table.row_count < total_initial

        # Verify KEV detail panel uses Markdown
        kev_detail = pilot.app.query_one("#kev-detail-content", Markdown)
        assert len(kev_detail.source) > 0
        assert "| Thuộc tính KEV | Giá trị |" in kev_detail.source
        assert "| **Mã CVE** |" in kev_detail.source


@pytest.mark.asyncio
async def test_tui_export_actions():
    """Verify report export routines from TUI."""
    if not ASA_PATH.exists():
        pytest.skip("ASA sample file not present")

    app = VulnCheckApp()
    async with app.run_test() as pilot:
        btn_asa = pilot.app.query_one("#btn-sample-asa", Button)
        btn_asa.press()
        await pilot.pause()

        # Export single formats
        btn_md = pilot.app.query_one("#btn-export-md", Button)
        btn_md.press()
        await pilot.pause()

        btn_json = pilot.app.query_one("#btn-export-json", Button)
        btn_json.press()
        await pilot.pause()

        # Export all shortcut action
        pilot.app.action_export_all()
        await pilot.pause()

        md_file = OUTPUTS_DIR / "MCC-ASA_report.md"
        json_file = OUTPUTS_DIR / "MCC-ASA_report.json"
        xlsx_file = OUTPUTS_DIR / "MCC-ASA_report.xlsx"

        assert md_file.exists() and md_file.stat().st_size > 0
        assert json_file.exists() and json_file.stat().st_size > 0
        assert xlsx_file.exists() and xlsx_file.stat().st_size > 0

        # Cleanup test outputs
        for f in (md_file, json_file, xlsx_file):
            if f.exists():
                f.unlink()


@pytest.mark.asyncio
async def test_tui_initial_file_param():
    """Verify initializing TUI with an initial configuration file parameter."""
    if not ASA_PATH.exists():
        pytest.skip("ASA sample file not present")

    app = VulnCheckApp(initial_file=str(ASA_PATH))
    async with app.run_test() as pilot:
        await pilot.pause()
        audit_table = pilot.app.query_one("#audit-datatable", DataTable)
        assert audit_table.row_count >= 1

        inp = pilot.app.query_one("#input-config-path", Input)
        assert inp.value == str(ASA_PATH)


@pytest.mark.asyncio
async def test_tui_nonexistent_file():
    """Verify handling of nonexistent file path gracefully with toast and without crashing."""
    app = VulnCheckApp()
    async with app.run_test() as pilot:
        inp = pilot.app.query_one("#input-config-path", Input)
        inp.value = "F:/does_not_exist.txt"
        btn_scan = pilot.app.query_one("#btn-scan", Button)
        btn_scan.press()
        await pilot.pause()

        # Audit table remains empty and app did not crash
        audit_table = pilot.app.query_one("#audit-datatable", DataTable)
        assert audit_table.row_count == 0

        # Verify toast error notification was recorded
        assert len(pilot.app._notifications) >= 1
        last_toast = list(pilot.app._notifications)[-1]
        assert last_toast.title == "Scan Error"
        assert "not found" in last_toast.message.lower()


@pytest.mark.asyncio
async def test_tui_empty_file(tmp_path):
    """Verify handling of empty configuration file safely (0 finding, metadata empty/UNKNOWN, no crash)."""
    empty_file = tmp_path / "empty_config.txt"
    empty_file.write_text("", encoding="utf-8")

    app = VulnCheckApp()
    async with app.run_test() as pilot:
        inp = pilot.app.query_one("#input-config-path", Input)
        inp.value = str(empty_file)
        btn_scan = pilot.app.query_one("#btn-scan", Button)
        btn_scan.press()
        await pilot.pause()

        # 0 finding in table
        audit_table = pilot.app.query_one("#audit-datatable", DataTable)
        assert audit_table.row_count == 0

        # Metadata card displays UNKNOWN device info
        meta_card = pilot.app.query_one("#device-metadata-card", Static)
        meta_text = str(meta_card.render())
        assert "UNKNOWN" in meta_text

        # 0 exploitable counter
        metric_exp = pilot.app.query_one("#metric-exploitable", Static)
        assert "0" in str(metric_exp.render())

        # Detail panel displays no vulnerabilities message safely
        detail = pilot.app.query_one("#detail-content", Markdown)
        assert "No vulnerabilities" in detail.source


SAMPLE_ASA_CONFIG = """
Serial Number: JMX999999
: Hardware:   ASA5525, 4096 MB RAM
:
ASA Version 9.18(2)
!
hostname EDGE-ASA-TEST
domain-name lab.internal
!
http server enable
http 0.0.0.0 0.0.0.0 outside
webvpn
 enable outside
!
"""

SAMPLE_IOS_XE_CONFIG = """
Current configuration : 5890 bytes
!
version 17.6
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname CORE-IOSXE-TEST
!
ip http server
ip http secure-server
ip http authentication local
!
end
"""


@pytest.mark.asyncio
async def test_tui_self_contained_audit_asa_and_iosxe(tmp_path):
    """Verify ASA and IOS XE audits self-containedly via tmp_path without depending on F: drive."""
    asa_file = tmp_path / "test_asa_config.txt"
    asa_file.write_text(SAMPLE_ASA_CONFIG.strip(), encoding="utf-8")

    iosxe_file = tmp_path / "test_iosxe_config.txt"
    iosxe_file.write_text(SAMPLE_IOS_XE_CONFIG.strip(), encoding="utf-8")

    app = VulnCheckApp()
    async with app.run_test() as pilot:
        # 1. Audit self-contained ASA config
        inp = pilot.app.query_one("#input-config-path", Input)
        inp.value = str(asa_file)
        btn_scan = pilot.app.query_one("#btn-scan", Button)
        btn_scan.press()
        await pilot.pause()

        audit_table = pilot.app.query_one("#audit-datatable", DataTable)
        assert audit_table.row_count >= 1

        meta_card = pilot.app.query_one("#device-metadata-card", Static)
        meta_text = str(meta_card.render())
        assert "EDGE-ASA-TEST" in meta_text
        assert "Cisco ASA" in meta_text

        detail = pilot.app.query_one("#detail-content", Markdown)
        assert "CVE-2024-20353" in detail.source or "CVE-2023-20269" in detail.source
        assert "Precondition" in detail.source
        assert "Mitigation" in detail.source
        assert "| Thuộc tính | Chi tiết |" in detail.source
        assert "| **Trạng thái** |" in detail.source

        # 2. Audit self-contained IOS XE config
        inp.value = str(iosxe_file)
        btn_scan.press()
        await pilot.pause()

        assert audit_table.row_count >= 2
        meta_text_ios = str(meta_card.render())
        assert "CORE-IOSXE-TEST" in meta_text_ios
        assert "Cisco IOS XE" in meta_text_ios

        detail_ios = pilot.app.query_one("#detail-content", Markdown)
        assert "CVE-2023-20198" in detail_ios.source
        assert "Precondition" in detail_ios.source
        assert "Mitigation" in detail_ios.source


@pytest.mark.asyncio
async def test_tui_narrow_terminal_responsiveness():
    """Verify UI mounts cleanly and handles layout on narrow terminal without overflow crash."""
    app = VulnCheckApp()
    async with app.run_test(size=(60, 24)) as pilot:
        # Check initial Audit tab widgets and geometry
        sample_bar = pilot.app.query_one("#quick-samples-bar")
        action_bar = pilot.app.query_one("#config-input-bar")
        assert sample_bar is not None
        assert action_bar is not None
        assert sample_bar.styles.overflow_x == "auto"
        assert action_bar.styles.overflow_x == "auto"
        assert pilot.app.size.width == 60
        assert sample_bar.size.width <= 60

        # Switch to Fast Lookup tab and check responsiveness
        pilot.app.action_tab_lookup()
        await pilot.pause()
        tabs = pilot.app.query_one("#main-tabs", TabbedContent)
        assert tabs.active == "tab-lookup"
        lookup_bar = pilot.app.query_one("#lookup-controls-bar")
        assert lookup_bar is not None
        assert lookup_bar.styles.overflow_x == "auto"
        assert lookup_bar.size.width <= 60

        # Switch to KEV Explorer tab and check responsiveness
        pilot.app.action_tab_kev()
        await pilot.pause()
        assert tabs.active == "tab-kev"
        kev_bar = pilot.app.query_one("#kev-controls-bar")
        assert kev_bar is not None
        assert kev_bar.size.width <= 60

        # Switch back to Lookup tab and verify active state
        pilot.app.action_tab_lookup()
        await pilot.pause()
        assert tabs.active == "tab-lookup"
        assert lookup_bar.size.width <= 60

        # Switch back to Device Audit tab and verify round-trip transition
        pilot.app.action_tab_audit()
        await pilot.pause()
        assert tabs.active == "tab-audit"
        assert sample_bar.size.width <= 60


def test_tui_markdown_detail_tables():
    """Verify markdown table rendering for vulnerability detail and CISA KEV detail panels."""
    app = VulnCheckApp()

    # 1. Test _render_vuln_detail Markdown table
    vuln = {
        "cve_id": "CVE-2024-20353",
        "title": "Cisco ASA WebVPN Denial of Service Vulnerability",
        "status": "EXPLOITABLE",
        "real_risk": "CRITICAL",
        "base_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
        "in_kev": True,
        "vendor": "Cisco",
        "os_family": "Cisco ASA",
        "affected_versions": "< 9.18.4",
        "precondition_description": "WebVPN / SSL VPN enabled on any interface",
        "precondition_met": True,
        "mitigation_cmd": "no webvpn",
        "description": "A vulnerability in the web server of Cisco ASA Software...",
        "references": ["https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssl-dos-g8gmns"],
    }
    dev_info = {
        "vendor": "Cisco",
        "os_family": "Cisco ASA",
        "version": "9.18(2)",
    }
    vuln_md = app._render_vuln_detail(vuln, dev_info)
    assert "| Thuộc tính | Chi tiết |" in vuln_md
    assert "| :--- | :--- |" in vuln_md
    assert "| **Trạng thái** | `EXPLOITABLE` |" in vuln_md
    assert "| **Mức độ Rủi ro** | `CRITICAL` |" in vuln_md
    assert "| **Điểm CVSS v3.1** | `8.6` |" in vuln_md
    assert "| **CISA KEV** | `In CISA KEV` |" in vuln_md
    assert "| **Hãng & OS** | `Cisco (Cisco ASA)` |" in vuln_md
    assert "| **Dải ảnh hưởng** | `< 9.18.4` |" in vuln_md

    # Test non-KEV branch
    vuln_not_kev = dict(vuln, in_kev=False)
    vuln_not_kev_md = app._render_vuln_detail(vuln_not_kev, dev_info)
    assert "| **CISA KEV** | `Not in KEV` |" in vuln_not_kev_md

    # 2. Test _render_kev_detail Markdown table
    kev_record = {
        "cveID": "CVE-2024-20353",
        "vendorProject": "Cisco",
        "product": "Adaptive Security Appliance (ASA)",
        "vulnerabilityName": "Cisco ASA Web Server Denial of Service",
        "dateAdded": "2024-04-24",
        "dueDate": "2024-05-15",
        "knownRansomwareCampaignUse": "Known",
        "requiredAction": "Apply mitigations per vendor instructions or discontinue use.",
        "shortDescription": "Cisco ASA contains a denial of service vulnerability...",
    }
    kev_md = app._render_kev_detail(kev_record)
    assert "| Thuộc tính KEV | Giá trị |" in kev_md
    assert "| :--- | :--- |" in kev_md
    assert "| **Mã CVE** | `CVE-2024-20353` |" in kev_md
    assert "| **Hãng sản xuất** | `Cisco` |" in kev_md
    assert "| **Sản phẩm** | `Adaptive Security Appliance (ASA)` |" in kev_md
    assert "| **Ngày công bố KEV** | `2024-04-24` |" in kev_md
    assert "| **Hạn chót xử lý** | `2024-05-15` |" in kev_md
    assert "| **Chiến dịch Ransomware** | `Known` |" in kev_md

