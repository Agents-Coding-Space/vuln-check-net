"""Report generation module for Vuln-Check-Net.

Exports security assessment results into:
- Markdown (.md)
- Microsoft Excel (.xlsx) with corporate styling & conditional formatting
- Machine-readable JSON (.json)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Union

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from src.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
)


class Reporter:
    """Generates vulnerability assessment reports in Markdown, Excel, and JSON formats."""

    def __init__(self) -> None:
        pass

    def _normalize_results(
        self, scan_results: Union[Dict[str, Any], List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Normalize input scan_results into a list of device audit reports."""
        if isinstance(scan_results, dict):
            return [scan_results]
        return scan_results

    # =========================================================================
    # 1. MARKDOWN EXPORT
    # =========================================================================

    def export_markdown(
        self,
        scan_results: Union[Dict[str, Any], List[Dict[str, Any]]],
        output_path: Union[str, Path],
    ) -> str:
        """Export audit report to Markdown format.

        Args:
            scan_results: Single report dict or list of reports.
            output_path: Target .md file path.

        Returns:
            The output file path as string.
        """
        devices = self._normalize_results(scan_results)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines: List[str] = []
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines.append("# Network Device CVE & Configuration Audit Report")
        lines.append(f"*Generated on: {now_str} by Vuln-Check-Net Engine*\n")
        lines.append("---")

        for idx, dev in enumerate(devices, 1):
            info = dev.get("device_info", {})
            summary = dev.get("summary", {})
            vulns = dev.get("vulnerabilities", [])
            features = info.get("features", {})

            hostname = info.get("hostname", "UNKNOWN")
            lines.append(f"## Device #{idx}: {hostname}")
            lines.append("")

            # 1. Device Metadata Table
            lines.append("### 1. Device Metadata")
            lines.append("| Property | Value |")
            lines.append("| :--- | :--- |")
            lines.append(f"| **Hostname** | `{hostname}` |")
            lines.append(f"| **Domain Name** | `{info.get('domain_name', 'N/A')}` |")
            lines.append(f"| **Vendor** | `{info.get('vendor', 'Unknown')}` |")
            lines.append(f"| **OS Family** | `{info.get('os_family', 'Unknown')}` |")
            lines.append(f"| **OS Version** | **`{info.get('version', 'N/A')}`** |")
            lines.append(f"| **Hardware Model** | `{info.get('model', 'Unknown')}` |")
            lines.append("")

            # 2. Executive Summary Metrics
            lines.append("### 2. Audit Executive Summary")
            lines.append("| Metric | Count | Description |")
            lines.append("| :--- | :--- | :--- |")
            lines.append(f"| **Rules Evaluated** | {summary.get('total_rules_evaluated', 0)} | Total vendor CVE rules tested |")
            lines.append(f"| **Version In Range** | {summary.get('total_affected_versions', 0)} | CVEs matching OS version (Necessary Condition) |")
            lines.append(f"| :fire: **EXPLOITABLE (Action Required)** | **{summary.get('exploitable_count', 0)}** | Precondition active in config (Sufficient Condition) |")
            lines.append(f"| :shield: **MITIGATED (False Positives Avoided)** | **{summary.get('mitigated_count', 0)}** | Feature disabled in config (Real Risk neutralized) |")
            lines.append(f"| :warning: **In CISA KEV** | **{summary.get('in_kev_count', 0)}** | Known Exploited in the Wild / Ransomware campaigns |")
            lines.append(f"| **Critical Real Risk** | {summary.get('critical_count', 0)} | Immediate remediation priority |")
            lines.append(f"| **High Real Risk** | {summary.get('high_count', 0)} | High remediation priority |")
            lines.append("")

            # 3. Active Features
            lines.append("### 3. Audited Configuration Features")
            lines.append("| Feature | State in Config | Security Significance |")
            lines.append("| :--- | :--- | :--- |")
            for feat, is_on in features.items():
                status_icon = "ENABLED :warning:" if is_on else "DISABLED :white_check_mark:"
                lines.append(f"| `{feat}` | **{status_icon}** | {'Attack surface exposed' if is_on else 'Attack surface closed'} |")
            lines.append("")

            # 4. Detailed Vulnerability Table
            lines.append("### 4. Vulnerability Assessment Findings")
            if not vulns:
                lines.append("*No vulnerabilities matching the device OS version were identified.*\n")
            else:
                lines.append("| CVE ID | Title | Status | Real Risk | CVSS | KEV | Precondition Met? |")
                lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
                for v in vulns:
                    status_badge = f"**`{v['status']}`**"
                    risk_badge = f"**{v['real_risk']}**"
                    kev_badge = "**YES (KEV)**" if v.get("in_kev") else "No"
                    prec_met = "YES" if v.get("precondition_met") else "NO"
                    lines.append(
                        f"| [{v['cve_id']}](#{v['cve_id'].lower()}) | {v['title']} | {status_badge} | {risk_badge} | {v['base_score']} | {kev_badge} | {prec_met} |"
                    )
                lines.append("")

                # 5. Technical Cards for Exploitable & Mitigated
                lines.append("### 5. Technical Details & Remediation Playbook")
                for v in vulns:
                    lines.append(f"#### <a id=\"{v['cve_id'].lower()}\"></a>{v['cve_id']} - {v['title']}")
                    lines.append(f"- **Status**: `{v['status']}` ({'Vulnerable service active and reachable' if v['status'] == STATUS_EXPLOITABLE else 'Feature inactive; vulnerability dormant/mitigated'})")
                    lines.append(f"- **Real Operational Risk**: **{v['real_risk']}** (CVSS: {v['base_score']})")
                    if v.get("in_kev"):
                        kev_det = v.get("kev_details", {})
                        lines.append(f"- **CISA KEV Alert**: Listed on CISA KEV (Date Added: {kev_det.get('date_added', 'N/A')}). Ransomware use: `{kev_det.get('ransomware_campaign', 'Unknown')}`")
                        if kev_det.get("required_action"):
                            lines.append(f"- **CISA Required Action**: {kev_det.get('required_action')}")
                    lines.append(f"- **Affected OS Versions**: `{v.get('affected_versions', 'N/A')}`")
                    lines.append(f"- **Triggering Precondition**: {v.get('precondition_description', 'N/A')}")
                    lines.append(f"- **Precondition Active on Device**: `{'YES' if v.get('precondition_met') else 'NO'}`")
                    lines.append(f"- **Description**: {v.get('description', '')}")
                    lines.append("- **Remediation / Hardening CLI Command**:")
                    lines.append("```bash")
                    lines.append(v.get("mitigation_cmd", "# No mitigation command provided"))
                    lines.append("```")
                    if v.get("references"):
                        lines.append(f"- **References**: {', '.join(v['references'])}")
                    lines.append("")

            lines.append("---\n")

        content = "\n".join(lines)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return str(path)

    # =========================================================================
    # 2. EXCEL EXPORT (openpyxl)
    # =========================================================================

    def export_excel(
        self,
        scan_results: Union[Dict[str, Any], List[Dict[str, Any]]],
        output_path: Union[str, Path],
    ) -> str:
        """Export audit report to formatted Excel workbook.

        Features corporate Navy blue headers, conditional formatting, and auto-column fitting.

        Args:
            scan_results: Single report dict or list of reports.
            output_path: Target .xlsx file path.

        Returns:
            The output file path as string.
        """
        devices = self._normalize_results(scan_results)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        wb = openpyxl.Workbook()
        # Remove default sheet
        wb.remove(wb.active)

        # Style definitions
        navy_header_fill = PatternFill(start_color="1B365D", end_color="1B365D", fill_type="solid")
        header_font = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
        regular_font = Font(name="Segoe UI", size=10)
        bold_font = Font(name="Segoe UI", size=10, bold=True)
        center_align = Alignment(horizontal="center", vertical="center")
        left_align = Alignment(horizontal="left", vertical="center")
        wrap_align = Alignment(horizontal="left", vertical="center", wrap_text=True)

        border_thin = Side(border_style="thin", color="D3D3D3")
        cell_border = Border(top=border_thin, left=border_thin, right=border_thin, bottom=border_thin)

        # Status Fills
        fill_exploitable = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
        font_exploitable = Font(name="Segoe UI", size=10, bold=True, color="9C0006")

        fill_mitigated = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
        font_mitigated = Font(name="Segoe UI", size=10, bold=True, color="006100")

        # Risk Fills
        fill_critical = PatternFill(start_color="D9534F", end_color="D9534F", fill_type="solid")
        font_critical = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")

        fill_high = PatternFill(start_color="F0AD4E", end_color="F0AD4E", fill_type="solid")
        font_high = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")

        fill_medium = PatternFill(start_color="FCF8E3", end_color="FCF8E3", fill_type="solid")
        font_medium = Font(name="Segoe UI", size=10, bold=True, color="8A6D3B")

        fill_low = PatternFill(start_color="DFF0D8", end_color="DFF0D8", fill_type="solid")
        font_low = Font(name="Segoe UI", size=10, bold=True, color="3C763D")

        # -------------------------------------------------------------
        # SHEET 1: Executive Summary
        # -------------------------------------------------------------
        ws_sum = wb.create_sheet(title="Executive Summary")
        ws_sum.views.sheetView[0].showGridLines = True

        # Title Banner
        ws_sum.merge_cells("A1:G1")
        title_cell = ws_sum["A1"]
        title_cell.value = "Vuln-Check-Net: Network Device Security Audit Summary"
        title_cell.font = Font(name="Segoe UI", size=14, bold=True, color="FFFFFF")
        title_cell.fill = navy_header_fill
        title_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws_sum.row_dimensions[1].height = 36

        # Subtitle
        ws_sum.merge_cells("A2:G2")
        sub_cell = ws_sum["A2"]
        sub_cell.value = f"Audit Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Devices: {len(devices)}"
        sub_cell.font = Font(name="Segoe UI", size=10, italic=True, color="555555")
        sub_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws_sum.row_dimensions[2].height = 20

        sum_headers = [
            "Device Hostname",
            "Vendor",
            "OS Family",
            "OS Version",
            "Hardware Model",
            "Exploitable CVEs",
            "Mitigated CVEs",
            "In CISA KEV",
            "Critical Risk",
            "High Risk",
        ]

        ws_sum.append([])
        ws_sum.append(sum_headers)
        header_row = 4
        ws_sum.row_dimensions[header_row].height = 26

        for col_idx in range(1, len(sum_headers) + 1):
            cell = ws_sum.cell(row=header_row, column=col_idx)
            cell.font = header_font
            cell.fill = navy_header_fill
            cell.alignment = center_align
            cell.border = cell_border

        for dev in devices:
            info = dev.get("device_info", {})
            sm = dev.get("summary", {})
            row_data = [
                info.get("hostname", "UNKNOWN"),
                info.get("vendor", "Unknown"),
                info.get("os_family", "Unknown"),
                info.get("version", "N/A"),
                info.get("model", "Unknown"),
                sm.get("exploitable_count", 0),
                sm.get("mitigated_count", 0),
                sm.get("in_kev_count", 0),
                sm.get("critical_count", 0),
                sm.get("high_count", 0),
            ]
            ws_sum.append(row_data)
            cur_row = ws_sum.max_row
            ws_sum.row_dimensions[cur_row].height = 22
            for col_idx in range(1, len(row_data) + 1):
                c = ws_sum.cell(row=cur_row, column=col_idx)
                c.font = regular_font
                c.border = cell_border
                c.alignment = center_align if col_idx > 1 else left_align

                # Highlight exploitable
                if col_idx == 6 and c.value and int(c.value) > 0:
                    c.fill = fill_exploitable
                    c.font = font_exploitable
                if col_idx == 8 and c.value and int(c.value) > 0:
                    c.fill = fill_critical
                    c.font = font_critical

        # -------------------------------------------------------------
        # SHEET 2: Vulnerability Findings
        # -------------------------------------------------------------
        ws_vuln = wb.create_sheet(title="Vulnerabilities")
        ws_vuln.views.sheetView[0].showGridLines = True
        ws_vuln.freeze_panes = "A2"

        vuln_headers = [
            "Device Hostname",
            "OS Family",
            "OS Version",
            "CVE ID",
            "Vulnerability Title",
            "Exploitability Status",
            "Real Operational Risk",
            "Base CVSS",
            "In CISA KEV?",
            "Ransomware Campaign",
            "Precondition Required",
            "Precondition Active?",
            "Remediation / Mitigation Command",
            "Vulnerability Description",
        ]

        ws_vuln.append(vuln_headers)
        ws_vuln.row_dimensions[1].height = 28

        for col_idx in range(1, len(vuln_headers) + 1):
            cell = ws_vuln.cell(row=1, column=col_idx)
            cell.font = header_font
            cell.fill = navy_header_fill
            cell.alignment = center_align
            cell.border = cell_border

        for dev in devices:
            info = dev.get("device_info", {})
            hname = info.get("hostname", "UNKNOWN")
            os_fam = info.get("os_family", "Unknown")
            os_ver = info.get("version", "N/A")

            for v in dev.get("vulnerabilities", []):
                in_kev_str = "YES" if v.get("in_kev") else "NO"
                ransom_str = v.get("kev_details", {}).get("ransomware_campaign", "N/A")
                prec_met_str = "YES" if v.get("precondition_met") else "NO"

                row_vals = [
                    hname,
                    os_fam,
                    os_ver,
                    v.get("cve_id", ""),
                    v.get("title", ""),
                    v.get("status", ""),
                    v.get("real_risk", ""),
                    v.get("base_score", 0.0),
                    in_kev_str,
                    ransom_str,
                    v.get("precondition_description", ""),
                    prec_met_str,
                    v.get("mitigation_cmd", ""),
                    v.get("description", ""),
                ]

                ws_vuln.append(row_vals)
                cur_row = ws_vuln.max_row
                ws_vuln.row_dimensions[cur_row].height = 24

                for col_idx in range(1, len(row_vals) + 1):
                    c = ws_vuln.cell(row=cur_row, column=col_idx)
                    c.font = regular_font
                    c.border = cell_border
                    c.alignment = left_align

                    # Alignments
                    if col_idx in (1, 2, 3, 4, 8, 9, 10, 12):
                        c.alignment = center_align

                    # Status styling (Col 6)
                    if col_idx == 6:
                        c.alignment = center_align
                        if c.value == STATUS_EXPLOITABLE:
                            c.fill = fill_exploitable
                            c.font = font_exploitable
                        elif c.value == STATUS_MITIGATED:
                            c.fill = fill_mitigated
                            c.font = font_mitigated

                    # Real Risk styling (Col 7)
                    if col_idx == 7:
                        c.alignment = center_align
                        if c.value == RISK_CRITICAL:
                            c.fill = fill_critical
                            c.font = font_critical
                        elif c.value == RISK_HIGH:
                            c.fill = fill_high
                            c.font = font_high
                        elif c.value == RISK_MEDIUM:
                            c.fill = fill_medium
                            c.font = font_medium
                        elif c.value == RISK_LOW:
                            c.fill = fill_low
                            c.font = font_low

                    # In KEV styling (Col 9)
                    if col_idx == 9 and c.value == "YES":
                        c.fill = fill_critical
                        c.font = font_critical

                    # Precondition Met styling (Col 12)
                    if col_idx == 12:
                        c.font = bold_font

        # Auto-fit column widths for all sheets
        for sheet in (ws_sum, ws_vuln):
            for col in sheet.columns:
                max_len = 0
                col_letter = get_column_letter(col[0].column)
                for cell in col:
                    val_str = str(cell.value or "")
                    if cell.row == 1 and sheet == ws_sum:
                        continue  # Skip merged banner
                    max_len = max(max_len, len(val_str))
                sheet.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 70)

        wb.save(path)
        return str(path)

    # =========================================================================
    # 3. JSON EXPORT
    # =========================================================================

    def export_json(
        self,
        scan_results: Union[Dict[str, Any], List[Dict[str, Any]]],
        output_path: Union[str, Path],
    ) -> str:
        """Export audit report to structured JSON file."""
        devices = self._normalize_results(scan_results)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "generator": "Vuln-Check-Net Engine",
            "timestamp": datetime.now().isoformat(),
            "devices_count": len(devices),
            "results": devices,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return str(path)
