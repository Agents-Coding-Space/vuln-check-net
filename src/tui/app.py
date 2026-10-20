"""Terminal User Interface (TUI) for Vuln-Check-Net.

Multi-Vendor Network CVE Audit Engine interactive terminal console
built with textual and rich.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Markdown,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from src.config import (
    OS_ARBOR_ARBOS,
    OS_CISCO_ASA,
    OS_CISCO_IOS_XE,
    OS_F5_BIGIP,
    OS_FORTINET_FORTIOS,
    OS_IMPERVA_SECURESPHERE,
    OS_PALOALTO_PANOS,
    OUTPUTS_DIR,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_MEDIUM,
    STATUS_EXPLOITABLE,
    STATUS_MITIGATED,
    STATUS_POTENTIAL,
    VENDOR_CISCO,
    VENDOR_F5,
    VENDOR_FORTINET,
    VENDOR_IMPERVA,
    VENDOR_NETSCOUT,
    VENDOR_PALOALTO,
)
from src.engine import CorrelationEngine
from src.fetcher_cisa import CisaKevFetcher
from src.parser import ConfigParser
from src.reporter import Reporter

# 7 Real-world sample configurations
QUICK_SAMPLES: List[Tuple[str, str, str]] = [
    (
        "ASA 1",
        "F:/WORK/NCS_Downloads/Network config/Firewall ASA1.txt",
        "btn-sample-asa",
    ),
    (
        "IOS XE",
        "F:/WORK/NCS_Downloads/cisco_ios_xe_sample_config.txt",
        "btn-sample-iosxe",
    ),
    (
        "FortiOS",
        "F:/WORK/NCS_Downloads/fortigate_fortios_sample_config.txt",
        "btn-sample-fortios",
    ),
    (
        "PAN-OS",
        "F:/WORK/NCS_Downloads/paloalto_panos_sample_config.txt",
        "btn-sample-panos",
    ),
    (
        "F5 BIG-IP",
        "F:/WORK/NCS_Downloads/f5_bigip_asm_waf_sample_config.txt",
        "btn-sample-f5",
    ),
    (
        "Arbor",
        "F:/WORK/NCS_Downloads/arbor_sightline_tms_sample_config.txt",
        "btn-sample-arbor",
    ),
    (
        "Imperva",
        "F:/WORK/NCS_Downloads/imperva_waf_sample_config.txt",
        "btn-sample-imperva",
    ),
]

# Supported Vendor & OS options for Version Lookup
VENDOR_OPTIONS: List[Tuple[str, str]] = [
    ("Cisco ASA", "cisco_asa"),
    ("Cisco IOS XE", "cisco_ios_xe"),
    ("Fortinet FortiOS", "fortinet_fortios"),
    ("Palo Alto PAN-OS", "paloalto_panos"),
    ("F5 BIG-IP", "f5_bigip"),
    ("NETSCOUT Arbor", "arbor_arbos"),
    ("Imperva SecureSphere", "imperva_securesphere"),
]

VENDOR_MAP: Dict[str, Tuple[str, str]] = {
    "cisco_asa": (VENDOR_CISCO, OS_CISCO_ASA),
    "cisco_ios_xe": (VENDOR_CISCO, OS_CISCO_IOS_XE),
    "fortinet_fortios": (VENDOR_FORTINET, OS_FORTINET_FORTIOS),
    "paloalto_panos": (VENDOR_PALOALTO, OS_PALOALTO_PANOS),
    "f5_bigip": (VENDOR_F5, OS_F5_BIGIP),
    "arbor_arbos": (VENDOR_NETSCOUT, OS_ARBOR_ARBOS),
    "imperva_securesphere": (VENDOR_IMPERVA, OS_IMPERVA_SECURESPHERE),
}

LOOKUP_PRESETS: List[Tuple[str, str, str, str]] = [
    ("ASA 9.20(3)", "cisco_asa", "9.20(3)", "btn-preset-asa"),
    ("IOS XE 17.6", "cisco_ios_xe", "17.6", "btn-preset-iosxe"),
    ("FortiOS 7.2.4", "fortinet_fortios", "7.2.4", "btn-preset-fortios"),
    ("PAN-OS 10.2.3", "paloalto_panos", "10.2.3-h4", "btn-preset-panos"),
    ("BIG-IP 17.1.1", "f5_bigip", "17.1.1", "btn-preset-f5"),
    ("Arbor 9.7.1", "arbor_arbos", "9.7.1", "btn-preset-arbor"),
    ("Imperva 14.7", "imperva_securesphere", "14.7.0.20", "btn-preset-imperva"),
]

APP_CSS = """
Screen {
    background: #0b1120;
    color: #e2e8f0;
}

Header {
    background: #1e293b;
    color: #38bdf8;
    height: 1;
}

Footer {
    background: #1e293b;
    color: #94a3b8;
}

TabbedContent {
    height: 1fr;
}

TabPane {
    padding: 0 1;
}

/* Quick samples bar */
.sample-bar {
    layout: horizontal;
    overflow-x: auto;
    overflow-y: hidden;
    height: auto;
    min-height: 3;
    align-vertical: middle;
    margin: 0;
    padding: 0;
}

.sample-bar Label {
    margin: 1 1 0 0;
    color: #38bdf8;
    text-style: bold;
}

.btn-sample {
    margin: 0 1 0 0;
    min-width: 9;
    height: 3;
}

/* Input & Action bar */
.action-bar {
    layout: horizontal;
    overflow-x: auto;
    overflow-y: hidden;
    height: auto;
    min-height: 3;
    margin: 0 0 1 0;
}

.action-bar Input {
    width: 1fr;
    min-width: 20;
    margin-right: 1;
}

.action-bar Button {
    margin-right: 1;
    min-width: 12;
}

/* Summary section: Device metadata card + Metrics */
.summary-row {
    height: 7;
    margin-bottom: 1;
}

#device-metadata-card {
    width: 50%;
    height: 100%;
    border: round #38bdf8;
    background: #131d31;
    padding: 0 1;
    margin-right: 1;
}

#metrics-summary-bar {
    width: 50%;
    height: 100%;
    layout: horizontal;
    border: round #334155;
    background: #131d31;
    padding: 0;
}

.metric-card {
    width: 1fr;
    height: 100%;
    text-align: center;
    content-align: center middle;
    border-right: solid #334155;
    padding: 0;
}

/* Data Tables */
DataTable {
    background: #131d31;
    border: round #334155;
    height: 1fr;
    min-height: 8;
    margin-bottom: 1;
}

DataTable > .datatable--cursor {
    background: #1d4ed8;
    color: #ffffff;
    text-style: bold;
}

/* Detail Panels */
.detail-container {
    height: 1fr;
    min-height: 8;
    border: round #38bdf8;
    background: #0f172a;
    padding: 0 1;
}

.detail-container:focus {
    border: heavy #c084fc;
    background: #1e1b4b;
}

/* Detail Action & Hint Bar */
.detail-header-bar {
    layout: horizontal;
    overflow-x: auto;
    overflow-y: hidden;
    height: auto;
    min-height: 3;
    align-vertical: middle;
    margin: 0;
    padding: 0;
}

.btn-detail-tool {
    margin: 0 1 0 0;
    min-width: 4;
    height: 3;
}

#btn-vuln-fullscreen, #btn-lookup-fullscreen, #btn-kev-fullscreen {
    min-width: 17;
}

.detail-hint-label {
    margin: 1 0 0 1;
    color: #94a3b8;
}

.detail-panel {
    width: 100%;
}

Markdown {
    margin: 0;
    padding: 0;
}

/* Tab 2: Fast Lookup */
.lookup-bar {
    layout: horizontal;
    overflow-x: auto;
    overflow-y: hidden;
    height: auto;
    min-height: 3;
    align-vertical: middle;
    margin-bottom: 1;
}

.lookup-bar Label {
    margin: 1 1 0 0;
    color: #38bdf8;
    text-style: bold;
}

.lookup-bar Select {
    width: 1fr;
    min-width: 18;
    max-width: 28;
    margin-right: 1;
}

.lookup-bar Input {
    width: 1fr;
    min-width: 16;
    max-width: 24;
    margin-right: 1;
}

.lookup-bar Button {
    min-width: 15;
}

#lookup-summary-card {
    height: 3;
    border: round #38bdf8;
    background: #131d31;
    padding: 0 1;
    margin-bottom: 1;
}

/* Tab 3: CISA KEV */
.kev-bar {
    layout: horizontal;
    overflow-x: auto;
    overflow-y: hidden;
    height: auto;
    min-height: 3;
    align-vertical: middle;
    margin-bottom: 1;
}

.kev-bar Input {
    width: 1fr;
    min-width: 20;
    margin-right: 1;
}

.kev-bar Button {
    margin-right: 1;
    min-width: 10;
}

#label-kev-count {
    margin: 1 0 0 1;
    color: #c084fc;
    text-style: bold;
}

.filter-bar {
    layout: horizontal;
    overflow-x: auto;
    overflow-y: hidden;
    height: auto;
    min-height: 3;
    align-vertical: middle;
    margin-bottom: 1;
}

.filter-bar Label {
    margin: 1 1 0 0;
    color: #38bdf8;
    text-style: bold;
}

.btn-filter, .btn-preset {
    margin-right: 1;
    min-width: 9;
}

.btn-filter-active {
    background: #0284c7 !important;
    color: #ffffff !important;
    text-style: bold;
}
"""


class DetailScrollContainer(VerticalScroll):
    """Scrollable container for vulnerability details with keyboard focus affordance."""

    can_focus = True

    BINDINGS = [
        Binding("escape", "return_to_table", "Back to Table", show=False),
    ]

    def __init__(
        self, *children: Any, target_table_id: str = "audit-datatable", **kwargs: Any
    ) -> None:
        super().__init__(*children, **kwargs)
        self.target_table_id = target_table_id

    def action_return_to_table(self) -> None:
        """Return focus to the associated DataTable."""
        try:
            table = self.app.query_one(f"#{self.target_table_id}")
            table.focus()
        except Exception:
            pass


class VulnerabilityDetailModal(ModalScreen[None]):
    """Fullscreen modal dialog for comfortable vulnerability inspection and scrolling."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=True),
        Binding("v", "dismiss", "Close [V]", show=False),
        Binding("q", "dismiss", "Close [Q]", show=False),
    ]

    DEFAULT_CSS = """
    VulnerabilityDetailModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.75);
    }

    #modal-dialog {
        width: 90%;
        height: 85%;
        border: thick #38bdf8;
        background: #0f172a;
        padding: 1 2;
    }

    #modal-header {
        height: 3;
        dock: top;
        layout: horizontal;
        margin-bottom: 1;
        border-bottom: solid #334155;
    }

    #modal-title {
        width: 1fr;
        color: #38bdf8;
        text-style: bold;
        content-align: left middle;
    }

    #btn-modal-close {
        min-width: 14;
    }

    #modal-scroll {
        width: 100%;
        height: 1fr;
    }
    """

    def __init__(
        self, markdown_text: str, title: str = "Vulnerability Full Details"
    ) -> None:
        super().__init__()
        self.markdown_text = markdown_text
        self.dialog_title = title

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-dialog"):
            with Horizontal(id="modal-header"):
                yield Label(self.dialog_title, id="modal-title")
                yield Button("[Esc] Close", id="btn-modal-close", variant="primary")
            with VerticalScroll(id="modal-scroll"):
                yield Markdown(self.markdown_text, id="modal-markdown")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-modal-close":
            self.dismiss()


class VulnCheckApp(App):
    """Interactive Terminal User Interface for Vuln-Check-Net."""

    TITLE = "Vuln-Check-Net"
    SUB_TITLE = "Multi-Vendor Network CVE Audit & Intelligence Engine"
    CSS = APP_CSS

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True, priority=True),
        Binding("ctrl+s", "scan_file", "Scan Config", show=True, priority=True),
        Binding("ctrl+d", "tab_audit", "Device Audit", show=True, priority=True),
        Binding("ctrl+l", "tab_lookup", "Version Lookup", show=True, priority=True),
        Binding("ctrl+k", "tab_kev", "KEV Explorer", show=True, priority=True),
        Binding("ctrl+e", "export_all", "Export", show=True, priority=True),
        Binding("f1", "filter_triage_all", "F1: All", show=True),
        Binding("f2", "filter_triage_exploitable", "F2: Exploitable", show=True),
        Binding("f3", "filter_triage_kev", "F3: KEV", show=True),
        Binding("f4", "filter_triage_mitigated", "F4: Mitigated", show=True),
        Binding("v", "view_fullscreen", "Full Details [V]", show=True),
        Binding("alt+down", "scroll_detail_down", "Scroll Detail ↓", show=True),
        Binding("alt+up", "scroll_detail_up", "Scroll Detail ↑", show=True),
        Binding("alt+pagedown", "page_detail_down", "Detail Page ↓", show=False),
        Binding("alt+pageup", "page_detail_up", "Detail Page ↑", show=False),
    ]

    def __init__(self, initial_file: Optional[str] = None) -> None:
        super().__init__()
        self.initial_file = initial_file
        self.current_triage_filter: str = "all"
        self.current_audit_result: Optional[Dict[str, Any]] = None
        self.audit_vulns_map: Dict[str, Dict[str, Any]] = {}
        self.lookup_vulns_map: Dict[str, Dict[str, Any]] = {}
        self.kev_records_map: Dict[str, Dict[str, Any]] = {}

        # Business logic singletons
        self.cisa_fetcher = CisaKevFetcher()
        self.parser = ConfigParser()
        self.engine = CorrelationEngine(cisa_fetcher=self.cisa_fetcher)
        self.reporter = Reporter()

    def compose(self) -> ComposeResult:
        """Compose layout widgets."""
        yield Header(show_clock=True)
        with TabbedContent(id="main-tabs"):
            # TAB 1: Device Audit
            with TabPane("Device Audit", id="tab-audit"):
                # Quick samples bar
                with Horizontal(id="quick-samples-bar", classes="sample-bar"):
                    yield Label("Quick Samples:")
                    for label, _path, btn_id in QUICK_SAMPLES:
                        yield Button(label, id=btn_id, classes="btn-sample")

                # Action / Input bar
                with Horizontal(id="config-input-bar", classes="action-bar"):
                    yield Input(
                        placeholder="Path to running-config file (or click a quick sample above)...",
                        id="input-config-path",
                    )
                    yield Button("Scan File", id="btn-scan", variant="primary")
                    yield Button("Export MD", id="btn-export-md")
                    yield Button("Export Excel", id="btn-export-xlsx")
                    yield Button("Export JSON", id="btn-export-json")

                # Device Metadata & Metrics Row
                with Horizontal(id="device-summary-section", classes="summary-row"):
                    yield Static(
                        "[dim]No configuration scanned yet.\nClick a Quick Sample above or enter a file path to audit.[/dim]",
                        id="device-metadata-card",
                    )
                    with Horizontal(id="metrics-summary-bar"):
                        yield Static(
                            "[dim]Rules Tested[/dim]\n[bold white]0[/bold white]",
                            id="metric-total-rules",
                            classes="metric-card",
                        )
                        yield Static(
                            "[dim]Version Matched[/dim]\n[bold cyan]0[/bold cyan]",
                            id="metric-version-matched",
                            classes="metric-card",
                        )
                        yield Static(
                            "[dim]EXPLOITABLE[/dim]\n[bold red]0[/bold red]",
                            id="metric-exploitable",
                            classes="metric-card",
                        )
                        yield Static(
                            "[dim]MITIGATED[/dim]\n[bold green]0[/bold green]",
                            id="metric-mitigated",
                            classes="metric-card",
                        )
                        yield Static(
                            "[dim]In CISA KEV[/dim]\n[bold magenta]0[/bold magenta]",
                            id="metric-in-kev",
                            classes="metric-card",
                        )
                        yield Static(
                            "[dim]Critical / High[/dim]\n[bold yellow]0 / 0[/bold yellow]",
                            id="metric-crithigh",
                            classes="metric-card",
                        )

                # Triage Filter Bar
                with Horizontal(id="audit-filter-bar", classes="filter-bar"):
                    yield Label("Triage Filter:")
                    yield Button(
                        "All [F1]",
                        id="btn-triage-all",
                        classes="btn-filter btn-filter-active",
                    )
                    yield Button(
                        "Exploitable [F2]",
                        id="btn-triage-exploitable",
                        classes="btn-filter",
                    )
                    yield Button(
                        "CISA KEV [F3]", id="btn-triage-kev", classes="btn-filter"
                    )
                    yield Button(
                        "Mitigated [F4]",
                        id="btn-triage-mitigated",
                        classes="btn-filter",
                    )
                    yield Button(
                        "Potential", id="btn-triage-potential", classes="btn-filter"
                    )

                # DataTable for audit findings
                yield DataTable(id="audit-datatable")

                # Detail Action & Hint Bar
                with Horizontal(
                    id="vuln-detail-header-bar", classes="detail-header-bar"
                ):
                    yield Button(
                        "[V] Full Details",
                        id="btn-vuln-fullscreen",
                        classes="btn-detail-tool",
                    )
                    yield Button(
                        "↑", id="btn-vuln-scroll-up", classes="btn-detail-tool"
                    )
                    yield Button(
                        "↓", id="btn-vuln-scroll-down", classes="btn-detail-tool"
                    )
                    yield Label(
                        "[dim]Enter/Click to Focus • ↑/↓ or Alt+↑/↓ to Scroll • Esc to return to Table[/dim]",
                        id="lbl-vuln-hints",
                        classes="detail-hint-label",
                    )

                # Vulnerability detail panel
                with DetailScrollContainer(
                    id="vuln-detail-container",
                    classes="detail-container",
                    target_table_id="audit-datatable",
                ):
                    yield Markdown(
                        "*Select a vulnerability from the table to view full details, precondition evidence, and mitigation playbook.*",
                        id="detail-content",
                        classes="detail-panel",
                    )

            # TAB 2: Fast CVE Lookup
            with TabPane("Version Lookup", id="tab-lookup"):
                with Horizontal(id="lookup-controls-bar", classes="lookup-bar"):
                    yield Label("Vendor / OS Family:")
                    yield Select(
                        VENDOR_OPTIONS, id="select-lookup-vendor", value="cisco_asa"
                    )
                    yield Label("OS Version:")
                    yield Input(
                        placeholder="e.g. 9.20(3), 17.6, 7.2.4",
                        id="input-lookup-version",
                    )
                    yield Button(
                        "Check Version", id="btn-check-version", variant="primary"
                    )

                with Horizontal(id="lookup-presets-bar", classes="filter-bar"):
                    yield Label("Quick Presets:")
                    for label, _vkey, _ver, pid in LOOKUP_PRESETS:
                        yield Button(label, id=pid, classes="btn-preset")

                yield Static(
                    "[dim]Select a vendor, enter a version string (or click a quick preset), then click 'Check Version'.[/dim]",
                    id="lookup-summary-card",
                )
                yield DataTable(id="table-lookup-vulns")

                with Horizontal(
                    id="lookup-detail-header-bar", classes="detail-header-bar"
                ):
                    yield Button(
                        "[V] Full Details",
                        id="btn-lookup-fullscreen",
                        classes="btn-detail-tool",
                    )
                    yield Button(
                        "↑", id="btn-lookup-scroll-up", classes="btn-detail-tool"
                    )
                    yield Button(
                        "↓", id="btn-lookup-scroll-down", classes="btn-detail-tool"
                    )
                    yield Label(
                        "[dim]Enter/Click to Focus • ↑/↓ or Alt+↑/↓ to Scroll • Esc to return to Table[/dim]",
                        id="lbl-lookup-hints",
                        classes="detail-hint-label",
                    )

                with DetailScrollContainer(
                    id="lookup-detail-container",
                    classes="detail-container",
                    target_table_id="table-lookup-vulns",
                ):
                    yield Static(
                        "[dim]Select a vulnerability from the table to view potential risk and mitigation commands.[/dim]",
                        id="lookup-detail-panel",
                        classes="detail-panel",
                    )

            # TAB 3: CISA KEV Explorer
            with TabPane("CISA KEV Explorer", id="tab-kev"):
                with Horizontal(id="kev-controls-bar", classes="kev-bar"):
                    yield Input(
                        placeholder="Search CVE ID, vendor, product, or keyword...",
                        id="input-kev-search",
                    )
                    yield Button("Search", id="btn-kev-search", variant="primary")
                    yield Button("Reset", id="btn-kev-reset")
                    yield Label("Loading KEV records...", id="label-kev-count")

                with Horizontal(id="kev-filters-bar", classes="filter-bar"):
                    yield Label("Quick Filters:")
                    yield Button("All", id="btn-filter-all", classes="btn-filter")
                    yield Button("Cisco", id="btn-filter-cisco", classes="btn-filter")
                    yield Button(
                        "Fortinet", id="btn-filter-fortinet", classes="btn-filter"
                    )
                    yield Button(
                        "Palo Alto", id="btn-filter-paloalto", classes="btn-filter"
                    )
                    yield Button("F5", id="btn-filter-f5", classes="btn-filter")
                    yield Button(
                        "Ransomware Only",
                        id="btn-filter-ransomware",
                        classes="btn-filter",
                    )

                yield DataTable(id="table-kev")

                with Horizontal(
                    id="kev-detail-header-bar", classes="detail-header-bar"
                ):
                    yield Button(
                        "[V] Full Details",
                        id="btn-kev-fullscreen",
                        classes="btn-detail-tool",
                    )
                    yield Button("↑", id="btn-kev-scroll-up", classes="btn-detail-tool")
                    yield Button(
                        "↓", id="btn-kev-scroll-down", classes="btn-detail-tool"
                    )
                    yield Label(
                        "[dim]Enter/Click to Focus • ↑/↓ or Alt+↑/↓ to Scroll • Esc to return to Table[/dim]",
                        id="lbl-kev-hints",
                        classes="detail-hint-label",
                    )

                with DetailScrollContainer(
                    id="kev-detail-container",
                    classes="detail-container",
                    target_table_id="table-kev",
                ):
                    yield Markdown(
                        "*Select a KEV entry from the table to view remediation actions and intelligence.*",
                        id="kev-detail-content",
                        classes="detail-panel",
                    )

            # TAB 4: Database Health & Synchronization
            with TabPane("Database & Sync", id="tab-db"):
                with Horizontal(id="db-controls-bar", classes="lookup-bar"):
                    yield Button("Check Status", id="btn-db-status", variant="primary")
                    yield Button(
                        "Update Now (Sync)", id="btn-db-sync", variant="warning"
                    )
                    yield Label(
                        "Manage local SQLite cache & Day-by-Day sync",
                        id="label-db-banner",
                    )

                with DetailScrollContainer(
                    id="db-status-container",
                    classes="detail-container",
                ):
                    yield Markdown(
                        "Click **Check Status** or **Update Now (Sync)** to inspect synchronization health.",
                        id="db-status-content",
                        classes="detail-panel",
                    )

        yield Footer()

    def on_mount(self) -> None:
        """Initialize data tables and mount initial views."""
        # Setup Tab 1 DataTable
        table_audit = self.query_one("#audit-datatable", DataTable)
        table_audit.cursor_type = "row"
        table_audit.add_column("CVE ID", key="cve")
        table_audit.add_column("Title", key="title")
        table_audit.add_column("Triage Status", key="status")
        table_audit.add_column("Real Risk", key="risk")
        table_audit.add_column("CVSS", key="cvss")
        table_audit.add_column("CISA KEV", key="kev")
        table_audit.add_column("Precondition Requirement / Evidence", key="precond")

        # Setup Tab 2 DataTable
        table_lookup = self.query_one("#table-lookup-vulns", DataTable)
        table_lookup.cursor_type = "row"
        table_lookup.add_column("CVE ID", key="cve")
        table_lookup.add_column("Title", key="title")
        table_lookup.add_column("CVSS", key="cvss")
        table_lookup.add_column("In KEV", key="kev")
        table_lookup.add_column("Precondition Required", key="precond")
        table_lookup.add_column("Mitigation Command", key="mitigation")

        # Setup Tab 3 DataTable
        table_kev = self.query_one("#table-kev", DataTable)
        table_kev.cursor_type = "row"
        table_kev.add_column("CVE ID", key="cve")
        table_kev.add_column("Vendor", key="vendor")
        table_kev.add_column("Product", key="product")
        table_kev.add_column("Vulnerability Name", key="name")
        table_kev.add_column("Date Added", key="date_added")
        table_kev.add_column("Due Date", key="due_date")
        table_kev.add_column("Ransomware", key="ransomware")

        # Load KEV catalog on startup
        self.load_kev_catalog()

        # If initial file provided via CLI, load and scan it
        if self.initial_file:
            self.query_one("#input-config-path", Input).value = self.initial_file
            self.scan_file_path(self.initial_file)

    # =========================================================================
    # ACTIONS & KEY BINDINGS
    # =========================================================================

    def action_tab_audit(self) -> None:
        """Switch to Device Audit tab."""
        self.query_one("#main-tabs", TabbedContent).active = "tab-audit"

    def action_filter_triage_all(self) -> None:
        """Filter audit table to show all findings (F1)."""
        self.set_triage_filter("all")

    def action_filter_triage_exploitable(self) -> None:
        """Filter audit table to show only EXPLOITABLE findings (F2)."""
        self.set_triage_filter("exploitable")

    def action_filter_triage_kev(self) -> None:
        """Filter audit table to show only CISA KEV findings (F3)."""
        self.set_triage_filter("kev")

    def action_filter_triage_mitigated(self) -> None:
        """Filter audit table to show only MITIGATED findings (F4)."""
        self.set_triage_filter("mitigated")

    def set_triage_filter(self, filter_name: str) -> None:
        """Apply a triage filter and refresh findings table."""
        self.current_triage_filter = filter_name.lower()
        self._update_filter_button_styles()
        self._refresh_audit_table()
        filter_names = {
            "all": "All Vulnerabilities (F1)",
            "exploitable": "EXPLOITABLE Only (F2)",
            "kev": "CISA KEV Only (F3)",
            "mitigated": "MITIGATED Only (F4)",
            "potential": "POTENTIAL Only",
        }
        lbl = filter_names.get(self.current_triage_filter, self.current_triage_filter)
        self.notify(f"Filter: {lbl}", title="Triage Filter", timeout=2)

    def _update_filter_button_styles(self) -> None:
        """Update active button styling in audit filter bar."""
        mapping = {
            "all": "#btn-triage-all",
            "exploitable": "#btn-triage-exploitable",
            "kev": "#btn-triage-kev",
            "mitigated": "#btn-triage-mitigated",
            "potential": "#btn-triage-potential",
        }
        for key, btn_id in mapping.items():
            try:
                btn = self.query_one(btn_id, Button)
                if key == self.current_triage_filter:
                    btn.add_class("btn-filter-active")
                else:
                    btn.remove_class("btn-filter-active")
            except Exception:
                pass

    def action_tab_lookup(self) -> None:
        """Switch to Version Lookup tab."""
        self.query_one("#main-tabs", TabbedContent).active = "tab-lookup"

    def action_tab_kev(self) -> None:
        """Switch to CISA KEV Explorer tab."""
        self.query_one("#main-tabs", TabbedContent).active = "tab-kev"

    def _get_active_detail_container(self) -> Optional[VerticalScroll]:
        """Find the detail container for the currently active tab."""
        try:
            tabs = self.query_one("#main-tabs", TabbedContent)
            active_tab = tabs.active
            if active_tab == "tab-audit":
                return self.query_one("#vuln-detail-container", VerticalScroll)
            elif active_tab == "tab-lookup":
                return self.query_one("#lookup-detail-container", VerticalScroll)
            elif active_tab == "tab-kev":
                return self.query_one("#kev-detail-container", VerticalScroll)
        except Exception:
            pass
        return None

    def action_scroll_detail_down(self) -> None:
        """Scroll active detail panel down by 3 lines."""
        container = self._get_active_detail_container()
        if container:
            container.scroll_relative(y=3, animate=False)

    def action_scroll_detail_up(self) -> None:
        """Scroll active detail panel up by 3 lines."""
        container = self._get_active_detail_container()
        if container:
            container.scroll_relative(y=-3, animate=False)

    def action_page_detail_down(self) -> None:
        """Scroll active detail panel down by one page."""
        container = self._get_active_detail_container()
        if container:
            container.scroll_page_down(animate=False)

    def action_page_detail_up(self) -> None:
        """Scroll active detail panel up by one page."""
        container = self._get_active_detail_container()
        if container:
            container.scroll_page_up(animate=False)

    def action_view_fullscreen(self) -> None:
        """Open fullscreen modal to comfortably inspect vulnerability details."""
        try:
            tabs = self.query_one("#main-tabs", TabbedContent)
            active_tab = tabs.active
        except Exception:
            active_tab = "tab-audit"

        title = "Vulnerability Details"
        md_text = ""

        if active_tab == "tab-audit":
            try:
                table = self.query_one("#audit-datatable", DataTable)
                if table.row_count > 0 and table.cursor_row is not None:
                    row_key = table.coordinate_to_cell_key(
                        (table.cursor_row, 0)
                    ).row_key.value
                    if row_key and str(row_key) in self.audit_vulns_map:
                        v = self.audit_vulns_map[str(row_key)]
                        st = (
                            (v.get("status") or v.get("triage_status", ""))
                            .strip()
                            .upper()
                        )
                        title = f"[{st}] {v.get('cve_id', 'Vulnerability')} — {v.get('title', '')}"
            except Exception:
                pass
            try:
                md_widget = self.query_one("#detail-content", Markdown)
                md_text = md_widget.source
            except Exception:
                pass

        elif active_tab == "tab-lookup":
            try:
                table = self.query_one("#table-lookup-vulns", DataTable)
                if table.row_count > 0 and table.cursor_row is not None:
                    row_key = table.coordinate_to_cell_key(
                        (table.cursor_row, 0)
                    ).row_key.value
                    if row_key and str(row_key) in self.lookup_vulns_map:
                        v = self.lookup_vulns_map[str(row_key)]
                        title = f"{v.get('cve_id', 'Lookup')} — {v.get('title', '')}"
            except Exception:
                pass
            try:
                static_widget = self.query_one("#lookup-detail-panel", Static)
                md_text = str(static_widget.render())
            except Exception:
                pass

        elif active_tab == "tab-kev":
            try:
                table = self.query_one("#table-kev", DataTable)
                if table.row_count > 0 and table.cursor_row is not None:
                    row_key = table.coordinate_to_cell_key(
                        (table.cursor_row, 0)
                    ).row_key.value
                    if row_key and str(row_key) in self.kev_records_map:
                        rec = self.kev_records_map[str(row_key)]
                        title = f"{rec.get('cveID', 'KEV')} — {rec.get('vulnerabilityName', '')}"
            except Exception:
                pass
            try:
                md_widget = self.query_one("#kev-detail-content", Markdown)
                md_text = md_widget.source
            except Exception:
                pass

        if not md_text:
            md_text = "*No vulnerability details available to view in fullscreen.*"

        self.push_screen(VulnerabilityDetailModal(md_text, title))

    def action_scan_file(self) -> None:
        """Trigger scan on file path in input box."""
        self.query_one("#main-tabs", TabbedContent).active = "tab-audit"
        path = self.query_one("#input-config-path", Input).value.strip()
        if path:
            self.scan_file_path(path)
        else:
            self.notify(
                "Please enter a configuration file path or click a Quick Sample.",
                title="Config Path Required",
                severity="warning",
            )

    def action_export_all(self) -> None:
        """Export all 3 report formats (Markdown, Excel, JSON)."""
        if not self.current_audit_result:
            self.notify(
                "Please scan a device configuration before exporting.",
                title="No Scan Data",
                severity="warning",
            )
            return

        dev_info = self.current_audit_result.get("device_info", {})
        hostname = dev_info.get("hostname", "device")
        safe_name = "".join(
            c if c.isalnum() or c in ("-", "_") else "_" for c in hostname
        )
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

        target_md = OUTPUTS_DIR / f"{safe_name}_report.md"
        target_xlsx = OUTPUTS_DIR / f"{safe_name}_report.xlsx"
        target_json = OUTPUTS_DIR / f"{safe_name}_report.json"

        self.reporter.export_markdown(self.current_audit_result, target_md)
        self.reporter.export_excel(self.current_audit_result, target_xlsx)
        self.reporter.export_json(self.current_audit_result, target_json)

        self.notify(
            f"Exported MD, Excel, and JSON reports to outputs/ for {hostname}",
            title="Reports Exported",
            severity="information",
        )

    # =========================================================================
    # EVENT HANDLERS
    # =========================================================================

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button click events across all tabs."""
        bid = event.button.id
        if not bid:
            return

        # 1. Quick Samples buttons
        if bid.startswith("btn-sample-"):
            for _name, path, btn_id in QUICK_SAMPLES:
                if btn_id == bid:
                    self.query_one("#input-config-path", Input).value = path
                    self.scan_file_path(path)
                    return

        # 2. Main Scan button
        elif bid == "btn-scan":
            path = self.query_one("#input-config-path", Input).value.strip()
            if not path:
                self.notify(
                    "Please enter a config file path or select a Quick Sample.",
                    title="No Path Provided",
                    severity="warning",
                )
                return
            self.scan_file_path(path)

        # 2a. Triage Filter buttons
        elif bid == "btn-triage-all":
            self.set_triage_filter("all")
        elif bid == "btn-triage-exploitable":
            self.set_triage_filter("exploitable")
        elif bid == "btn-triage-kev":
            self.set_triage_filter("kev")
        elif bid == "btn-triage-mitigated":
            self.set_triage_filter("mitigated")
        elif bid == "btn-triage-potential":
            self.set_triage_filter("potential")

        # 2b. Detail Header buttons (fullscreen & scrolling)
        elif bid in (
            "btn-vuln-fullscreen",
            "btn-lookup-fullscreen",
            "btn-kev-fullscreen",
        ):
            self.action_view_fullscreen()
        elif bid in ("btn-vuln-scroll-up", "btn-lookup-scroll-up", "btn-kev-scroll-up"):
            self.action_scroll_detail_up()
        elif bid in (
            "btn-vuln-scroll-down",
            "btn-lookup-scroll-down",
            "btn-kev-scroll-down",
        ):
            self.action_scroll_detail_down()

        # 3. Export buttons
        elif bid == "btn-export-md":
            self._export_format("md")
        elif bid == "btn-export-xlsx":
            self._export_format("xlsx")
        elif bid == "btn-export-json":
            self._export_format("json")

        # 4. Lookup Check button
        elif bid == "btn-check-version":
            vendor_val = self.query_one("#select-lookup-vendor", Select).value
            version_val = self.query_one("#input-lookup-version", Input).value
            vkey = str(vendor_val) if vendor_val != Select.BLANK else "cisco_asa"
            self.run_version_lookup(vkey, version_val)

        # 5. Lookup Preset buttons
        elif bid.startswith("btn-preset-"):
            for _label, vkey, ver, preset_id in LOOKUP_PRESETS:
                if preset_id == bid:
                    self.query_one("#select-lookup-vendor", Select).value = vkey
                    self.query_one("#input-lookup-version", Input).value = ver
                    self.run_version_lookup(vkey, ver)
                    return

        # 6. KEV Search & Reset buttons
        elif bid == "btn-kev-search":
            kw = self.query_one("#input-kev-search", Input).value
            self.load_kev_catalog(filter_kw=kw)
        elif bid == "btn-kev-reset":
            self.query_one("#input-kev-search", Input).value = ""
            self.load_kev_catalog()

        # 7. KEV Filter buttons
        elif bid == "btn-filter-all":
            self.query_one("#input-kev-search", Input).value = ""
            self.load_kev_catalog()
        elif bid == "btn-filter-cisco":
            self.load_kev_catalog(vendor_filter="cisco")
        elif bid == "btn-filter-fortinet":
            self.load_kev_catalog(vendor_filter="fortinet")
        elif bid == "btn-filter-paloalto":
            self.load_kev_catalog(vendor_filter="palo alto")
        elif bid == "btn-filter-f5":
            self.load_kev_catalog(vendor_filter="f5")
        elif bid == "btn-filter-ransomware":
            self.load_kev_catalog(ransomware_only=True)

        # 8. Database Status & Sync buttons
        elif bid == "btn-db-status":
            self.render_db_status()
        elif bid == "btn-db-sync":
            self.run_db_sync()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key pressed in Input fields."""
        iid = event.input.id
        if iid == "input-config-path":
            path = event.value.strip()
            if path:
                self.scan_file_path(path)
        elif iid == "input-lookup-version":
            vendor_val = self.query_one("#select-lookup-vendor", Select).value
            vkey = str(vendor_val) if vendor_val != Select.BLANK else "cisco_asa"
            self.run_version_lookup(vkey, event.value)
        elif iid == "input-kev-search":
            self.load_kev_catalog(filter_kw=event.value)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Handle row cursor movement in any DataTable."""
        self._handle_table_selection(
            event.data_table.id, event.row_key.value if event.row_key else None
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row click or Enter in any DataTable."""
        table_id = event.data_table.id
        row_key = event.row_key.value if event.row_key else None
        self._handle_table_selection(table_id, row_key)

        # Automatically transfer focus into the corresponding detail container
        try:
            if table_id == "audit-datatable":
                self.query_one("#vuln-detail-container").focus()
            elif table_id == "table-lookup-vulns":
                self.query_one("#lookup-detail-container").focus()
            elif table_id == "table-kev":
                self.query_one("#kev-detail-container").focus()
        except Exception:
            pass

    def _handle_table_selection(
        self, table_id: Optional[str], key: Optional[str]
    ) -> None:
        """Update detail panel according to active table selection."""
        if not table_id or not key or not self.is_running:
            return

        key_str = str(key)
        try:
            if table_id == "audit-datatable":
                if key_str in self.audit_vulns_map:
                    dev_info = (
                        self.current_audit_result.get("device_info", {})
                        if self.current_audit_result
                        else {}
                    )
                    panel = self.query_one("#detail-content", Markdown)
                    panel.update(
                        self._render_vuln_detail(
                            self.audit_vulns_map[key_str], dev_info
                        )
                    )
                    container = self.query_one("#vuln-detail-container", VerticalScroll)
                    container.scroll_to(y=0, animate=False)

            elif table_id == "table-lookup-vulns":
                if key_str in self.lookup_vulns_map:
                    panel = self.query_one("#lookup-detail-panel", Static)
                    panel.update(
                        self._render_lookup_detail(self.lookup_vulns_map[key_str])
                    )
                    container = self.query_one(
                        "#lookup-detail-container", VerticalScroll
                    )
                    container.scroll_to(y=0, animate=False)

            elif table_id == "table-kev":
                if key_str in self.kev_records_map:
                    panel = self.query_one("#kev-detail-content", Markdown)
                    panel.update(self._render_kev_detail(self.kev_records_map[key_str]))
                    container = self.query_one("#kev-detail-container", VerticalScroll)
                    container.scroll_to(y=0, animate=False)
        except Exception:
            return

    # =========================================================================
    # TAB 1: DEVICE AUDIT LOGIC
    # =========================================================================

    def scan_file_path(self, file_path_str: str) -> None:
        """Audit a configuration file and update all UI views."""
        p = Path(file_path_str)
        if not p.exists() or not p.is_file():
            self.notify(
                f"Configuration file not found:\n{file_path_str}",
                title="Scan Error",
                severity="error",
            )
            return

        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.notify(
                f"Could not read file: {e}", title="Read Error", severity="error"
            )
            return

        try:
            parsed = self.parser.parse(content)
            audit_result = self.engine.evaluate_device(parsed)
        except Exception as e:
            self.notify(
                f"Engine evaluation error: {e}", title="Audit Error", severity="error"
            )
            return

        self.current_audit_result = audit_result
        dev_info = audit_result.get("device_info", {})
        summary = audit_result.get("summary", {})
        vulns = audit_result.get("vulnerabilities", [])

        self.audit_vulns_map = {v["cve_id"]: v for v in vulns}

        # 1. Update Device Metadata Card
        meta_card = self.query_one("#device-metadata-card", Static)
        meta_card.update(self._render_metadata_card(dev_info))

        # 2. Update Metrics Summary Counters
        self._update_metrics(summary)

        # 3. Populate Findings DataTable via current filter
        self.current_triage_filter = "all"
        self._update_filter_button_styles()
        self._refresh_audit_table()

        hostname = dev_info.get("hostname", "Device")
        exp_cnt = summary.get("exploitable_count", 0)
        self.notify(
            f"Audit finished for {hostname}: {len(vulns)} CVE rules matched ({exp_cnt} EXPLOITABLE).",
            title="Scan Complete",
            severity="information" if exp_cnt == 0 else "warning",
        )

    def _populate_audit_table(self, vulns: List[Dict[str, Any]]) -> None:
        """Populate the audit DataTable with vulnerabilities."""
        table = self.query_one("#audit-datatable", DataTable)
        table.clear()

        for v in vulns:
            cve_id = v.get("cve_id", "")
            title = v.get("title", "")
            st = (v.get("status") or v.get("triage_status", "")).strip().upper()
            if st == STATUS_EXPLOITABLE:
                st_txt = Text("[EXPLOITABLE]", style="bold white on #b91c1c")
            elif st == STATUS_MITIGATED:
                st_txt = Text("[MITIGATED]", style="bold white on #059669")
            elif st == STATUS_POTENTIAL:
                st_txt = Text("[POTENTIAL]", style="bold black on #eab308")
            else:
                st_txt = Text(f"[{st}]", style="bold white on #475569")

            risk = v.get("real_risk", "")
            if risk == RISK_CRITICAL:
                risk_txt = Text("CRITICAL", style="bold red")
            elif risk == RISK_HIGH:
                risk_txt = Text("HIGH", style="bold yellow")
            elif risk == RISK_MEDIUM:
                risk_txt = Text("MEDIUM", style="bold #f59e0b")
            else:
                risk_txt = Text(risk, style="green")

            score_txt = str(v.get("base_score", ""))
            kev_txt = (
                Text("[!] KEV", style="bold red")
                if v.get("in_kev")
                else Text("No", style="dim")
            )
            precond_txt = v.get("feature_evidence") or v.get(
                "precondition_description", ""
            )

            table.add_row(
                cve_id,
                title[:38] + ("..." if len(title) > 38 else ""),
                st_txt,
                risk_txt,
                score_txt,
                kev_txt,
                precond_txt[:45] + ("..." if len(precond_txt) > 45 else ""),
                key=cve_id,
            )

    def _refresh_audit_table(self) -> None:
        """Re-filter and refresh the audit findings table."""
        if not self.current_audit_result:
            return

        all_vulns = self.current_audit_result.get("vulnerabilities", [])
        dev_info = self.current_audit_result.get("device_info", {})

        filtered = self.reporter.filter_vulnerabilities(
            all_vulns,
            filter_triage=self.current_triage_filter
            if self.current_triage_filter != "kev"
            else "all",
            kev_only=(self.current_triage_filter == "kev"),
        )

        self._populate_audit_table(filtered)

        detail_panel = self.query_one("#detail-content", Markdown)
        table = self.query_one("#audit-datatable", DataTable)
        if filtered:
            table.move_cursor(row=0)
            detail_panel.update(self._render_vuln_detail(filtered[0], dev_info))
            self.query_one("#vuln-detail-container", VerticalScroll).scroll_to(
                y=0, animate=False
            )
        else:
            if not all_vulns:
                detail_panel.update(
                    "*No vulnerabilities matched this device OS version and configuration.*"
                )
            else:
                detail_panel.update(
                    f"*No findings matched filter '{self.current_triage_filter.upper()}'. Total findings: {len(all_vulns)}.*"
                )

    def _render_metadata_card(self, info: Dict[str, Any]) -> str:
        """Render device metadata card with rich syntax."""
        hostname = info.get("hostname", "UNKNOWN")
        domain = info.get("domain_name") or "N/A"
        vendor = info.get("vendor", "Unknown")
        os_family = info.get("os_family", "Unknown")
        version = info.get("version", "N/A")
        model = info.get("model", "Unknown")
        features = info.get("features", {})

        active_feats = [k for k, v in features.items() if v]
        inactive_feats = [k for k, v in features.items() if not v]

        active_str = (
            " ".join(f"[bold green on #064e3b] {f} [/]" for f in active_feats)
            if active_feats
            else "[dim]None[/dim]"
        )
        inactive_str = (
            " ".join(f"[dim]{f}[/dim]" for f in inactive_feats)
            if inactive_feats
            else "[dim]None[/dim]"
        )

        return (
            f"[bold cyan]Host:[/bold cyan] [bold white]{hostname}[/bold white]  |  "
            f"[bold cyan]Vendor:[/bold cyan] {vendor}  |  "
            f"[bold cyan]OS:[/bold cyan] {os_family} [bold yellow]{version}[/bold yellow]  |  "
            f"[bold cyan]Model:[/bold cyan] {model}  |  "
            f"[bold cyan]Domain:[/bold cyan] {domain}\n"
            f"[bold green]Active Features ({len(active_feats)}):[/bold green] {active_str}\n"
            f"[bold #94a3b8]Inactive Features ({len(inactive_feats)}):[/bold #94a3b8] {inactive_str}"
        )

    def _update_metrics(self, summary: Dict[str, Any]) -> None:
        """Update metrics summary counter boxes."""
        tot_rules = summary.get("total_rules_evaluated", 0)
        ver_match = summary.get("total_affected_versions", 0)
        exp = summary.get("exploitable_count", 0)
        mit = summary.get("mitigated_count", 0)
        kev = summary.get("in_kev_count", 0)
        crit = summary.get("critical_count", 0)
        high = summary.get("high_count", 0)

        self.query_one("#metric-total-rules", Static).update(
            f"[dim]Rules Tested[/dim]\n[bold white]{tot_rules}[/bold white]"
        )
        self.query_one("#metric-version-matched", Static).update(
            f"[dim]Version Matched[/dim]\n[bold cyan]{ver_match}[/bold cyan]"
        )
        self.query_one("#metric-exploitable", Static).update(
            f"[dim]EXPLOITABLE[/dim]\n[bold red]{exp}[/bold red]"
        )
        self.query_one("#metric-mitigated", Static).update(
            f"[dim]MITIGATED[/dim]\n[bold green]{mit}[/bold green]"
        )
        self.query_one("#metric-in-kev", Static).update(
            f"[dim]In CISA KEV[/dim]\n[bold magenta]{kev}[/bold magenta]"
        )
        self.query_one("#metric-crithigh", Static).update(
            f"[dim]Critical / High[/dim]\n[bold red]{crit}[/bold red] / [bold yellow]{high}[/bold yellow]"
        )

    def _render_vuln_detail(
        self, vuln: Dict[str, Any], dev_info: Dict[str, Any]
    ) -> str:
        """Render comprehensive vulnerability detail panel in Markdown format."""
        cve_id = vuln.get("cve_id", "N/A")
        title = vuln.get("title", "")
        status = vuln.get("status", "")
        real_risk = vuln.get("real_risk", "")
        score = vuln.get("base_score", "N/A")
        cvss = score
        vector = vuln.get("cvss_vector") or "N/A"
        in_kev = vuln.get("in_kev", False)
        kev_details = vuln.get("kev_details", {})
        precond_desc = vuln.get("precondition_description", "N/A")
        precond_met = vuln.get("precondition_met", False)
        feature_evidence = (
            vuln.get("feature_evidence")
            or "No direct configuration evidence pattern matched."
        )
        mitigation_reason = (
            vuln.get("mitigation_reason") or "No specific mitigation reason recorded."
        )
        mit_cmd = vuln.get("mitigation_cmd", "N/A")
        affected_ver = vuln.get("affected_versions", "N/A")
        vendor = vuln.get("vendor") or dev_info.get("vendor", "N/A")
        os_fam = vuln.get("os_family") or dev_info.get("os_family", "N/A")
        desc = vuln.get("description", "No description available.")
        refs = vuln.get("references", [])
        dev_ver = dev_info.get("version", "N/A")

        status_badge = f"`[{status}]`"
        risk_badge = f"`{real_risk}`"
        kev_badge = "In CISA KEV" if in_kev else "Not in KEV"
        kev_header_badge = f"`{kev_badge}`" if in_kev else f"*{kev_badge}*"
        precond_status = (
            "**Active in running-config (VULNERABLE / EXPLOITABLE)**"
            if precond_met
            else "**Disabled or Absent (ATTACK SURFACE NEUTRALIZED)**"
        )

        lines = [
            f"# {cve_id} — {title}",
            "",
            f"**Status:** {status_badge}  |  **Real Risk:** {risk_badge}  |  **CVSS:** **{score}** (`{vector}`)  |  **Catalog:** {kev_header_badge}",
            "",
            "| Thuộc tính | Chi tiết |",
            "| :--- | :--- |",
            f"| **Trạng thái** | `{status}` |",
            f"| **Triage Status** | `[{status}]` |",
            f"| **Mức độ Rủi ro** | `{real_risk}` |",
            f"| **Điểm CVSS v3.1** | `{cvss}` |",
            f"| **CISA KEV** | `{kev_badge}` |",
            f"| **Lý do Triage** | {mitigation_reason} |",
            f"| **Bằng chứng Cấu hình** | `{feature_evidence}` |",
            f"| **Hãng & OS** | `{vendor} ({os_fam})` |",
            f"| **Dải ảnh hưởng** | `{affected_ver}` |",
            "",
            "---",
            "",
            "### Triage Assessment & Configuration Evidence",
            f"- **Triage Status:** `[{status}]`",
            f"- **Triage Reason:** {mitigation_reason}",
            f"- **Configuration Evidence (`feature_evidence`):** `{feature_evidence}`",
            f"- **Precondition Evaluated:** {precond_desc}",
            f"- **Precondition Met:** `{'YES' if precond_met else 'NO'}`",
            f"- **Config Audit State:** {precond_status}",
            "",
            "### Precondition Requirement & Audit Evidence",
            f"- **Condition Required:** {precond_desc}",
            f"- **Config Audit State:** {precond_status}",
            f"- **Feature Evidence:** `{feature_evidence}`",
            f"- **Triage Reason:** {mitigation_reason}",
            "",
            "### Affected OS Version Range",
            f"- **Affected Range:** `{affected_ver}`",
            f"- **Running Version:** `{dev_ver}` (Matches necessary condition)",
            "",
            "### Mitigation Playbook & Remediation Command",
            "```text",
            f"{mit_cmd}",
            "```",
            "",
        ]

        if in_kev and kev_details:
            due = kev_details.get("due_date", "N/A")
            action = kev_details.get("required_action", "N/A")
            campaign = kev_details.get("ransomware_campaign", "Unknown")
            notes = kev_details.get("notes", "")
            lines.extend(
                [
                    "### CISA KEV Threat Intelligence",
                    f"- **Remediation Due Date:** `{due}`",
                    f"- **Mandatory Action:** {action}",
                    f"- **Ransomware Campaign:** `{campaign}`",
                ]
            )
            if notes:
                lines.append(f"- **Advisory Notes:** {notes}")
            lines.append("")

        lines.extend(
            [
                "### Technical Description",
                f"{desc}",
            ]
        )

        if refs:
            lines.append("")
            lines.append("### References")
            for ref in refs:
                lines.append(f"- [{ref}]({ref})")

        return "\n".join(lines)

    def _export_format(self, fmt: str) -> None:
        """Export current audit report to specified file format."""
        if not self.current_audit_result:
            self.notify(
                "Please scan a configuration file before exporting.",
                title="No Scan Data",
                severity="warning",
            )
            return

        dev_info = self.current_audit_result.get("device_info", {})
        hostname = dev_info.get("hostname", "device")
        safe_name = "".join(
            c if c.isalnum() or c in ("-", "_") else "_" for c in hostname
        )
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

        if fmt == "md":
            target = OUTPUTS_DIR / f"{safe_name}_report.md"
            self.reporter.export_markdown(self.current_audit_result, target)
            self.notify(
                f"Markdown report saved: {target.name}",
                title="Export Markdown",
                severity="information",
            )
        elif fmt == "xlsx":
            target = OUTPUTS_DIR / f"{safe_name}_report.xlsx"
            self.reporter.export_excel(self.current_audit_result, target)
            self.notify(
                f"Excel report saved: {target.name}",
                title="Export Excel",
                severity="information",
            )
        elif fmt == "json":
            target = OUTPUTS_DIR / f"{safe_name}_report.json"
            self.reporter.export_json(self.current_audit_result, target)
            self.notify(
                f"JSON report saved: {target.name}",
                title="Export JSON",
                severity="information",
            )

    # =========================================================================
    # TAB 2: VERSION LOOKUP LOGIC
    # =========================================================================

    def run_version_lookup(self, vendor_key: str, version: str) -> None:
        """Evaluate vulnerabilities based purely on vendor and version string."""
        vendor_key = vendor_key or "cisco_asa"
        version_str = version.strip()
        if not version_str:
            self.notify(
                "Please enter an OS version string (e.g. 9.20(3), 17.6, 7.2.4).",
                title="Version Required",
                severity="warning",
            )
            return

        mapping = VENDOR_MAP.get(vendor_key, (VENDOR_CISCO, OS_CISCO_ASA))
        vendor, os_family = mapping

        results = self.engine.evaluate_version_only(
            vendor=vendor, os_family=os_family, version=version_str
        )
        self.lookup_vulns_map = {item["cve_id"]: item for item in results}

        # Update summary card
        summary_card = self.query_one("#lookup-summary-card", Static)
        status_col = "red" if results else "green"
        summary_card.update(
            f"[bold cyan]Vendor:[/bold cyan] {vendor}  |  "
            f"[bold cyan]OS Family:[/bold cyan] {os_family}  |  "
            f"[bold cyan]Version:[/bold cyan] [bold yellow]{version_str}[/bold yellow]  |  "
            f"[bold]Potential CVEs Matched:[/bold] [bold {status_col}]{len(results)}[/bold {status_col}]  |  "
            f"[dim]Run full device config scan to verify if feature preconditions are active[/dim]"
        )

        table = self.query_one("#table-lookup-vulns", DataTable)
        table.clear()

        for item in results:
            cve_id = item.get("cve_id", "")
            title = item.get("title", "")
            score_txt = str(item.get("base_score", ""))
            kev_txt = (
                Text("YES", style="bold red")
                if item.get("in_kev")
                else Text("NO", style="dim")
            )
            precond_txt = item.get("precondition_description", "")
            mit_txt = item.get("mitigation_cmd", "")

            table.add_row(
                cve_id,
                title[:38] + ("..." if len(title) > 38 else ""),
                score_txt,
                kev_txt,
                precond_txt[:40] + ("..." if len(precond_txt) > 40 else ""),
                mit_txt[:45] + ("..." if len(mit_txt) > 45 else ""),
                key=cve_id,
            )

        detail_panel = self.query_one("#lookup-detail-panel", Static)
        if results:
            table.move_cursor(row=0)
            detail_panel.update(self._render_lookup_detail(results[0]))
            self.query_one("#lookup-detail-container", VerticalScroll).scroll_to(
                y=0, animate=False
            )
        else:
            detail_panel.update(
                f"[bold green]✔ No known CVE rules match {os_family} version {version_str}.[/bold green]"
            )

    def _render_lookup_detail(self, item: Dict[str, Any]) -> str:
        """Render lookup vulnerability details."""
        cve_id = item.get("cve_id", "N/A")
        title = item.get("title", "")
        score = item.get("base_score", "N/A")
        in_kev = item.get("in_kev", False)
        precond = item.get("precondition_description", "N/A")
        mit = item.get("mitigation_cmd", "N/A")
        desc = item.get("description", "No description available.")
        affected = item.get("affected_versions", "N/A")

        kev_badge = (
            "[bold white on #9333ea] CISA KEV [/]"
            if in_kev
            else "[dim][Not in KEV][/dim]"
        )

        return (
            "[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n"
            f"[bold white]{cve_id}[/bold white] - [bold yellow]{title}[/bold yellow]  |  "
            f"CVSS: [bold]{score}[/bold]  {kev_badge}\n"
            "[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n"
            "[bold magenta]► Precondition Required to Exploit (Sufficient Condition):[/bold magenta]\n"
            f"  • {precond}\n"
            "\n"
            "[bold cyan]► Affected Version Range (Necessary Condition):[/bold cyan]\n"
            f"  • [yellow]{affected}[/yellow]\n"
            "\n"
            "[bold green]► Mitigation Playbook & Remediation Command:[/bold green]\n"
            f"  [bold white on #1e293b] {mit} [/bold white on #1e293b]\n"
            "\n"
            "[bold white]► Technical Description:[/bold white]\n"
            f"  {desc}"
        )

    # =========================================================================
    # TAB 3: CISA KEV EXPLORER LOGIC
    # =========================================================================

    def load_kev_catalog(
        self,
        filter_kw: Optional[str] = None,
        vendor_filter: Optional[str] = None,
        ransomware_only: bool = False,
    ) -> None:
        """Filter and render CISA KEV catalog entries."""
        all_cves = self.cisa_fetcher.get_all_cves()
        filtered: List[Dict[str, Any]] = []

        for rec in all_cves:
            cve_id = rec.get("cveID", "").lower()
            vendor = rec.get("vendorProject", "").lower()
            prod = rec.get("product", "").lower()
            vuln_name = rec.get("vulnerabilityName", "").lower()
            desc = rec.get("shortDescription", "").lower()
            ransom = rec.get("knownRansomwareCampaignUse", "").lower()

            if ransomware_only and ransom != "known":
                continue

            if vendor_filter and vendor_filter.lower() not in vendor:
                continue

            if filter_kw:
                kw = filter_kw.lower().strip()
                if not (
                    kw in cve_id
                    or kw in vendor
                    or kw in prod
                    or kw in vuln_name
                    or kw in desc
                ):
                    continue

            filtered.append(rec)

        self.kev_records_map = {rec["cveID"]: rec for rec in filtered}

        table = self.query_one("#table-kev", DataTable)
        table.clear()

        for rec in filtered:
            cve_id = rec.get("cveID", "")
            vendor = rec.get("vendorProject", "")
            product = rec.get("product", "")
            vuln_name = rec.get("vulnerabilityName", "")
            date_added = rec.get("dateAdded", "")
            due_date = rec.get("dueDate", "")
            ransom = rec.get("knownRansomwareCampaignUse", "")
            if ransom.lower() == "known":
                ransom_txt = Text("KNOWN", style="bold white on #dc2626")
            else:
                ransom_txt = Text(ransom or "Unknown", style="dim")

            table.add_row(
                cve_id,
                vendor[:18],
                product[:25] + ("..." if len(product) > 25 else ""),
                vuln_name[:35] + ("..." if len(vuln_name) > 35 else ""),
                date_added,
                due_date,
                ransom_txt,
                key=cve_id,
            )

        # Update count label
        count_lbl = self.query_one("#label-kev-count", Label)
        count_lbl.update(f"Showing {len(filtered)} / {len(all_cves)} KEV Records")

        detail = self.query_one("#kev-detail-content", Markdown)
        if filtered:
            table.move_cursor(row=0)
            detail.update(self._render_kev_detail(filtered[0]))
            self.query_one("#kev-detail-container", VerticalScroll).scroll_to(
                y=0, animate=False
            )
        else:
            detail.update("*No KEV records match the current filter query.*")

    def _render_kev_detail(self, rec: Dict[str, Any]) -> str:
        """Render CISA KEV catalog entry details in Markdown format."""
        cve_id = rec.get("cveID", "N/A")
        vendor = rec.get("vendorProject", "Unknown")
        product = rec.get("product", "Unknown")
        vuln_name = rec.get("vulnerabilityName", "N/A")
        date_added = rec.get("dateAdded", "N/A")
        due_date = rec.get("dueDate", "N/A")
        ransomware = rec.get("knownRansomwareCampaignUse", "Unknown")
        action = rec.get("requiredAction", "N/A")
        desc = rec.get("shortDescription", "No description provided.")
        notes = rec.get("notes", "")

        ransom_badge = (
            "**`KNOWN RANSOMWARE CAMPAIGN USE`**"
            if ransomware.lower() == "known"
            else f"`Ransomware: {ransomware}`"
        )

        lines = [
            f"# {cve_id} — {vuln_name}",
            "",
            f"**Vendor:** `{vendor}`  |  **Product:** `{product}`  |  **Threat:** {ransom_badge}",
            "",
            "| Thuộc tính KEV | Giá trị |",
            "| :--- | :--- |",
            f"| **Mã CVE** | `{cve_id}` |",
            f"| **Hãng sản xuất** | `{vendor}` |",
            f"| **Sản phẩm** | `{product}` |",
            f"| **Ngày công bố KEV** | `{date_added}` |",
            f"| **Hạn chót xử lý** | `{due_date}` |",
            f"| **Chiến dịch Ransomware** | `{ransomware}` |",
            "",
            "---",
            "",
            "### Federal Remediation Timeline & Requirement",
            f"- **Date Added to Catalog:** `{date_added}`",
            f"- **Remediation Due Date:** `{due_date}`",
            f"- **Mandatory Action:** {action}",
            "",
            "### Vulnerability Summary",
            f"{desc}",
        ]
        if notes:
            lines.extend(
                [
                    "",
                    "### Advisory & Reference Notes",
                    f"{notes}",
                ]
            )

        return "\n".join(lines)

    # =========================================================================
    # TAB 4: DATABASE STATUS & SYNCHRONIZATION
    # =========================================================================

    def render_db_status(self) -> None:
        """Render database status and sync metadata into Tab 4."""
        from src.fetcher_cisa import get_cisa_fetcher
        from src.fetcher_nvd import NVDDatabase

        db = NVDDatabase()
        cve_count = db.get_cve_count()
        kev_count = get_cisa_fetcher().count()
        metadata = db.get_all_sync_metadata()

        lines = [
            "# Vulnerability Database Health & Sync Status",
            "",
            f"**SQLite Database Path:** `{db.db_path}`",
            "",
            "| Chỉ số | Giá trị |",
            "| :--- | :--- |",
            f"| **Tổng số NVD CVE Records** | `{cve_count:,}` |",
            f"| **Tổng số CISA KEV Catalog** | `{kev_count:,}` |",
            "| **Cơ chế đồng bộ** | NIST NVD API 2.0 (Incremental) + CISA KEV JSON Feed |",
            "",
            "---",
            "",
            "### Chi tiết lịch sử đồng bộ (Sync Metadata)",
            "",
            "| Nguồn dữ liệu | Thời gian đồng bộ gần nhất (UTC) | Trạng thái | Số bản ghi | Chi tiết |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]

        if not metadata:
            lines.append(
                "| `NVD Offline Seed` | `Initial Seed` | `ACTIVE` | "
                f"`{cve_count:,}` | Pre-seeded offline bundle |"
            )
            lines.append(
                "| `CISA KEV Catalog` | `Initial Seed` | `ACTIVE` | "
                f"`{kev_count:,}` | Official CISA KEV catalog |"
            )
        else:
            for m in metadata:
                source = m.get("source", "")
                ts = m.get("last_sync_timestamp", "N/A")
                status = m.get("status", "")
                count = m.get("record_count", 0)
                details = m.get("details", "")
                lines.append(
                    f"| `{source}` | `{ts}` | `{status.upper()}` | `{count}` | {details} |"
                )

        detail = self.query_one("#db-status-content", Markdown)
        detail.update("\n".join(lines))

    def run_db_sync(self) -> None:
        """Trigger incremental database synchronization in TUI."""
        from src.fetcher_cisa import get_cisa_fetcher

        detail = self.query_one("#db-status-content", Markdown)
        detail.update(
            "### ⏳ Synchronizing Database...\nChecking CISA KEV and NVD updates..."
        )

        # Update CISA KEV
        cisa_res = get_cisa_fetcher().sync_incremental()
        self.render_db_status()
        self.notify(
            f"Database sync finished: CISA KEV {cisa_res.get('status')}",
            title="Database Update",
        )


if __name__ == "__main__":
    app = VulnCheckApp()
    app.run()
