#!/usr/bin/env python3
"""Vuln-Check-Net: Multi-Vendor Network CVE Audit Engine.

Command-line interface for assessing network device configurations
against known vulnerabilities with precondition correlation.
"""

import argparse
import sys
from pathlib import Path
from typing import List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.config import (
    OS_ARBOR_ARBOS,
    OS_CISCO_ASA,
    OS_CISCO_IOS_XE,
    OS_F5_BIGIP,
    OS_FORTINET_FORTIOS,
    OS_IMPERVA_SECURESPHERE,
    OS_PALOALTO_PANOS,
    VENDOR_CISCO,
    VENDOR_F5,
    VENDOR_FORTINET,
    VENDOR_IMPERVA,
    VENDOR_NETSCOUT,
    VENDOR_PALOALTO,
)
from src.engine import CorrelationEngine
from src.fetcher_cisa import CisaKevFetcher
from src.reporter import Reporter

console = Console()


def render_banner() -> None:
    """Display CLI banner."""
    banner = (
        "[bold cyan]Vuln-Check-Net[/bold cyan] : [bold white]Multi-Vendor Network CVE Audit Engine[/bold white]\n"
        "[dim]Two-Condition Correlation (Version Range + Active Preconditions) | CISA KEV & NVD Intelligence[/dim]\n"
        "[bold green]Authoritative Data Source: NIST NVD API 2.0 (Local SQLite Cache) + CISA KEV Feed[/bold green]"
    )
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))


def print_device_audit(
    result: dict,
    filter_triage: str = "all",
    kev_only: bool = False,
    out_console: Console = console,
) -> None:
    """Print terminal summary and vulnerability findings for a device."""
    reporter = Reporter()
    reporter.print_device_audit(
        result,
        filter_triage=filter_triage,
        kev_only=kev_only,
        console=out_console,
    )


def handle_scan(args: argparse.Namespace) -> None:
    """Handle `scan` subcommand."""
    files_to_scan: List[Path] = []

    if args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            console.print(
                f"[bold red]Error: Specified file not found: {fpath}[/bold red]"
            )
            sys.exit(1)
        files_to_scan.append(fpath)

    elif args.dir:
        dpath = Path(args.dir)
        if not dpath.exists() or not dpath.is_dir():
            console.print(
                f"[bold red]Error: Specified directory not found: {dpath}[/bold red]"
            )
            sys.exit(1)
        for ext in ("*.txt", "*.cfg", "*.conf", "*.log"):
            files_to_scan.extend(dpath.glob(ext))

    if not files_to_scan:
        console.print(
            "[bold yellow]No configuration files found to scan.[/bold yellow]"
        )
        sys.exit(1)

    engine = CorrelationEngine()
    reporter = Reporter()

    all_results = []

    with console.status(
        f"[cyan]Auditing {len(files_to_scan)} configuration file(s)...[/cyan]"
    ):
        for f in files_to_scan:
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                result = engine.scan_config(content, filename=str(f.name))
                all_results.append(result)
            except Exception as e:
                console.print(f"[red]Error parsing {f.name}: {e}[/red]")

    for r in all_results:
        reporter.print_device_audit(
            r,
            filter_triage=getattr(args, "triage", "all"),
            kev_only=getattr(args, "kev_only", False),
            console=console,
        )

    # Export reports if requested
    if args.out_md:
        out_p = reporter.export_markdown(all_results, args.out_md)
        console.print(
            f"[bold green]✔ Markdown report exported to: {out_p}[/bold green]"
        )

    if args.out_xlsx:
        out_p = reporter.export_excel(all_results, args.out_xlsx)
        console.print(f"[bold green]✔ Excel report exported to: {out_p}[/bold green]")

    if args.out_json:
        out_p = reporter.export_json(all_results, args.out_json)
        console.print(f"[bold green]✔ JSON report exported to: {out_p}[/bold green]")


def handle_lookup(args: argparse.Namespace) -> None:
    """Handle `lookup` subcommand."""
    vendor = args.vendor
    version = args.version

    # Guess os_family if not provided
    os_family = args.os
    if not os_family:
        vl = vendor.lower()
        if "asa" in vl:
            os_family = OS_CISCO_ASA
            vendor = VENDOR_CISCO
        elif "xe" in vl or "ios" in vl:
            os_family = OS_CISCO_IOS_XE
            vendor = VENDOR_CISCO
        elif "forti" in vl:
            os_family = OS_FORTINET_FORTIOS
            vendor = VENDOR_FORTINET
        elif "palo" in vl or "pan" in vl:
            os_family = OS_PALOALTO_PANOS
            vendor = VENDOR_PALOALTO
        elif "f5" in vl or "bigip" in vl:
            os_family = OS_F5_BIGIP
            vendor = VENDOR_F5
        elif "arbor" in vl or "arbos" in vl or "sightline" in vl or "netscout" in vl:
            os_family = OS_ARBOR_ARBOS
            vendor = VENDOR_NETSCOUT
        elif "imperva" in vl or "securesphere" in vl:
            os_family = OS_IMPERVA_SECURESPHERE
            vendor = VENDOR_IMPERVA
        else:
            os_family = OS_CISCO_ASA

    engine = CorrelationEngine()
    results = engine.evaluate_version_only(
        vendor=vendor, os_family=os_family, version=version
    )

    if getattr(args, "kev_only", False):
        results = [r for r in results if r.get("in_kev")]
    if getattr(args, "triage", "all") != "all":
        target = args.triage.strip().lower()
        results = [
            r
            for r in results
            if (r.get("status") or r.get("triage_status", "")).strip().lower() == target
        ]

    console.print(
        Panel(
            f"[bold]Vendor:[/bold] {vendor} | [bold]OS Family:[/bold] {os_family} | [bold]Version:[/bold] [yellow]{version}[/yellow]\n"
            f"[dim]Potential vulnerabilities based on version range. Run a full config scan to verify preconditions.[/dim]\n"
            f"[bold green]Authoritative Data Source: NIST NVD API 2.0 (Local SQLite Cache) + CISA KEV Feed[/bold green]",
            title="Version Vulnerability Lookup",
            border_style="cyan",
        )
    )

    if not results:
        console.print(
            f"[green]✔ No known CVE rules match {os_family} version {version}.[/green]"
        )
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("CVE ID", style="bold white", width=16)
    table.add_column("Title", width=34)
    table.add_column("CVSS", width=6, justify="center")
    table.add_column("KEV", width=7, justify="center")
    table.add_column("Precondition Needed to Exploit", width=38)
    table.add_column("Mitigation Command", width=40)

    for item in results:
        kev_txt = "[bold red]YES[/]" if item.get("in_kev") else "[dim]NO[/dim]"
        table.add_row(
            item.get("cve_id"),
            item.get("title")[:32] + "..."
            if len(item.get("title", "")) > 32
            else item.get("title", ""),
            str(item.get("base_score", "")),
            kev_txt,
            item.get("precondition_description", ""),
            item.get("mitigation_cmd", ""),
        )

    console.print(table)


def handle_update_kev(args: argparse.Namespace) -> None:
    """Handle `update-kev` subcommand."""
    fetcher = CisaKevFetcher()
    console.print(f"Current local CISA KEV count: [cyan]{fetcher.count()}[/cyan]")
    console.print("[yellow]Updating CISA KEV catalog from official feed...[/yellow]")
    success = fetcher.update_cache(force=True)
    if success:
        console.print(
            f"[bold green]✔ Successfully updated CISA KEV catalog! New count: {fetcher.count()}[/bold green]"
        )
    else:
        console.print(
            "[yellow]Notice: Could not update from internet. Retaining cached/seed data.[/yellow]"
        )


def handle_db_status(args: argparse.Namespace) -> None:
    """Handle `db status` subcommand."""
    from src.fetcher_nvd import NVDDatabase

    db = NVDDatabase()
    cve_count = db.get_cve_count()
    kev_fetcher = CisaKevFetcher()
    metadata = db.get_all_sync_metadata()

    console.print(
        Panel(
            f"[bold cyan]Local SQLite Database:[/bold cyan] {db.db_path}\n"
            f"[bold white]Total NVD CVE Records:[/bold white] [green]{cve_count:,}[/green]\n"
            f"[bold white]Total CISA KEV Catalog:[/bold white] [yellow]{kev_fetcher.count():,}[/yellow]",
            title="Database Status & Synchronization Health",
            border_style="cyan",
        )
    )

    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Data Source", style="bold white", width=26)
    table.add_column("Last Sync (UTC)", width=24)
    table.add_column("Status", width=14, justify="center")
    table.add_column("Records", width=10, justify="right")
    table.add_column("Details", width=36)

    if not metadata:
        # Show default summary if no metadata table records yet
        table.add_row(
            "NVD Offline Seed",
            "Initial Seed",
            "[green]ACTIVE[/green]",
            f"{cve_count:,}",
            "Pre-seeded offline bundle",
        )
        table.add_row(
            "CISA KEV Catalog",
            "Initial Seed",
            "[green]ACTIVE[/green]",
            f"{kev_fetcher.count():,}",
            "Official CISA KEV catalog",
        )
    else:
        for m in metadata:
            status_style = (
                "[green]SUCCESS[/green]"
                if m.get("status") in ("success", "up_to_date")
                else "[red]FAILED[/red]"
            )
            table.add_row(
                m.get("source", ""),
                m.get("last_sync_timestamp", "N/A"),
                status_style,
                str(m.get("record_count", 0)),
                m.get("details", "")[:34],
            )

    console.print(table)


def handle_db_update(args: argparse.Namespace) -> None:
    """Handle `db update` subcommand."""
    from src.fetcher_nvd import NVDFetcher

    fetcher = NVDFetcher()
    days_back = args.days
    force_full = args.full
    target_product = args.product.lower() if args.product else "all"

    console.print(
        Panel(
            f"[bold]Mode:[/bold] {'FULL SYNC' if force_full else f'INCREMENTAL SYNC ({days_back} days window)'}\n"
            f"[bold]Target Product:[/bold] {target_product.upper()}\n"
            f"[dim]Synchronizing with NIST NVD API 2.0 and CISA KEV feeds...[/dim]",
            title="Database Update",
            border_style="blue",
        )
    )

    # 1. Update CISA KEV
    console.print("[cyan]➜ Updating CISA KEV catalog...[/cyan]")
    cisa_res = CisaKevFetcher().sync_incremental(force=force_full)
    console.print(
        f"  [green]✔ CISA KEV Status:[/green] {cisa_res.get('status')} "
        f"(Total: {cisa_res.get('total_count')}, Added: {cisa_res.get('added_count')})"
    )

    # 2. Update NVD by Product
    cpe_map = {
        "cisco_asa": (
            "cisco",
            "adaptive_security_appliance",
            "cpe:2.3:o:cisco:adaptive_security_appliance_software",
        ),
        "cisco_ios_xe": ("cisco", "ios_xe", "cpe:2.3:o:cisco:ios_xe"),
        "fortinet_fortios": ("fortinet", "fortios", "cpe:2.3:o:fortinet:fortios"),
        "paloalto_panos": (
            "palo_alto_networks",
            "pan-os",
            "cpe:2.3:o:paloaltonetworks:pan-os",
        ),
    }

    products_to_sync = (
        cpe_map.keys()
        if target_product in ("all", "*")
        else [target_product]
        if target_product in cpe_map
        else []
    )

    if not products_to_sync:
        console.print(
            f"[red]Unknown product '{target_product}'. Choices: all, {', '.join(cpe_map.keys())}[/red]"
        )
        return

    for p in products_to_sync:
        vendor, product, cpe = cpe_map[p]
        console.print(f"[cyan]➜ Synchronizing NVD for {vendor}/{product}...[/cyan]")
        if force_full:
            count = fetcher.sync_product_cves(
                vendor=vendor, product=product, cpe_name=cpe, max_results=1000
            )
        else:
            count = fetcher.sync_incremental_cves(
                vendor=vendor,
                product=product,
                cpe_name=cpe,
                days_back=days_back,
                max_results=500,
            )
        console.print(f"  [green]✔ Synced {count} CVEs for {vendor}/{product}[/green]")

    console.print(
        "[bold green]\nDatabase synchronization finished successfully![/bold green]"
    )


def handle_tui(args: argparse.Namespace) -> None:
    """Handle `tui` subcommand."""
    from src.tui.app import VulnCheckApp

    app = VulnCheckApp(initial_file=args.file)
    app.run()


def check_startup_freshness() -> None:
    """Check database freshness on startup and notify if update is recommended."""
    from datetime import datetime, timezone
    from src.config import AUTO_UPDATE_ON_STARTUP, CACHE_EXPIRY_HOURS
    from src.fetcher_nvd import NVDDatabase

    if not AUTO_UPDATE_ON_STARTUP:
        return

    db = NVDDatabase()
    metadata = db.get_all_sync_metadata()
    if not metadata:
        return

    now_utc = datetime.now(timezone.utc)
    stale_sources = []

    for m in metadata:
        ts_str = m.get("last_sync_timestamp")
        if not ts_str:
            continue
        try:
            clean_ts = ts_str.rstrip("Z").split(".")[0]
            sync_dt = datetime.fromisoformat(clean_ts).replace(tzinfo=timezone.utc)
            hours_diff = (now_utc - sync_dt).total_seconds() / 3600.0
            if hours_diff > CACHE_EXPIRY_HOURS:
                stale_sources.append((m.get("source"), int(hours_diff)))
        except Exception:
            pass

    if stale_sources:
        console.print(
            f"[dim yellow]ℹ Notice: Local database was last updated over {CACHE_EXPIRY_HOURS} hours ago. "
            f"Run [bold cyan]python run_scan.py db update[/bold cyan] to sync the latest daily CVEs.[/dim yellow]"
        )


def main() -> None:
    """Main CLI entry point."""
    render_banner()
    check_startup_freshness()

    parser = argparse.ArgumentParser(
        prog="python run_scan.py",
        description="Multi-Vendor Network CVE Audit Engine (Vuln-Check-Net)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # scan subcommand
    p_scan = subparsers.add_parser(
        "scan", help="Scan network device configuration file or directory"
    )
    p_scan.add_argument("--file", "-f", help="Path to single configuration file")
    p_scan.add_argument(
        "--dir", "-d", help="Path to directory containing configuration files"
    )
    p_scan.add_argument(
        "--triage",
        "--filter-triage",
        dest="triage",
        choices=["all", "exploitable", "mitigated", "potential"],
        default="all",
        help="Filter findings by triage status (all, exploitable, mitigated, potential)",
    )
    p_scan.add_argument(
        "--kev-only",
        action="store_true",
        default=False,
        help="Filter findings to only CISA KEV cataloged vulnerabilities",
    )
    p_scan.add_argument("--out-md", help="Path to export Markdown report (.md)")
    p_scan.add_argument("--out-xlsx", help="Path to export Excel workbook (.xlsx)")
    p_scan.add_argument("--out-json", help="Path to export JSON output (.json)")

    # lookup subcommand
    p_lookup = subparsers.add_parser(
        "lookup", help="Look up potential CVEs by vendor and OS version"
    )
    p_lookup.add_argument(
        "--vendor", "-v", required=True, help="Vendor (e.g. Cisco, Fortinet, Palo Alto)"
    )
    p_lookup.add_argument(
        "--version",
        "-ver",
        required=True,
        help="OS version string (e.g. 9.20(3), 17.3.1, 7.2.4)",
    )
    p_lookup.add_argument(
        "--os", help="Specific OS family (e.g. 'Cisco ASA', 'Cisco IOS XE')"
    )
    p_lookup.add_argument(
        "--triage",
        "--filter-triage",
        dest="triage",
        choices=["all", "exploitable", "mitigated", "potential"],
        default="all",
        help="Filter findings by triage status (all, exploitable, mitigated, potential)",
    )
    p_lookup.add_argument(
        "--kev-only",
        action="store_true",
        default=False,
        help="Filter findings to only CISA KEV cataloged vulnerabilities",
    )

    # update-kev subcommand
    subparsers.add_parser(
        "update-kev", help="Fetch latest CISA Known Exploited Vulnerabilities catalog"
    )

    # db subcommand
    p_db = subparsers.add_parser(
        "db", help="Manage local vulnerability databases (NVD API 2.0 & CISA KEV)"
    )
    db_subparsers = p_db.add_subparsers(dest="db_action", help="DB action")

    # db status
    db_subparsers.add_parser("status", help="Show database sync status and health")

    # db update
    p_db_update = db_subparsers.add_parser(
        "update", help="Update database incrementally or fully from NVD and CISA"
    )
    p_db_update.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days back to sync modified CVEs (default: 7)",
    )
    p_db_update.add_argument(
        "--full",
        action="store_true",
        default=False,
        help="Perform full catalog sync instead of incremental window",
    )
    p_db_update.add_argument(
        "--product",
        choices=[
            "all",
            "cisco_asa",
            "cisco_ios_xe",
            "fortinet_fortios",
            "paloalto_panos",
        ],
        default="all",
        help="Specific product to sync (default: all)",
    )

    # tui subcommand
    p_tui = subparsers.add_parser(
        "tui", help="Launch interactive Terminal User Interface (TUI)"
    )
    p_tui.add_argument(
        "--file", "-f", help="Initial configuration file to audit in TUI"
    )

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    if args.subcommand == "scan":
        if not args.file and not args.dir:
            p_scan.print_help()
            console.print(
                "[bold red]\nError: You must provide either --file or --dir[/bold red]"
            )
            sys.exit(1)
        handle_scan(args)
    elif args.subcommand == "lookup":
        handle_lookup(args)
    elif args.subcommand == "update-kev":
        handle_update_kev(args)
    elif args.subcommand == "db":
        if args.db_action == "status":
            handle_db_status(args)
        elif args.db_action == "update":
            handle_db_update(args)
        else:
            p_db.print_help()
    elif args.subcommand == "tui":
        handle_tui(args)


if __name__ == "__main__":
    main()
