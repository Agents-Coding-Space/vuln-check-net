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
    RISK_CRITICAL,
    RISK_HIGH,
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
from src.fetcher_cisa import CisaKevFetcher
from src.parser import ConfigParser
from src.reporter import Reporter

console = Console()


def render_banner() -> None:
    """Display CLI banner."""
    banner = (
        "[bold cyan]Vuln-Check-Net[/bold cyan] : [bold white]Multi-Vendor Network CVE Audit Engine[/bold white]\n"
        "[dim]Two-Condition Correlation (Version Range + Active Preconditions) | CISA KEV & NVD Intelligence[/dim]"
    )
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))


def print_device_audit(result: dict) -> None:
    """Print terminal summary and vulnerability findings for a device."""
    info = result.get("device_info", {})
    summary = result.get("summary", {})
    vulns = result.get("vulnerabilities", [])

    # Device Metadata Table
    dev_table = Table(
        title=f"Device Audit: [bold yellow]{info.get('hostname')}[/bold yellow]",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    dev_table.add_column("Property", style="bold white", width=18)
    dev_table.add_column("Value", style="cyan")

    dev_table.add_row("Hostname", info.get("hostname", "UNKNOWN"))
    dev_table.add_row("Domain Name", info.get("domain_name") or "N/A")
    dev_table.add_row("Vendor", info.get("vendor", "Unknown"))
    dev_table.add_row("OS Family", info.get("os_family", "Unknown"))
    dev_table.add_row("OS Version", f"[bold green]{info.get('version', 'N/A')}[/bold green]")
    dev_table.add_row("Hardware Model", info.get("model", "Unknown"))

    features = info.get("features", {})
    active_feats = [k for k, v in features.items() if v]
    inactive_feats = [k for k, v in features.items() if not v]
    dev_table.add_row(
        "Active Features",
        ", ".join(f"[red]{f}[/red]" for f in active_feats) if active_feats else "[dim]None[/dim]",
    )
    dev_table.add_row(
        "Inactive Features",
        ", ".join(f"[dim green]{f}[/dim green]" for f in inactive_feats) if inactive_feats else "[dim]None[/dim]",
    )
    console.print(dev_table)

    # Executive Summary Counters
    exp_cnt = summary.get("exploitable_count", 0)
    mit_cnt = summary.get("mitigated_count", 0)
    kev_cnt = summary.get("in_kev_count", 0)
    crit_cnt = summary.get("critical_count", 0)
    high_cnt = summary.get("high_count", 0)

    summary_text = (
        f"[bold]Rules Tested:[/bold] {summary.get('total_rules_evaluated', 0)} | "
        f"[bold]Version Matched:[/bold] {summary.get('total_affected_versions', 0)} | "
        f"[bold red]EXPLOITABLE:[/bold red] {exp_cnt} | "
        f"[bold green]MITIGATED:[/bold green] {mit_cnt} | "
        f"[bold magenta]CISA KEV:[/bold magenta] {kev_cnt} | "
        f"[bold red]CRITICAL:[/bold red] {crit_cnt} | "
        f"[bold yellow]HIGH:[/bold yellow] {high_cnt}"
    )
    border_col = "red" if exp_cnt > 0 else "green"
    console.print(Panel(summary_text, title="Audit Metrics", border_style=border_col))

    # Vulnerability Table
    if not vulns:
        console.print("[green]✔ No matching vulnerabilities found for this device OS version.[/green]\n")
        return

    v_table = Table(box=box.SIMPLE_HEAVY, header_style="bold magenta")
    v_table.add_column("CVE ID", style="bold white", width=16)
    v_table.add_column("Title", width=34)
    v_table.add_column("Status", width=13, justify="center")
    v_table.add_column("Real Risk", width=11, justify="center")
    v_table.add_column("CVSS", width=6, justify="center")
    v_table.add_column("KEV", width=9, justify="center")
    v_table.add_column("Precondition Requirement", width=38)

    for v in vulns:
        st = v.get("status", "")
        if st == STATUS_EXPLOITABLE:
            st_text = "[bold white on red] EXPLOITABLE [/]"
        else:
            st_text = "[bold white on green] MITIGATED [/]"

        risk = v.get("real_risk", "")
        if risk == RISK_CRITICAL:
            risk_text = "[bold red]CRITICAL[/]"
        elif risk == RISK_HIGH:
            risk_text = "[bold yellow]HIGH[/]"
        else:
            risk_text = f"[green]{risk}[/green]"

        kev_text = "[bold red]YES[/]" if v.get("in_kev") else "[dim]NO[/dim]"

        v_table.add_row(
            v.get("cve_id"),
            v.get("title")[:32] + "..." if len(v.get("title", "")) > 32 else v.get("title", ""),
            st_text,
            risk_text,
            str(v.get("base_score", "")),
            kev_text,
            v.get("precondition_description", ""),
        )

    console.print(v_table)
    console.print("")


def handle_scan(args: argparse.Namespace) -> None:
    """Handle `scan` subcommand."""
    files_to_scan: List[Path] = []

    if args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            console.print(f"[bold red]Error: Specified file not found: {fpath}[/bold red]")
            sys.exit(1)
        files_to_scan.append(fpath)

    elif args.dir:
        dpath = Path(args.dir)
        if not dpath.exists() or not dpath.is_dir():
            console.print(f"[bold red]Error: Specified directory not found: {dpath}[/bold red]")
            sys.exit(1)
        for ext in ("*.txt", "*.cfg", "*.conf", "*.log"):
            files_to_scan.extend(dpath.glob(ext))

    if not files_to_scan:
        console.print("[bold yellow]No configuration files found to scan.[/bold yellow]")
        sys.exit(1)

    parser = ConfigParser()
    engine = CorrelationEngine()
    reporter = Reporter()

    all_results = []

    with console.status(f"[cyan]Auditing {len(files_to_scan)} configuration file(s)...[/cyan]") as status:
        for f in files_to_scan:
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                parsed = parser.parse(content)
                result = engine.evaluate_device(parsed)
                all_results.append(result)
            except Exception as e:
                console.print(f"[red]Error parsing {f.name}: {e}[/red]")

    for r in all_results:
        print_device_audit(r)

    # Export reports if requested
    if args.out_md:
        out_p = reporter.export_markdown(all_results, args.out_md)
        console.print(f"[bold green]✔ Markdown report exported to: {out_p}[/bold green]")

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
    results = engine.evaluate_version_only(vendor=vendor, os_family=os_family, version=version)

    console.print(
        Panel(
            f"[bold]Vendor:[/bold] {vendor} | [bold]OS Family:[/bold] {os_family} | [bold]Version:[/bold] [yellow]{version}[/yellow]\n"
            f"[dim]Potential vulnerabilities based on version range. Run a full config scan to verify preconditions.[/dim]",
            title="Version Vulnerability Lookup",
            border_style="cyan",
        )
    )

    if not results:
        console.print(f"[green]✔ No known CVE rules match {os_family} version {version}.[/green]")
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
            item.get("title")[:32] + "..." if len(item.get("title", "")) > 32 else item.get("title", ""),
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
        console.print(f"[bold green]✔ Successfully updated CISA KEV catalog! New count: {fetcher.count()}[/bold green]")
    else:
        console.print("[yellow]Notice: Could not update from internet. Retaining cached/seed data.[/yellow]")


def main() -> None:
    """Main CLI entry point."""
    render_banner()

    parser = argparse.ArgumentParser(
        prog="python run_scan.py",
        description="Multi-Vendor Network CVE Audit Engine (Vuln-Check-Net)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # scan subcommand
    p_scan = subparsers.add_parser("scan", help="Scan network device configuration file or directory")
    p_scan.add_argument("--file", "-f", help="Path to single configuration file")
    p_scan.add_argument("--dir", "-d", help="Path to directory containing configuration files")
    p_scan.add_argument("--out-md", help="Path to export Markdown report (.md)")
    p_scan.add_argument("--out-xlsx", help="Path to export Excel workbook (.xlsx)")
    p_scan.add_argument("--out-json", help="Path to export JSON output (.json)")

    # lookup subcommand
    p_lookup = subparsers.add_parser("lookup", help="Look up potential CVEs by vendor and OS version")
    p_lookup.add_argument("--vendor", "-v", required=True, help="Vendor (e.g. Cisco, Fortinet, Palo Alto)")
    p_lookup.add_argument("--version", "-ver", required=True, help="OS version string (e.g. 9.20(3), 17.3.1, 7.2.4)")
    p_lookup.add_argument("--os", help="Specific OS family (e.g. 'Cisco ASA', 'Cisco IOS XE')")

    # update-kev subcommand
    subparsers.add_parser("update-kev", help="Fetch latest CISA Known Exploited Vulnerabilities catalog")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    if args.subcommand == "scan":
        if not args.file and not args.dir:
            p_scan.print_help()
            console.print("[bold red]\nError: You must provide either --file or --dir[/bold red]")
            sys.exit(1)
        handle_scan(args)
    elif args.subcommand == "lookup":
        handle_lookup(args)
    elif args.subcommand == "update-kev":
        handle_update_kev(args)


if __name__ == "__main__":
    main()
