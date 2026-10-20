"""Unit and integration tests for CLI interface (run_scan.py)."""

import subprocess
import sys
from rich.console import Console

from run_scan import render_banner, print_device_audit


SAMPLE_CONFIG = """
Serial Number: JMX999999
: Hardware:   ASA5525, 4096 MB RAM
:
ASA Version 9.18(2)
!
hostname CLI-TEST-ASA
domain-name test.local
!
http server enable
http 0.0.0.0 0.0.0.0 outside
webvpn
 enable outside
!
"""


def test_cli_banner_contains_authoritative_sources():
    console = Console(record=True, width=120)
    # Temporarily monkeypatch console in run_scan
    import run_scan

    orig_console = run_scan.console
    try:
        run_scan.console = console
        render_banner()
        out = console.export_text()
        assert (
            "Authoritative Data Source: NIST NVD API 2.0 (Local SQLite Cache) + CISA KEV Feed"
            in out
        )
    finally:
        run_scan.console = orig_console


def test_cli_print_device_audit(tmp_path):
    from src.engine import CorrelationEngine
    from src.parser import ConfigParser

    parser = ConfigParser()
    parsed = parser.parse(SAMPLE_CONFIG)
    engine = CorrelationEngine()
    scan_res = engine.evaluate_device(
        parsed, config_text=SAMPLE_CONFIG, filename="sample.cfg"
    )

    console = Console(record=True, width=120)
    print_device_audit(scan_res, out_console=console)
    output = console.export_text()

    assert "Authoritative Data Source" in output
    assert "CLI-TEST-ASA" in output
    assert "NVD & Triage Intelligence Breakdown" in output
    assert "[EXPLOITABLE]" in output
    assert "[!] KEV" in output or "No" in output


def test_cli_scan_subcommand_via_subprocess(tmp_path):
    cfg_file = tmp_path / "test_cli_config.txt"
    cfg_file.write_text(SAMPLE_CONFIG.strip(), encoding="utf-8")

    # 1. Standard scan
    cmd = [sys.executable, "run_scan.py", "scan", "--file", str(cfg_file)]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert res.returncode == 0
    assert "Authoritative Data Source" in res.stdout
    assert "NIST NVD API 2.0" in res.stdout
    assert "CISA KEV" in res.stdout
    assert "CLI-TEST-ASA" in res.stdout
    assert "NVD & Triage Intelligence Breakdown" in res.stdout
    assert "[EXPLOITABLE]" in res.stdout

    # 2. Filter: --triage exploitable
    cmd_exp = [
        sys.executable,
        "run_scan.py",
        "scan",
        "--file",
        str(cfg_file),
        "--triage",
        "exploitable",
    ]
    res_exp = subprocess.run(
        cmd_exp,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert res_exp.returncode == 0
    assert "Triage: EXPLOITABLE" in res_exp.stdout
    assert "[EXPLOITABLE]" in res_exp.stdout

    # 3. Filter alias: --filter-triage exploitable
    cmd_alias = [
        sys.executable,
        "run_scan.py",
        "scan",
        "--file",
        str(cfg_file),
        "--filter-triage",
        "exploitable",
    ]
    res_alias = subprocess.run(
        cmd_alias,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert res_alias.returncode == 0
    assert "Triage: EXPLOITABLE" in res_alias.stdout

    # 4. Filter: --kev-only
    cmd_kev = [
        sys.executable,
        "run_scan.py",
        "scan",
        "--file",
        str(cfg_file),
        "--kev-only",
    ]
    res_kev = subprocess.run(
        cmd_kev,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert res_kev.returncode == 0
    assert "CISA KEV Only" in res_kev.stdout


def test_cli_lookup_subcommand_via_subprocess():
    cmd = [
        sys.executable,
        "run_scan.py",
        "lookup",
        "--vendor",
        "Cisco",
        "--version",
        "9.20(3)",
        "--os",
        "Cisco ASA",
        "--kev-only",
    ]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert res.returncode == 0
    assert "Authoritative Data Source" in res.stdout
    assert "NIST NVD API 2.0" in res.stdout
    assert "CISA KEV" in res.stdout
    assert "Version Vulnerability Lookup" in res.stdout
    assert "Cisco ASA" in res.stdout
