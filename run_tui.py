#!/usr/bin/env python3
"""Vuln-Check-Net Terminal User Interface (TUI) Entry Point.

Run standalone TUI application for multi-vendor network CVE audit:
    python run_tui.py
    python run_tui.py "path/to/config.txt"
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.tui.app import VulnCheckApp


def main() -> None:
    """Launch the TUI application."""
    initial_file = sys.argv[1] if len(sys.argv) > 1 else None
    app = VulnCheckApp(initial_file=initial_file)
    app.run()


if __name__ == "__main__":
    main()
