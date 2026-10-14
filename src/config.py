"""Configuration and constants for Vuln-Check-Net."""

import os
from pathlib import Path

# Base directories
SRC_DIR = Path(__file__).resolve().parent
BASE_DIR = SRC_DIR.parent
DATA_DIR = BASE_DIR / "data"
OUTPUTS_DIR = BASE_DIR / "outputs"

# Ensure data and outputs directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# Cache and DB paths
DB_PATH = DATA_DIR / "vuln_cache.db"
CISA_KEV_CACHE_PATH = DATA_DIR / "cisa_kev_cache.json"

# External API endpoints
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Network settings
HTTP_TIMEOUT = int(os.environ.get("VULN_CHECK_TIMEOUT", "15"))
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Rate limiting
NVD_DELAY_NO_KEY = 6.0
NVD_DELAY_WITH_KEY = 0.6
MAX_RETRIES = 3
BACKOFF_FACTOR = 2.0

# Supported Vendors & OS Families
VENDOR_CISCO = "Cisco"
VENDOR_FORTINET = "Fortinet"
VENDOR_PALOALTO = "Palo Alto"

OS_CISCO_ASA = "Cisco ASA"
OS_CISCO_IOS_XE = "Cisco IOS XE"
OS_CISCO_IOS_CLASSIC = "Cisco IOS Classic"
OS_FORTINET_FORTIOS = "Fortinet FortiOS"
OS_PALOALTO_PANOS = "Palo Alto PAN-OS"

# Vulnerability Exploitability Status
STATUS_EXPLOITABLE = "EXPLOITABLE"
STATUS_MITIGATED = "MITIGATED"
STATUS_NOT_AFFECTED = "NOT_AFFECTED"

# Risk Levels
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"
