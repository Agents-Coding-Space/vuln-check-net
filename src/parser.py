"""Network device configuration parser.

Extracts device metadata (hostname, vendor, OS family, version, model)
and active features (HTTP server, WebVPN/SSL-VPN, SNMP, Telnet, SSH,
BGP, OSPF, AAA) to enable accurate vulnerability correlation.
"""

import re
from typing import Any, Dict

from src.config import (
    OS_CISCO_ASA,
    OS_CISCO_IOS_CLASSIC,
    OS_CISCO_IOS_XE,
    OS_FORTINET_FORTIOS,
    OS_PALOALTO_PANOS,
    VENDOR_CISCO,
    VENDOR_FORTINET,
    VENDOR_PALOALTO,
)


class ConfigParser:
    """Parser for multi-vendor network device running configurations."""

    def __init__(self) -> None:
        pass

    def parse(self, config_text: str) -> Dict[str, Any]:
        """Parse configuration text and extract device metadata and features.

        Args:
            config_text: Raw configuration text from device.

        Returns:
            Dictionary containing:
                - hostname: str
                - domain_name: str
                - vendor: str
                - os_family: str
                - version: str
                - model: str
                - features: Dict[str, bool]
                - raw_metadata: Dict[str, Any]
        """
        if not config_text:
            return self._empty_result()

        vendor, os_family = self._detect_vendor_and_os(config_text)
        version = self._extract_version(config_text, os_family)
        hostname = self._extract_hostname(config_text, os_family)
        domain_name = self._extract_domain(config_text, os_family)
        model = self._extract_model(config_text, os_family)
        features = self._extract_features(config_text, os_family)

        return {
            "hostname": hostname,
            "domain_name": domain_name,
            "vendor": vendor,
            "os_family": os_family,
            "version": version,
            "model": model,
            "features": features,
            "raw_metadata": {
                "detected_vendor": vendor,
                "detected_os": os_family,
                "lines_count": len(config_text.splitlines()),
            },
        }

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "hostname": "UNKNOWN",
            "domain_name": "",
            "vendor": "UNKNOWN",
            "os_family": "UNKNOWN",
            "version": "",
            "model": "UNKNOWN",
            "features": {},
            "raw_metadata": {},
        }

    def _detect_vendor_and_os(self, text: str) -> tuple[str, str]:
        """Detect the hardware/OS vendor and specific OS family."""
        # 1. Cisco ASA
        if re.search(r"ASA Version\s+[\d\.\(\)]+", text, re.I) or re.search(
            r": Hardware:\s+FPR|ciscoasa\b", text, re.I
        ):
            return VENDOR_CISCO, OS_CISCO_ASA

        # 2. Cisco IOS XE
        if re.search(r"IOS-XE|IOS XE", text, re.I) or re.search(
            r"Cisco IOS Software.*XE Software", text, re.I
        ):
            return VENDOR_CISCO, OS_CISCO_IOS_XE

        # 3. Cisco IOS Classic
        if re.search(r"Cisco IOS Software", text, re.I) or re.search(
            r"^version\s+1[25]\.", text, re.M | re.I
        ):
            return VENDOR_CISCO, OS_CISCO_IOS_CLASSIC

        # 4. Fortinet FortiOS
        if (
            re.search(r"#config-version=.*-build", text, re.I)
            or re.search(r"FortiOS\b", text, re.I)
            or re.search(r"config system global", text, re.I)
        ):
            return VENDOR_FORTINET, OS_FORTINET_FORTIOS

        # 5. Palo Alto PAN-OS
        if (
            re.search(r"sw-version:\s*[\d\.\-h]+", text, re.I)
            or re.search(r"<sw-version>[\d\.\-h]+</sw-version>", text, re.I)
            or re.search(r"set deviceconfig system", text, re.I)
            or re.search(r"PAN-OS", text, re.I)
        ):
            return VENDOR_PALOALTO, OS_PALOALTO_PANOS

        # Generic Cisco fallback
        if re.search(r"^\s*hostname\s+\S+", text, re.M | re.I) and re.search(
            r"^\s*interface\s+\S+", text, re.M | re.I
        ):
            return VENDOR_CISCO, OS_CISCO_ASA

        return "Unknown", "Unknown"

    def _extract_version(self, text: str, os_family: str) -> str:
        """Extract operating system version string."""
        if os_family == OS_CISCO_ASA:
            m = re.search(r"ASA Version\s+([^\r\n!]+)", text, re.I)
            if m:
                return m.group(1).strip()

        elif os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            m = re.search(
                r"Version\s+([0-9\.\(\)a-zA-Z]+)(?:,\s*RELEASE|,\s*EXPERIMENTAL|\s)",
                text,
                re.I,
            )
            if m:
                return m.group(1).strip()
            m2 = re.search(r"^\s*version\s+([0-9\.\(\)a-zA-Z]+)", text, re.M | re.I)
            if m2:
                return m2.group(1).strip()

        elif os_family == OS_FORTINET_FORTIOS:
            m = re.search(r"#config-version=[A-Za-z0-9]+-([0-9\.]+)-", text)
            if m:
                return m.group(1).strip()
            m2 = re.search(r'set\s+os-version\s+"?([0-9\.]+)"?', text)
            if m2:
                return m2.group(1).strip()
            m3 = re.search(r"FortiOS\s+v?([0-9\.]+)", text, re.I)
            if m3:
                return m3.group(1).strip()

        elif os_family == OS_PALOALTO_PANOS:
            m = re.search(r"sw-version:\s*([0-9\.\-h]+)", text, re.I)
            if m:
                return m.group(1).strip()
            m2 = re.search(r"<sw-version>([0-9\.\-h]+)</sw-version>", text, re.I)
            if m2:
                return m2.group(1).strip()

        # Fallback generic version pattern
        m_gen = re.search(r"(?:version|ver|sw-version)[\s:=]+([0-9\.\(\)\-a-zA-Z]+)", text, re.I)
        return m_gen.group(1).strip() if m_gen else ""

    def _extract_hostname(self, text: str, os_family: str) -> str:
        """Extract device hostname."""
        if os_family == OS_FORTINET_FORTIOS:
            m = re.search(r'set\s+hostname\s+"?([^"\r\n\s]+)"?', text, re.I)
            if m:
                return m.group(1).strip()
        elif os_family == OS_PALOALTO_PANOS:
            m = re.search(r"hostname:\s*([^\r\n\s]+)", text, re.I)
            if m:
                return m.group(1).strip()
            m2 = re.search(r"set deviceconfig system hostname\s+(\S+)", text, re.I)
            if m2:
                return m2.group(1).strip()

        # Standard Cisco syntax
        m = re.search(r"^\s*hostname\s+([^\r\n\s]+)", text, re.M | re.I)
        if m:
            return m.group(1).strip()

        # sysname fallback (Huawei/H3C style)
        m_sys = re.search(r"^\s*sysname\s+([^\r\n\s]+)", text, re.M | re.I)
        if m_sys:
            return m_sys.group(1).strip()

        return "UNKNOWN"

    def _extract_domain(self, text: str, os_family: str) -> str:
        """Extract domain name."""
        m = re.search(r"^\s*(?:ip\s+)?domain-name\s+([^\r\n\s]+)", text, re.M | re.I)
        if m:
            return m.group(1).strip()
        m_dom = re.search(r"^\s*ip\s+domain\s+name\s+([^\r\n\s]+)", text, re.M | re.I)
        if m_dom:
            return m_dom.group(1).strip()
        return ""

    def _extract_model(self, text: str, os_family: str) -> str:
        """Extract hardware model string."""
        if os_family == OS_CISCO_ASA:
            m = re.search(r":\s*Hardware:\s*([^,\r\n]+)", text, re.I)
            if m:
                return m.group(1).strip()
            m2 = re.search(r"model:\s*([^,\r\n]+)", text, re.I)
            if m2:
                return m2.group(1).strip()

        elif os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            m = re.search(r"cisco\s+([A-Za-z0-9\-]+)\s+\(.*processor", text, re.I)
            if m:
                return m.group(1).strip()
            m2 = re.search(r"Model Number\s*:\s*([^\r\n\s]+)", text, re.I)
            if m2:
                return m2.group(1).strip()

        elif os_family == OS_FORTINET_FORTIOS:
            m = re.search(r"#config-version=([A-Za-z0-9]+)-", text)
            if m:
                return m.group(1).strip()

        elif os_family == OS_PALOALTO_PANOS:
            m = re.search(r"model:\s*([^\r\n\s]+)", text, re.I)
            if m:
                return m.group(1).strip()
            m2 = re.search(r"<model>([^<]+)</model>", text, re.I)
            if m2:
                return m2.group(1).strip()

        return "Unknown"

    def _extract_features(self, text: str, os_family: str) -> Dict[str, bool]:
        """Extract state of services and features from configuration."""
        features: Dict[str, bool] = {
            "http_server": False,
            "webvpn": False,
            "ssl_vpn": False,
            "snmp_server": False,
            "telnet": False,
            "ssh": False,
            "bgp": False,
            "ospf": False,
            "aaa": False,
            "smart_install": False,
            "http_outside": False,
        }

        # 1. HTTP Server / Web UI
        if os_family == OS_CISCO_ASA:
            features["http_server"] = bool(
                re.search(r"^\s*http\s+server\s+enable\b", text, re.M | re.I)
            )
            features["http_outside"] = bool(
                re.search(r"^\s*http\s+.*\boutside\b", text, re.M | re.I)
            )
        elif os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            # Must check that it is enabled and not disabled via 'no ip http server'
            has_http = bool(
                re.search(r"^\s*ip\s+http\s+(?:secure-)?server\b", text, re.M | re.I)
            )
            no_http = bool(
                re.search(r"^\s*no\s+ip\s+http\s+(?:secure-)?server\b", text, re.M | re.I)
            )
            features["http_server"] = has_http and not no_http
        elif os_family == OS_FORTINET_FORTIOS:
            features["http_server"] = bool(
                re.search(r"set\s+admin-sport\b|allowaccess.*https?\b", text, re.I)
            )
        elif os_family == OS_PALOALTO_PANOS:
            features["http_server"] = bool(
                re.search(r"service\s+\[.*web-interface.*\]", text, re.I)
                or not re.search(r"disable-http\s+yes", text, re.I)
            )

        # 2. WebVPN / SSL-VPN / GlobalProtect
        if os_family == OS_CISCO_ASA:
            # Requires webvpn stanza with actual enablement inside it:
            # - 'enable <interface>' (e.g. 'enable outside'), strictly excluding 'enable password'
            # - or 'anyconnect enable'
            # Subcommands must be indented within the webvpn stanza.
            webvpn_enabled = False
            lines = text.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i]
                match = re.match(r"^(\s*)webvpn\b", line, re.I)
                if match:
                    base_indent = len(match.group(1))
                    i += 1
                    while i < len(lines):
                        sub_line = lines[i]
                        if not sub_line.strip():
                            i += 1
                            continue
                        sub_indent = len(sub_line) - len(sub_line.lstrip())
                        if sub_indent <= base_indent:
                            break
                        cmd = sub_line.strip()
                        if (
                            re.match(r"^enable\s+(?!password\b)\S+", cmd, re.I)
                            or re.match(r"^anyconnect\s+enable\b", cmd, re.I)
                        ):
                            webvpn_enabled = True
                            break
                        i += 1
                    if webvpn_enabled:
                        break
                else:
                    i += 1

            features["webvpn"] = webvpn_enabled
            features["ssl_vpn"] = webvpn_enabled
        elif os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            features["webvpn"] = bool(
                re.search(r"^\s*webvpn\s+(?:gateway|context)\b", text, re.M | re.I)
            )
            features["ssl_vpn"] = features["webvpn"]
        elif os_family == OS_FORTINET_FORTIOS:
            features["ssl_vpn"] = bool(
                re.search(r"config\s+vpn\s+ssl\s+settings[\s\S]*?set\s+status\s+enable", text, re.I)
            )
            features["webvpn"] = features["ssl_vpn"]
        elif os_family == OS_PALOALTO_PANOS:
            features["ssl_vpn"] = bool(
                re.search(r"global-protect(?:-gateway|-portal)?\b", text, re.I)
            )
            features["webvpn"] = features["ssl_vpn"]

        # 3. SNMP Server
        # Must be actively configured (community or host or user) and NOT merely 'no snmp-server'
        if os_family in (OS_CISCO_ASA, OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            active_snmp = re.search(
                r"^\s*snmp-server\s+(?:community|host|user)\b", text, re.M | re.I
            )
            features["snmp_server"] = bool(active_snmp)
        elif os_family == OS_FORTINET_FORTIOS:
            features["snmp_server"] = bool(
                re.search(r"config\s+system\s+snmp\s+sysinfo[\s\S]*?set\s+status\s+enable", text, re.I)
                or re.search(r"config\s+system\s+snmp\s+community", text, re.I)
            )
        elif os_family == OS_PALOALTO_PANOS:
            features["snmp_server"] = bool(
                re.search(r"snmp-setting", text, re.I)
            )

        # 4. Telnet
        if os_family == OS_CISCO_ASA:
            # Needs actual telnet IP mask interface
            features["telnet"] = bool(
                re.search(r"^\s*telnet\s+\d+\.\d+\.\d+\.\d+\b", text, re.M | re.I)
            )
        elif os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            features["telnet"] = bool(
                re.search(r"transport\s+input\s+(?:all|.*\btelnet\b)", text, re.I)
            )
        elif os_family == OS_FORTINET_FORTIOS:
            features["telnet"] = bool(re.search(r"allowaccess.*telnet\b", text, re.I))
        elif os_family == OS_PALOALTO_PANOS:
            features["telnet"] = bool(re.search(r"service\s+\[.*telnet.*\]", text, re.I))

        # 5. SSH
        if os_family == OS_CISCO_ASA:
            features["ssh"] = bool(
                re.search(r"^\s*ssh\s+\d+\.\d+\.\d+\.\d+\b", text, re.M | re.I)
                or re.search(r"^\s*ssh\s+version\b", text, re.M | re.I)
            )
        elif os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            features["ssh"] = bool(
                re.search(r"transport\s+input\s+(?:all|.*\bssh\b)", text, re.I)
                or re.search(r"ip\s+ssh\b", text, re.I)
            )
        elif os_family == OS_FORTINET_FORTIOS:
            features["ssh"] = bool(re.search(r"allowaccess.*ssh\b", text, re.I))
        elif os_family == OS_PALOALTO_PANOS:
            features["ssh"] = bool(
                re.search(r"service\s+\[.*ssh.*\]", text, re.I)
                or not re.search(r"disable-ssh\s+yes", text, re.I)
            )

        # 6. Routing: BGP & OSPF
        features["bgp"] = bool(
            re.search(r"(?:router\s+bgp|config\s+router\s+bgp|protocol\s+bgp)", text, re.I)
        )
        features["ospf"] = bool(
            re.search(r"(?:router\s+ospf|config\s+router\s+ospf|protocol\s+ospf)", text, re.I)
        )

        # 7. AAA
        if os_family == OS_CISCO_ASA:
            features["aaa"] = bool(
                re.search(r"^\s*aaa\s+(?:authentication|authorization|accounting)\b", text, re.M | re.I)
                or re.search(r"^\s*aaa-server\b", text, re.M | re.I)
            )
        elif os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            features["aaa"] = bool(re.search(r"^\s*aaa\s+new-model\b", text, re.M | re.I))
        elif os_family == OS_FORTINET_FORTIOS:
            features["aaa"] = bool(
                re.search(r"config\s+user\s+(?:ldap|radius|tacacs\+)", text, re.I)
            )
        elif os_family == OS_PALOALTO_PANOS:
            features["aaa"] = bool(re.search(r"authentication-profile", text, re.I))

        # 8. Cisco Smart Install (TCP 4786)
        if os_family in (OS_CISCO_IOS_XE, OS_CISCO_IOS_CLASSIC):
            has_vstack = bool(re.search(r"^\s*vstack\b", text, re.M | re.I))
            no_vstack = bool(re.search(r"^\s*no\s+vstack\b", text, re.M | re.I))
            features["smart_install"] = has_vstack and not no_vstack

        return features
