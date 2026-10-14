"""Unit tests for network configuration parser."""

import pytest
from src.config import (
    OS_CISCO_ASA,
    OS_CISCO_IOS_XE,
    OS_FORTINET_FORTIOS,
    OS_PALOALTO_PANOS,
    VENDOR_CISCO,
    VENDOR_FORTINET,
    VENDOR_PALOALTO,
)
from src.parser import ConfigParser


@pytest.fixture
def parser():
    return ConfigParser()


def test_parse_cisco_asa(parser):
    config = """
    Serial Number: JMX123456
    : Hardware:   FPR-3105, 52077 MB RAM
    :
    ASA Version 9.20(3)
    !
    hostname EDGE-ASA
    domain-name corp.internal
    !
    http server enable
    http 0.0.0.0 0.0.0.0 outside
    no snmp-server location
    ssh 192.168.1.0 255.255.255.0 inside
    aaa authentication http console LOCAL
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_CISCO
    assert res["os_family"] == OS_CISCO_ASA
    assert res["version"] == "9.20(3)"
    assert res["hostname"] == "EDGE-ASA"
    assert res["domain_name"] == "corp.internal"
    assert res["model"] == "FPR-3105"

    features = res["features"]
    assert features["http_server"] is True
    assert features["http_outside"] is True
    assert features["ssh"] is True
    assert features["aaa"] is True
    assert features["snmp_server"] is False
    assert features["webvpn"] is False
    assert features["smart_install"] is False


def test_parse_cisco_ios_xe(parser):
    config = """
    Cisco IOS XE Software, Version 17.3.4b
    hostname CORE-CAT9300
    ip domain name corp.net
    cisco C9300-48P (x86_64) processor
    !
    ip http server
    ip http secure-server
    snmp-server community public RO
    vstack
    router bgp 65001
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_CISCO
    assert res["os_family"] == OS_CISCO_IOS_XE
    assert res["version"] == "17.3.4b"
    assert res["hostname"] == "CORE-CAT9300"
    assert res["model"] == "C9300-48P"

    features = res["features"]
    assert features["http_server"] is True
    assert features["snmp_server"] is True
    assert features["smart_install"] is True
    assert features["bgp"] is True


def test_parse_fortinet_fortios(parser):
    config = """
    #config-version=FG100E-7.2.4-FW-build1234:230101
    config system global
        set hostname "HQ-FW01"
        set admin-sport 8443
    end
    config vpn ssl settings
        set status enable
    end
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_FORTINET
    assert res["os_family"] == OS_FORTINET_FORTIOS
    assert res["version"] == "7.2.4"
    assert res["hostname"] == "HQ-FW01"
    assert res["model"] == "FG100E"

    features = res["features"]
    assert features["http_server"] is True
    assert features["ssl_vpn"] is True


def test_parse_paloalto_panos(parser):
    config = """
    sw-version: 10.2.3-h4
    model: PA-3220
    hostname: PA-DC-FW
    set network global-protect global-protect-gateway
    service [ ssh web-interface ]
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_PALOALTO
    assert res["os_family"] == OS_PALOALTO_PANOS
    assert res["version"] == "10.2.3-h4"
    assert res["hostname"] == "PA-DC-FW"
    assert res["model"] == "PA-3220"

    features = res["features"]
    assert features["ssl_vpn"] is True
    assert features["ssh"] is True
    assert features["http_server"] is True


def test_parse_empty_input(parser):
    res = parser.parse("")
    assert res["hostname"] == "UNKNOWN"
    assert res["vendor"] == "UNKNOWN"
    assert res["version"] == ""


def test_parse_cisco_asa_webvpn_disabled_with_enable_password(parser):
    """WebVPN must be False when webvpn stanza lacks enable <interface>,

    even if global 'enable password pbkdf2' or 'tunnel-group-list enable' exists.
    """
    config = """
    ASA Version 9.16(2)
    !
    hostname FW-EDGE-01
    enable password pbkdf2 8192 128 saltedhash1234567890
    !
    webvpn
     port 443
     tunnel-group-list enable
    !
    """
    res = parser.parse(config)
    assert res["features"]["webvpn"] is False
    assert res["features"]["ssl_vpn"] is False


def test_parse_cisco_asa_webvpn_enabled_with_interface(parser):
    """WebVPN must be True when webvpn stanza contains enable <interface>."""
    config = """
    ASA Version 9.16(2)
    !
    hostname FW-EDGE-01
    enable password pbkdf2 8192 128 saltedhash1234567890
    !
    webvpn
     port 443
     enable outside
     tunnel-group-list enable
    !
    """
    res = parser.parse(config)
    assert res["features"]["webvpn"] is True
    assert res["features"]["ssl_vpn"] is True


def test_parse_cisco_asa_webvpn_enabled_with_anyconnect(parser):
    """WebVPN must be True when webvpn stanza contains anyconnect enable."""
    config = """
    ASA Version 9.16(2)
    !
    hostname FW-EDGE-01
    !
    webvpn
     anyconnect enable
    !
    """
    res = parser.parse(config)
    assert res["features"]["webvpn"] is True
    assert res["features"]["ssl_vpn"] is True

