"""Unit tests for network configuration parser."""

import pytest
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


def test_parse_cisco_ios_xe_version_17_6(parser):
    """Cisco IOS XE with 'version 17.6' must NOT fall back to Cisco ASA."""
    config = """
    !
    version 17.6
    hostname CORE-RTR-HN-01
    ip domain name corp.example.vn
    !
    ip http server
    ip http secure-server
    transport input telnet ssh
    snmp-server community public RO
    router ospf 100
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_CISCO
    assert res["os_family"] == OS_CISCO_IOS_XE
    assert res["version"] == "17.6"
    assert res["hostname"] == "CORE-RTR-HN-01"
    assert res["domain_name"] == "corp.example.vn"

    features = res["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True
    assert features["telnet"] is True
    assert features["snmp_server"] is True
    assert features["ospf"] is True


def test_parse_paloalto_panos_html_unescape(parser):
    """Palo Alto PAN-OS XML with HTML entities must unescape and extract detail-version."""
    config = """
    &lt;?xml version=&quot;1.0&quot;?&gt;
    &lt;config version=&quot;11.0.0&quot; urldb=&quot;paloaltonetworks&quot; detail-version=&quot;11.0.2&quot;&gt;
      &lt;devices&gt;
        &lt;entry name=&quot;localhost.localdomain&quot;&gt;
          &lt;deviceconfig&gt;
            &lt;system&gt;
              &lt;hostname&gt;PA-3220-EDGE-FW01&lt;/hostname&gt;
              &lt;service&gt;
                &lt;disable-telnet&gt;no&lt;/disable-telnet&gt;
                &lt;disable-http&gt;no&lt;/disable-http&gt;
                &lt;disable-snmp&gt;no&lt;/disable-snmp&gt;
              &lt;/service&gt;
            &lt;/system&gt;
          &lt;/deviceconfig&gt;
          &lt;network&gt;
            &lt;profiles&gt;
              &lt;interface-management-profile&gt;
                &lt;entry name=&quot;MGMT&quot;&gt;
                  &lt;ssh&gt;yes&lt;/ssh&gt;
                  &lt;https&gt;yes&lt;/https&gt;
                &lt;/entry&gt;
              &lt;/interface-management-profile&gt;
            &lt;/profiles&gt;
          &lt;/network&gt;
        &lt;/entry&gt;
      &lt;/devices&gt;
    &lt;/config&gt;
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_PALOALTO
    assert res["os_family"] == OS_PALOALTO_PANOS
    assert res["version"] == "11.0.2"
    assert res["hostname"] == "PA-3220-EDGE-FW01"
    assert res["model"] == "PA-3220"

    features = res["features"]
    assert features["http_server"] is True
    assert features["telnet"] is True
    assert features["snmp_server"] is True
    assert features["ssh"] is True
    assert features["ssl_vpn"] is False


def test_parse_paloalto_panos_disabled_http_and_ssh(parser):
    """Palo Alto XML with explicit disable-http yes and disable-ssh yes must set both features to False."""
    config = """
    <?xml version="1.0"?>
    <config version="11.0.0" urldb="paloaltonetworks" detail-version="11.0.2">
      <devices>
        <entry name="localhost.localdomain">
          <deviceconfig>
            <system>
              <hostname>PA-SECURE-FW</hostname>
              <service>
                <disable-http>yes</disable-http>
                <disable-ssh>yes</disable-ssh>
                <disable-telnet>yes</disable-telnet>
                <disable-snmp>yes</disable-snmp>
              </service>
            </system>
          </deviceconfig>
        </entry>
      </devices>
    </config>
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_PALOALTO
    assert res["os_family"] == OS_PALOALTO_PANOS
    features = res["features"]
    assert features["http_server"] is False
    assert features["ssh"] is False
    assert features["telnet"] is False
    assert features["snmp_server"] is False


def test_parse_paloalto_panos_disabled_service_with_profile_override(parser):
    """Palo Alto XML with disable-http/disable-ssh in system service, but enabled via interface profile."""
    config = """
    <?xml version="1.0"?>
    <config version="11.0.0" urldb="paloaltonetworks" detail-version="11.0.2">
      <devices>
        <entry name="localhost.localdomain">
          <deviceconfig>
            <system>
              <hostname>PA-EDGE-FW</hostname>
              <service>
                <disable-http>yes</disable-http>
                <disable-ssh>yes</disable-ssh>
              </service>
            </system>
          </deviceconfig>
          <network>
            <profiles>
              <interface-management-profile>
                <entry name="MGMT-ALLOW">
                  <https>yes</https>
                  <ssh>yes</ssh>
                </entry>
              </interface-management-profile>
            </profiles>
          </network>
        </entry>
      </devices>
    </config>
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_PALOALTO
    assert res["os_family"] == OS_PALOALTO_PANOS
    features = res["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True


def test_parse_f5_bigip_tmsh(parser):
    """F5 BIG-IP TMSH configuration extraction."""
    config = """
    #TMSH-VERSION: 17.1.1
    # F5 BIG-IP LTM + ASM Sample Configuration Export
    sys global-settings {
        hostname bigip-waf-prod01.example.vn
    }
    sys httpd {
        allow { All }
    }
    sys sshd {
        login enabled
    }
    sys snmp {
        communities {
            /Common/comm-public {
                community-name public
            }
        }
    }
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_F5
    assert res["os_family"] == OS_F5_BIGIP
    assert res["version"] == "17.1.1"
    assert res["hostname"] == "bigip-waf-prod01.example.vn"

    features = res["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True
    assert features["snmp_server"] is True


def test_parse_arbor_sightline_tms(parser):
    """NETSCOUT Arbor Sightline/TMS ArbOS configuration extraction."""
    config = """
    # NETSCOUT Arbor Sightline / TMS (Peakflow SP) Configuration Export
    # Software Version: ArbOS 7.6 (Sightline 9.7.1)
    # System: ARBOR-TMS-EDGE-01
    services http status set enabled
    services ssh status set enabled
    services snmp status set enabled
    services bgp status set enabled
    ip hostname set arbor-tms-edge-01.example.vn
    ip domain set example.vn
    """
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_NETSCOUT
    assert res["os_family"] == OS_ARBOR_ARBOS
    assert res["version"] == "9.7.1"
    assert res["hostname"] == "arbor-tms-edge-01.example.vn"
    assert res["domain_name"] == "example.vn"

    features = res["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True
    assert features["snmp_server"] is True
    assert features["bgp"] is True


def test_parse_imperva_securesphere_json(parser):
    """Imperva SecureSphere WAF JSON configuration export."""
    config = """{
      "exportMetadata": {
        "vendor": "Imperva",
        "product": "SecureSphere WAF / MX Management Server",
        "version": "14.7.0.20",
        "applianceHostname": "impv-mx-hn-01.example.vn"
      },
      "systemConfiguration": {
        "managementInterface": {
          "webGuiPort": 8083,
          "sshEnabled": true
        },
        "snmp": {
          "enabled": true
        }
      }
    }"""
    res = parser.parse(config)
    assert res["vendor"] == VENDOR_IMPERVA
    assert res["os_family"] == OS_IMPERVA_SECURESPHERE
    assert res["version"] == "14.7.0.20"
    assert res["hostname"] == "impv-mx-hn-01.example.vn"
    assert res["model"] == "SecureSphere WAF / MX Management Server"

    features = res["features"]
    assert features["http_server"] is True
    assert features["ssh"] is True
    assert features["snmp_server"] is True
