"""Unit tests for version parsing and comparison utilities."""

import pytest
from src.version_utils import compare_versions, is_version_in_range, normalize_version


def test_normalize_asa_versions():
    assert normalize_version("9.20(3)") == (9, 20, 3, 0)
    assert normalize_version("9.18(4)22") == (9, 18, 4, 22)
    assert normalize_version("9.18(4)") == (9, 18, 4, 0)
    assert normalize_version("9.16.2") == (9, 16, 2, 0)


def test_normalize_ios_xe_versions():
    assert normalize_version("17.15.1a") == (17, 15, 1, 1)
    assert normalize_version("17.15.1b") == (17, 15, 1, 2)
    assert normalize_version("17.15.1") == (17, 15, 1, 0)
    assert normalize_version("16.10.1") == (16, 10, 1, 0)


def test_normalize_fortinet_versions():
    assert normalize_version("v7.2.4") == (7, 2, 4, 0)
    assert normalize_version("7.0.0") == (7, 0, 0, 0)
    assert normalize_version("7.4.1") == (7, 4, 1, 0)


def test_normalize_panos_versions():
    assert normalize_version("10.2.3-h4") == (10, 2, 3, 4)
    assert normalize_version("10.2.3") == (10, 2, 3, 0)
    assert normalize_version("11.0.2") == (11, 0, 2, 0)
    assert normalize_version("9.1.12-h3") == (9, 1, 12, 3)


def test_compare_asa_versions():
    assert compare_versions("9.18(4)", "9.18(4)22") == -1
    assert compare_versions("9.18(4)22", "9.18(4)22") == 0
    assert compare_versions("9.20(3)", "9.18(4)22") == 1
    assert compare_versions("9.16.2", "9.18(1)") == -1


def test_compare_ios_xe_versions():
    assert compare_versions("17.3.1", "17.3.1a") == -1
    assert compare_versions("17.3.1a", "17.3.1b") == -1
    assert compare_versions("17.3.1b", "17.3.2") == -1
    assert compare_versions("17.15.1a", "16.10.1") == 1


def test_compare_panos_versions():
    assert compare_versions("10.2.3", "10.2.3-h1") == -1
    assert compare_versions("10.2.3-h1", "10.2.3-h4") == -1
    assert compare_versions("10.2.3-h4", "10.2.4") == -1


def test_compare_fortinet_versions():
    assert compare_versions("v7.2.4", "7.2.4") == 0
    assert compare_versions("7.0.0", "7.2.4") == -1
    assert compare_versions("7.4.1", "7.2.4") == 1


def test_is_version_in_range():
    assert is_version_in_range("9.20(3)", min_ver="9.18(1)", max_ver="9.20(4)") is True
    assert is_version_in_range("9.20(3)", min_ver="9.20(3)", max_ver="9.20(3)", include_max=True) is True
    assert is_version_in_range("9.20(3)", min_ver="9.20(3)", max_ver="9.20(3)", include_max=False) is False
    assert is_version_in_range("10.2.3-h4", min_ver="10.2.0", max_ver="10.2.3-h5") is True
    assert is_version_in_range("17.15.1a", min_ver="17.15.0", max_ver="17.15.2") is True
    assert is_version_in_range("7.2.4", min_ver="7.2.0", max_ver="7.2.4", include_max=True) is True
    assert is_version_in_range("7.2.5", min_ver="7.2.0", max_ver="7.2.4", include_max=True) is False


def test_nvd_version_in_range_bounds():
    """Verify is_version_in_range with NVD CPE dải biên (v_start_inc, v_start_exc, v_end_inc, v_end_exc)."""
    # Cisco ASA: 9.18(3)40 in range [9.18, 9.18(4))
    assert is_version_in_range("9.18(3)40", v_start_inc="9.18", v_end_exc="9.18(4)") is True
    assert is_version_in_range("9.18(4)", v_start_inc="9.18", v_end_exc="9.18(4)") is False
    assert is_version_in_range("9.18(3)40", v_start_inc="9.18(3)40", v_end_inc="9.18(3)40") is True
    assert is_version_in_range("9.18(3)40", v_start_exc="9.18(3)40") is False

    # Exact version matching
    assert is_version_in_range("9.20(3)", exact_version="9.20(3)") is True
    assert is_version_in_range("9.20(3)", exact_version="9.20(4)") is False

    # Cisco IOS XE: 17.3.3 and 16.12.1a
    assert is_version_in_range("17.3.3", v_start_inc="17.3.0", v_end_exc="17.3.4") is True
    assert is_version_in_range("17.3.3", v_start_inc="17.3.3", v_end_inc="17.3.3") is True
    assert is_version_in_range("17.3.3", v_start_exc="17.3.3") is False
    assert is_version_in_range("16.12.1a", v_start_inc="16.12.1", v_end_inc="16.12.1a") is True
    assert is_version_in_range("16.12.1b", v_start_inc="16.12.1", v_end_inc="16.12.1a") is False

    # Fortinet FortiOS: 7.2.5
    assert is_version_in_range("7.2.5", v_start_inc="7.2.0", v_end_exc="7.2.6") is True
    assert is_version_in_range("7.2.5", v_start_inc="7.2.5", v_end_inc="7.2.5") is True
    assert is_version_in_range("7.2.5", v_start_exc="7.2.5") is False
    assert is_version_in_range("7.2.5", v_end_exc="7.2.5") is False

    # Palo Alto PAN-OS: 10.1.6-h3
    assert is_version_in_range("10.1.6-h3", v_start_inc="10.1.0", v_end_exc="10.1.6-h4") is True
    assert is_version_in_range("10.1.6-h3", v_start_inc="10.1.6-h3", v_end_inc="10.1.6-h3") is True
    assert is_version_in_range("10.1.6-h3", v_start_exc="10.1.6-h3") is False
    assert is_version_in_range("10.1.6-h3", v_end_exc="10.1.6-h3") is False
    assert is_version_in_range("10.1.6-h4", v_start_inc="10.1.0", v_end_exc="10.1.6-h4") is False

    # SemVer
    assert is_version_in_range("1.2.3", v_start_inc="1.0.0", v_end_exc="2.0.0", os_type="semver") is True
    assert is_version_in_range("2.0.0", v_start_inc="1.0.0", v_end_exc="2.0.0", os_type="semver") is False
    assert is_version_in_range("1.0.0-alpha", v_start_inc="1.0.0-alpha", v_end_exc="1.0.0") is True


def test_edge_cases():
    assert normalize_version("") == ()
    assert normalize_version(None) == ()
    assert is_version_in_range("", min_ver="1.0") is False
    assert compare_versions("", "") == 0
