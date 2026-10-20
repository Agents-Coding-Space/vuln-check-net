"""Unit and integration tests for NVD SQLite database schema and CISA KEV fetcher."""

import sqlite3
from unittest.mock import patch

import pytest

from src.fetcher_cisa import CisaKevFetcher, get_kev_details, is_in_kev
from src.fetcher_nvd import NVDDatabase, NVDFetcher, NvdFetcher, sync_product_cves


@pytest.fixture
def temp_db(tmp_path):
    """Provide a temporary SQLite database path for isolated testing."""
    db_file = tmp_path / "test_vuln_cache.db"
    return db_file


@pytest.fixture
def nvd_db(temp_db):
    """Provide an isolated NVDDatabase instance."""
    return NVDDatabase(db_path=temp_db)


class TestNVDDatabaseSchema:
    """Validate SQLite schema definitions and table constraints."""

    def test_tables_and_columns_exist(self, nvd_db, temp_db):
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        # Check cve_records columns
        cursor.execute("PRAGMA table_info(cve_records)")
        records_cols = {row[1]: row[2].upper() for row in cursor.fetchall()}
        expected_records = {
            "cve_id": "TEXT",
            "vendor": "TEXT",
            "product": "TEXT",
            "description": "TEXT",
            "cvss_score": "REAL",
            "cvss_vector": "TEXT",
            "cwe": "TEXT",
            "published_date": "TEXT",
            "last_modified": "TEXT",
            "in_cisa_kev": "INTEGER",
        }
        for col_name, col_type in expected_records.items():
            assert col_name in records_cols, (
                f"Column {col_name} missing from cve_records"
            )

        # Check cve_version_ranges columns
        cursor.execute("PRAGMA table_info(cve_version_ranges)")
        ranges_cols = {row[1]: row[2].upper() for row in cursor.fetchall()}
        expected_ranges = {
            "id": "INTEGER",
            "cve_id": "TEXT",
            "vendor": "TEXT",
            "product": "TEXT",
            "version_start_inc": "TEXT",
            "version_start_exc": "TEXT",
            "version_end_inc": "TEXT",
            "version_end_exc": "TEXT",
            "exact_version": "TEXT",
        }
        for col_name, col_type in expected_ranges.items():
            assert col_name in ranges_cols, (
                f"Column {col_name} missing from cve_version_ranges"
            )

        conn.close()

    def test_indexes_exist(self, nvd_db, temp_db):
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        indexes = {row[0] for row in cursor.fetchall()}

        assert "idx_cve_records_vendor_product" in indexes
        assert "idx_cve_records_cve_id" in indexes
        assert "idx_cve_ranges_vendor_product" in indexes
        assert "idx_cve_ranges_cve_id" in indexes
        conn.close()


class TestNVDDatabaseMethods:
    """Validate CRUD operations and queries on NVDDatabase / NVDFetcher."""

    def test_upsert_and_get_cve(self, nvd_db):
        record = {
            "cve_id": "CVE-2025-99999",
            "vendor": "TestVendor",
            "product": "TestProduct",
            "description": "Test Description for unit test",
            "cvss_score": 9.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe": "CWE-89",
            "published_date": "2025-01-01",
            "last_modified": "2025-01-02",
            "in_cisa_kev": 1,
        }
        ranges = [
            {
                "version_start_inc": "1.0.0",
                "version_end_exc": "2.0.0",
                "exact_version": None,
            },
            {
                "version_start_inc": "2.1.0",
                "version_end_exc": "2.1.5",
                "exact_version": None,
            },
        ]
        nvd_db.upsert_cve(record, ranges=ranges)

        fetched = nvd_db.get_cve("CVE-2025-99999")
        assert fetched is not None
        assert fetched["cve_id"] == "CVE-2025-99999"
        assert fetched["vendor"] == "TestVendor"
        assert fetched["product"] == "TestProduct"
        assert fetched["cvss_score"] == 9.5
        assert fetched["cwe"] == "CWE-89"
        assert fetched["in_cisa_kev"] == 1
        assert len(fetched["version_ranges"]) == 2

    def test_upsert_updates_existing_record(self, nvd_db):
        record = {
            "cve_id": "CVE-2025-11111",
            "vendor": "VendorA",
            "product": "ProductA",
            "description": "Initial description",
            "cvss_score": 5.0,
            "in_cisa_kev": 0,
        }
        nvd_db.upsert_cve(record)

        # Update record
        updated_record = {
            "cve_id": "CVE-2025-11111",
            "vendor": "VendorA",
            "product": "ProductA",
            "description": "Updated description",
            "cvss_score": 8.0,
            "in_cisa_kev": 1,
        }
        nvd_db.upsert_cve(updated_record)

        fetched = nvd_db.get_cve("CVE-2025-11111")
        assert fetched["description"] == "Updated description"
        assert fetched["cvss_score"] == 8.0
        assert fetched["in_cisa_kev"] == 1

    def test_get_cves_by_product(self, nvd_db):
        # Initial seed includes cisco adaptive_security_appliance
        results = nvd_db.get_cves_by_product("cisco", "adaptive_security_appliance")
        assert len(results) >= 10
        cve_ids = [r["cve_id"] for r in results]
        assert "CVE-2020-3452" in cve_ids
        assert "CVE-2020-3187" in cve_ids

        # Case insensitivity test
        results_caps = nvd_db.get_cves_by_product(
            "CISCO", "ADAPTIVE_SECURITY_APPLIANCE"
        )
        assert len(results_caps) == len(results)

    def test_get_cve_count(self, nvd_db):
        count = nvd_db.get_cve_count()
        assert count >= 21

    def test_nvd_fetcher_inheritance_and_alias(self, temp_db):
        fetcher = NVDFetcher(db_path=temp_db)
        assert isinstance(fetcher, NVDDatabase)
        assert NvdFetcher is NVDFetcher

        # Test get_cve from fetcher
        cve = fetcher.get_cve("CVE-2024-21762")
        assert cve is not None
        assert cve["vendor"] == "fortinet"


class TestCisaKevFetcher:
    """Validate CISA KEV fetcher, cache loading, unpacking, and convenience methods."""

    def test_kev_cache_contains_over_1200_entries(self):
        fetcher = CisaKevFetcher(auto_download=False)
        # Official catalog currently has 1,700+ entries
        assert fetcher.count() >= 1200

    def test_is_in_kev_unpacking(self):
        in_kev, details = is_in_kev("CVE-2020-3452")
        assert in_kev is True
        assert isinstance(details, dict)
        assert details.get("cveID") == "CVE-2020-3452"

    def test_is_in_kev_boolean_eval(self):
        match = is_in_kev("CVE-2020-3452")
        assert bool(match) is True
        assert match.in_kev is True
        assert match.details is not None

        no_match = is_in_kev("CVE-1900-99999")
        assert bool(no_match) is False
        assert no_match.in_kev is False
        assert no_match.details is None

    def test_get_kev_details(self):
        details = get_kev_details("CVE-2023-20198")
        assert details is not None
        assert details.get("cveID") == "CVE-2023-20198"

        none_details = get_kev_details("CVE-NON-EXISTENT")
        assert none_details is None

    def test_search_by_vendor(self):
        fetcher = CisaKevFetcher(auto_download=False)
        cisco_vulns = fetcher.search_by_vendor("cisco")
        assert len(cisco_vulns) > 5

    def test_multi_transport_fallback_on_update(self, tmp_path):
        temp_cache = tmp_path / "test_cisa_cache.json"
        fetcher = CisaKevFetcher(cache_file=temp_cache, auto_download=False)

        mock_payload = {
            "title": "Mock CISA Feed",
            "catalogVersion": "2026.01",
            "dateReleased": "2026-01-01T00:00:00Z",
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-0001",
                    "vendorProject": "MockVendor",
                    "product": "MockProduct",
                    "vulnerabilityName": "Mock Vulnerability",
                    "shortDescription": "Mock description for test",
                }
            ],
        }

        with patch.object(fetcher, "_download_kev_feed", return_value=mock_payload):
            success = fetcher.update_cache(force=True)
            assert success is True
            assert temp_cache.exists()
            assert fetcher.is_in_kev("CVE-2099-0001").in_kev is True
            # Presets also merged
            assert fetcher.is_in_kev("CVE-2020-24368").in_kev is True


class TestNVDSyncProductCVEs:
    """Validate NVD API 2.0 pagination, CPE range parsing and persistence."""

    def test_sync_product_cves_mocked_pagination(self, temp_db):
        fetcher = NVDFetcher(db_path=temp_db)

        # Mock responses for page 1 and page 2
        page1 = {
            "totalResults": 3,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-88001",
                        "published": "2024-05-01T10:00:00.000",
                        "lastModified": "2024-05-02T10:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Mock ASA Flaw 1"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 8.8,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                    }
                                }
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.18(3)40:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "9.18",
                                                "versionEndExcluding": "9.18(4)",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-88002",
                        "published": "2024-05-02T10:00:00.000",
                        "lastModified": "2024-05-03T10:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Mock ASA Flaw 2"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    }
                                }
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
                                                "versionEndIncluding": "9.20(3)",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                },
            ],
        }

        page2 = {
            "totalResults": 3,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-88003",
                        "published": "2024-05-03T10:00:00.000",
                        "lastModified": "2024-05-04T10:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Mock ASA Flaw 3"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.14(1)10:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ],
        }

        class MockResponse:
            def __init__(self, json_data, status_code=200):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        def mock_get(url, params=None, **kwargs):
            start = params.get("startIndex", 0) if params else 0
            if start == 0:
                return MockResponse(page1)
            elif start == 2:
                return MockResponse(page2)
            return MockResponse({"totalResults": 3, "vulnerabilities": []})

        with patch("requests.get", side_effect=mock_get):
            synced = sync_product_cves(
                vendor="cisco",
                product="adaptive_security_appliance_software",
                cpe_name="cpe:2.3:o:cisco:adaptive_security_appliance_software",
                max_results=500,
                fetcher=fetcher,
            )

        assert synced == 3

        # Verify records in database
        cve1 = fetcher.get_cve("CVE-2024-88001")
        assert cve1 is not None
        assert cve1["cvss_score"] == 8.8
        assert len(cve1["version_ranges"]) == 1
        assert cve1["version_ranges"][0]["version_start_inc"] == "9.18"
        assert cve1["version_ranges"][0]["version_end_exc"] == "9.18(4)"

        cve2 = fetcher.get_cve("CVE-2024-88002")
        assert cve2 is not None
        assert cve2["version_ranges"][0]["version_end_inc"] == "9.20(3)"

        cve3 = fetcher.get_cve("CVE-2024-88003")
        assert cve3 is not None
        assert cve3["version_ranges"][0]["exact_version"] == "9.14(1)10"
