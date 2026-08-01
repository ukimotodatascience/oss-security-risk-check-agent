from __future__ import annotations

import time
import pytest

from src.rules.B_dependencies.vuln_sources import VulnLookupService, VulnHit


@pytest.fixture(autouse=True)
def stable_vuln_env(monkeypatch):
    monkeypatch.setenv("VULN_API_TIMEOUT_SEC", "1")
    monkeypatch.setenv("VULN_MAX_RETRIES", "0")
    monkeypatch.setenv("VULN_ENABLE_FALLBACK", "true")
    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "0")
    VulnLookupService._process_cache.clear()


def test_query_osv_batch_success(monkeypatch):
    service = VulnLookupService()
    captured_payload = {}

    def fake_request(url, method="GET", headers=None, payload=None):
        if url == "https://api.osv.dev/v1/querybatch":
            captured_payload["payload"] = payload
            return {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-1",
                                "summary": "OSV-1",
                                "references": [{"url": "ref1"}],
                                "severity": [{"score": "CVSS:3.1/AV:N/AC:L/9.8"}],
                            }
                        ]
                    },
                    {},  # 脆弱性なし
                ]
            }
        return None

    monkeypatch.setattr(service, "_request_json", fake_request)

    res = service._query_osv_batch("python", [("pkg1", "1.0.0"), ("pkg2", "2.0.0")])
    assert res is not None
    assert len(res) == 2
    assert res[0][0].vuln_id == "GHSA-1"
    assert res[0][0].severity_score == 9.8
    assert res[1] == []
    assert captured_payload["payload"] == {
        "queries": [
            {"package": {"name": "pkg1", "ecosystem": "PyPI"}, "version": "1.0.0"},
            {"package": {"name": "pkg2", "ecosystem": "PyPI"}, "version": "2.0.0"},
        ]
    }


def test_bulk_lookup_hits_and_misses(monkeypatch):
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    service = VulnLookupService()

    # pkg1 は事前にキャッシュに登録
    key_pkg1 = ("python", "pkg1", "1.0.0", "osv", True)
    VulnLookupService._process_cache[key_pkg1] = (
        time.time(),
        [VulnHit("CVE-CACHE", "osv", "cached summary", 5.0, ())],
    )

    # OSV Batch 呼び出しをモック
    captured_packages = []

    def fake_osv_batch(ecosystem, packages):
        captured_packages.extend(packages)
        return [[VulnHit("CVE-NEW", "osv", "new summary", 8.0, ())]]

    monkeypatch.setattr(service, "_query_osv_batch", fake_osv_batch)

    deps = [("pkg1", "1.0.0"), ("pkg2", "2.0.0")]
    res = service.bulk_lookup("python", deps)

    assert len(res) == 2
    assert res[("pkg1", "1.0.0")][0].vuln_id == "CVE-CACHE"
    assert res[("pkg2", "2.0.0")][0].vuln_id == "CVE-NEW"
    assert captured_packages == [
        ("pkg2", "2.0.0")
    ]  # キャッシュミスした pkg2 のみ問い合わせられる
