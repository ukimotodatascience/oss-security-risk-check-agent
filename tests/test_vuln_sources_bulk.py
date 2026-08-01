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
    VulnLookupService._osv_detail_cache.clear()


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
                            }
                        ]
                    },
                    {},  # 脆弱性なし
                ]
            }
        if "https://api.osv.dev/v1/vulns/GHSA-1" in url:
            return {
                "id": "GHSA-1",
                "summary": "OSV-1",
                "references": [{"url": "ref1"}],
                "severity": [{"score": "CVSS:3.1/AV:N/AC:L/9.8"}],
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


def test_bulk_lookup_deduplicates_case_insensitive(tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    service = VulnLookupService()

    call_count = 0

    def fake_osv_batch(ecosystem, packages):
        nonlocal call_count
        call_count += 1
        return [[VulnHit("CVE-1", "osv", "summary", 5.0, ())]]

    monkeypatch.setattr(service, "_query_osv_batch", fake_osv_batch)

    with service.use_config(tmp_path, 0):
        # 同一パッケージで大文字小文字が異なるものが含まれている場合
        deps = [("Requests", "2.0.0"), ("requests", "2.0.0")]
        res = service.bulk_lookup("python", deps)

    assert len(res) == 2
    # 両方に同じ照会結果がマッピングされていること
    assert res[("Requests", "2.0.0")][0].vuln_id == "CVE-1"
    assert res[("requests", "2.0.0")][0].vuln_id == "CVE-1"
    # _query_osv_batch の呼び出しは 1 回のみ（重複排除されている）
    assert call_count == 1


def test_query_osv_batch_detail_fallback_on_failure(monkeypatch):
    service = VulnLookupService()

    # 詳細の取得が None を返す（失敗）
    def fake_request(url, method="GET", headers=None, payload=None):
        if url == "https://api.osv.dev/v1/querybatch":
            return {"results": [{"vulns": [{"id": "GHSA-1"}]}]}
        # 詳細のAPI呼び出しに対して None (通信エラー等) を返す
        if "https://api.osv.dev/v1/vulns/" in url:
            return None
        return None

    monkeypatch.setattr(service, "_request_json", fake_request)

    res = service._query_osv_batch("python", [("pkg1", "1.0.0")])
    # 詳細の取得に失敗したため、全体が None (プロバイダ失敗扱い) になっていること
    assert res == [None]


def test_requery_success_removes_from_failed_deps(monkeypatch):
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    monkeypatch.setenv("VULN_ENABLE_FALLBACK", "false")
    service = VulnLookupService()

    # OSV Batch API は None を返す（一時的な失敗を模擬）
    def fake_osv_batch(ecosystem, packages):
        return None

    # 個別再照会（_query_provider）は成功して結果を返す
    def fake_query_provider(provider, ecosystem, name, version):
        if provider == "osv":
            return [VulnHit("CVE-RETRY-SUCCESS", "osv", "summary", 6.0, ())]
        return []

    monkeypatch.setattr(service, "_query_osv_batch", fake_osv_batch)
    monkeypatch.setattr(service, "_query_provider", fake_query_provider)

    deps = [("pkg1", "1.0.0")]
    res = service.bulk_lookup("python", deps)

    # 最終的な結果が正しく得られていること（failed_deps から除外されたため採用される）
    assert res[("pkg1", "1.0.0")][0].vuln_id == "CVE-RETRY-SUCCESS"


def test_osv_detail_cache_ttl(tmp_path, monkeypatch):
    service = VulnLookupService()

    call_count = 0

    def fake_request(url, method="GET", headers=None, payload=None):
        nonlocal call_count
        call_count += 1
        return {
            "id": "GHSA-DETAIL-TTL",
            "summary": f"OSV-TTL-COUNT-{call_count}",
        }

    monkeypatch.setattr(service, "_request_json", fake_request)

    with service.use_config(tmp_path, 2):
        # 初回：APIを呼び出してキャッシュに登録
        d1 = service._get_osv_vulnerability_detail("GHSA-DETAIL-TTL")
        assert d1 is not None
        assert d1.get("summary") == "OSV-TTL-COUNT-1"

        # 2回目（即時）：キャッシュがヒットし、API呼び出しは発生しない
        d2 = service._get_osv_vulnerability_detail("GHSA-DETAIL-TTL")
        assert d2.get("summary") == "OSV-TTL-COUNT-1"
        assert call_count == 1

        # 時間を経過させる（3秒）
        real_time = time.time()
        monkeypatch.setattr(time, "time", lambda: real_time + 3.0)

        # 3回目（期限切れ後）：再度APIが呼び出される
        d3 = service._get_osv_vulnerability_detail("GHSA-DETAIL-TTL")
        assert d3.get("summary") == "OSV-TTL-COUNT-2"
        assert call_count == 2
