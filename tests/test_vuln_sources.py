from __future__ import annotations

import json
import os
import time
import urllib.error

import pytest

from src.rules.B_dependencies import vuln_sources as vuln_module
from src.rules.B_dependencies.vuln_sources import VulnLookupService


class JsonResponse:
    def __init__(self, payload: object) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._body


class RawResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._body


@pytest.fixture(autouse=True)
def stable_vuln_env(monkeypatch):
    monkeypatch.setenv("VULN_API_TIMEOUT_SEC", "1")
    monkeypatch.setenv("VULN_MAX_RETRIES", "0")
    monkeypatch.setenv("VULN_ENABLE_FALLBACK", "true")
    monkeypatch.delenv("OSV_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "0")
    VulnLookupService._process_cache.clear()


def test_lookup_queries_enabled_providers_deduplicates_and_caches(monkeypatch):
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv,github,nvd,unknown")
    service = VulnLookupService()
    calls = []

    def fake_query(provider: str, ecosystem: str, name: str, version: str):
        calls.append((provider, ecosystem, name, version))
        if provider == "unknown":
            return []
        return [
            vuln_module.VulnHit(
                vuln_id="CVE-2099-0001",
                source=provider,
                summary=f"{provider} hit",
                severity_score=7.5,
                references=(),
            )
        ]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    first = service.lookup("Python", "Requests", "2.0.0")
    second = service.lookup("python", "requests", "2.0.0")

    assert len(first) == 1
    assert first is second
    assert calls == [
        ("osv", "Python", "Requests", "2.0.0"),
        ("github", "Python", "Requests", "2.0.0"),
        ("nvd", "Python", "Requests", "2.0.0"),
        ("unknown", "Python", "Requests", "2.0.0"),
    ]


def test_lookup_stops_after_first_hit_when_fallback_is_disabled(monkeypatch):
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv,github")
    monkeypatch.setenv("VULN_ENABLE_FALLBACK", "false")
    service = VulnLookupService()
    calls = []

    def fake_query(provider: str, ecosystem: str, name: str, version: str):
        calls.append(provider)
        return [vuln_module.VulnHit("ID-1", provider, "summary", None, ())]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    assert service.lookup("python", "pkg", "1.0")
    assert calls == ["osv"]


def test_request_json_sends_payload_headers_and_parses_response(monkeypatch):
    monkeypatch.setenv("VULN_MAX_RETRIES", "0")
    service = VulnLookupService()
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["content_type"] = request.headers["Content-type"]
        captured["custom"] = request.headers["X-test"]
        captured["timeout"] = timeout
        return JsonResponse({"ok": True})

    monkeypatch.setattr(vuln_module, "urlopen", fake_urlopen)

    data = service._request_json(
        "https://example.test/api",
        method="POST",
        headers={"X-Test": "yes"},
        payload={"package": "demo"},
    )

    assert data == {"ok": True}
    assert captured == {
        "url": "https://example.test/api",
        "method": "POST",
        "body": {"package": "demo"},
        "content_type": "application/json",
        "custom": "yes",
        "timeout": 1,
    }


def test_request_json_retries_then_returns_none(monkeypatch):
    monkeypatch.setenv("VULN_MAX_RETRIES", "1")
    service = VulnLookupService()
    attempts = []

    def fake_urlopen(request, timeout):
        attempts.append(request.full_url)
        raise urllib.error.URLError("temporary failure")

    monkeypatch.setattr(vuln_module, "urlopen", fake_urlopen)
    monkeypatch.setattr(vuln_module.time, "sleep", lambda seconds: None)

    assert service._request_json("https://example.test/api") is None
    assert attempts == ["https://example.test/api", "https://example.test/api"]


def test_request_json_returns_none_for_invalid_json(monkeypatch):
    service = VulnLookupService()
    monkeypatch.setattr(
        vuln_module, "urlopen", lambda request, timeout: RawResponse(b"not-json")
    )

    assert service._request_json("https://example.test/api") is None


def test_query_osv_maps_vulnerability_fields(monkeypatch):
    monkeypatch.setenv("OSV_API_KEY", "osv-token")
    service = VulnLookupService()
    captured = {}

    def fake_request(url, method="GET", headers=None, payload=None):
        captured["url"] = url
        captured["method"] = method
        captured["headers"] = headers
        captured["payload"] = payload
        return {
            "vulns": [
                {
                    "id": "OSV-2024-1",
                    "summary": "OSV summary",
                    "references": [{"url": "https://osv.dev/vuln/OSV-2024-1"}],
                    "severity": [{"score": "CVSS:3.1/AV:N/AC:L/9.1"}],
                },
                "ignored",
                {"id": "OSV-NOSCORE", "severity": [{"score": "bad"}]},
            ]
        }

    monkeypatch.setattr(service, "_request_json", fake_request)

    hits = service._query_osv("python", "demo", "1.2.3")

    assert captured["method"] == "POST"
    assert captured["headers"] == {"Authorization": "Bearer osv-token"}
    assert captured["payload"] == {
        "package": {"name": "demo", "ecosystem": "PyPI"},
        "version": "1.2.3",
    }
    assert [hit.vuln_id for hit in hits] == ["OSV-2024-1", "OSV-NOSCORE"]
    assert hits[0].severity_score == 9.1
    assert hits[0].references == ["https://osv.dev/vuln/OSV-2024-1"]


def test_query_github_advisory_maps_response_and_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
    service = VulnLookupService()
    captured = {}

    def fake_request(url, method="GET", headers=None, payload=None):
        captured["url"] = url
        captured["headers"] = headers
        return [
            {
                "ghsa_id": "GHSA-xxxx-yyyy",
                "summary": "GitHub summary",
                "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy",
                "cvss": {"score": 8.8},
            },
            object(),
        ]

    monkeypatch.setattr(service, "_request_json", fake_request)

    hits = service._query_github_advisory("python", "demo")

    assert "ecosystem=pip" in captured["url"]
    assert "affects=demo" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer gh-token"
    assert len(hits) == 1
    assert hits[0].vuln_id == "GHSA-xxxx-yyyy"
    assert hits[0].severity_score == 8.8


def test_query_nvd_maps_nested_cve_fields(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "nvd-token")
    service = VulnLookupService()
    captured = {}

    def fake_request(url, method="GET", headers=None, payload=None):
        captured["url"] = url
        captured["headers"] = headers
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [
                            {"lang": "ja", "value": "日本語"},
                            {"lang": "en", "value": "English description"},
                        ],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                        },
                        "references": [
                            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}
                        ],
                    }
                },
                {"not_cve": {}},
            ]
        }

    monkeypatch.setattr(service, "_request_json", fake_request)

    hits = service._query_nvd("demo", "1.0.0")
    assert "keywordSearch=demo+1.0.0" in captured["url"]
    assert captured["headers"] == {"apiKey": "nvd-token"}
    assert len(hits) == 1
    assert hits[0].vuln_id == "CVE-2024-0001"
    assert hits[0].summary == "English description"
    assert hits[0].severity_score == 9.8


def test_vuln_lookup_service_shares_process_cache(monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")

    service1 = VulnLookupService()
    service2 = VulnLookupService()

    calls = []

    def fake_query(provider, ecosystem, name, version):
        calls.append((provider, name))
        return [
            vuln_module.VulnHit(
                vuln_id="CVE-2099-0002",
                source=provider,
                summary="mocked vuln",
                severity_score=5.0,
                references=(),
            )
        ]

    monkeypatch.setattr(service1, "_query_provider", fake_query)
    monkeypatch.setattr(service2, "_query_provider", fake_query)

    hits1 = service1.lookup("python", "mock-pkg", "1.0")
    assert len(hits1) == 1
    assert calls == [("osv", "mock-pkg")]

    hits2 = service2.lookup("python", "mock-pkg", "1.0")
    assert hits1 == hits2
    assert calls == [("osv", "mock-pkg")]


def test_vuln_lookup_service_file_cache_persistence_and_ttl(tmp_path, monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")

    monkeypatch.setenv("VULN_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "10")

    service = VulnLookupService()
    calls = []

    def fake_query(provider, ecosystem, name, version):
        calls.append(name)
        return [
            vuln_module.VulnHit(
                vuln_id="CVE-2099-0003",
                source=provider,
                summary="persistent vuln",
                severity_score=6.0,
                references=(),
            )
        ]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    hits1 = service.lookup("python", "pkg-persistent", "1.0")
    assert len(hits1) == 1
    assert calls == ["pkg-persistent"]

    cache_files = list(tmp_path.glob("*.json"))
    assert len(cache_files) == 1

    VulnLookupService._process_cache.clear()

    hits2 = service.lookup("python", "pkg-persistent", "1.0")
    assert hits1[0].vuln_id == hits2[0].vuln_id
    assert calls == ["pkg-persistent"]

    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "0")
    service_no_cache = VulnLookupService()
    monkeypatch.setattr(service_no_cache, "_query_provider", fake_query)
    VulnLookupService._process_cache.clear()

    hits3 = service_no_cache.lookup("python", "pkg-persistent", "1.0")
    assert len(hits3) == 1
    assert calls == ["pkg-persistent", "pkg-persistent"]


def test_vuln_lookup_service_cache_distinguishes_provider_configs(monkeypatch):
    VulnLookupService._process_cache.clear()

    calls = []

    def fake_query(provider, ecosystem, name, version):
        calls.append(provider)
        return [
            vuln_module.VulnHit(
                vuln_id=f"CVE-{provider}",
                source=provider,
                summary="vuln",
                severity_score=5.0,
                references=(),
            )
        ]

    # OSV のみの場合のサービス
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    service_osv = VulnLookupService()
    monkeypatch.setattr(service_osv, "_query_provider", fake_query)

    hits_osv = service_osv.lookup("python", "pkg-multi", "1.0")
    assert len(hits_osv) == 1
    assert hits_osv[0].source == "osv"
    assert calls == ["osv"]

    # 後から GITHUB も追加した場合のサービス
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv,github")
    service_multi = VulnLookupService()
    monkeypatch.setattr(service_multi, "_query_provider", fake_query)

    hits_multi = service_multi.lookup("python", "pkg-multi", "1.0")
    # キーが異なる（プロバイダ設定が異なる）ため、メモリ・ファイルキャッシュ共にヒットせず再照会される
    assert len(hits_multi) == 2
    assert hits_multi[1].source == "github"
    assert calls == ["osv", "osv", "github"]


def test_vuln_lookup_service_does_not_cache_failures(monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv,github")
    monkeypatch.setenv("VULN_ENABLE_FALLBACK", "true")

    service = VulnLookupService()
    calls = []

    def fake_query(provider, ecosystem, name, version):
        calls.append(provider)
        if provider == "osv":
            # OSVは通信障害
            return None
        return [
            vuln_module.VulnHit(
                vuln_id="CVE-GITHUB",
                source="github",
                summary="github vuln",
                severity_score=4.0,
                references=(),
            )
        ]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    # 1回目の照合
    hits1 = service.lookup("python", "pkg-fail", "1.0")
    # OSVが失敗したので、結果はGitHubのデータのみ。かつ has_failure=True のためキャッシュに保存されないはず
    assert len(hits1) == 1
    assert calls == ["osv", "github"]

    # 2回目の照合 -> キャッシュに入っていないため、再び外部API（モック）が叩かれる
    hits2 = service.lookup("python", "pkg-fail", "1.0")
    assert len(hits2) == 1
    assert calls == ["osv", "github", "osv", "github"]


def test_vuln_lookup_service_process_cache_ttl(monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    # TTLを極端に短く（1秒）設定
    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "1")

    service = VulnLookupService()
    calls = []

    def fake_query(provider, ecosystem, name, version):
        calls.append(name)
        return [
            vuln_module.VulnHit(
                vuln_id="CVE-2099-0004",
                source=provider,
                summary="short-lived vuln",
                severity_score=6.0,
                references=(),
            )
        ]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    # 1回目の照合 -> キャッシュが作られる
    hits1 = service.lookup("python", "pkg-short", "1.0")
    assert len(hits1) == 1
    assert calls == ["pkg-short"]

    # すぐに2回目を照合 -> メモリキャッシュから返る
    hits2 = service.lookup("python", "pkg-short", "1.0")
    assert hits1 == hits2
    assert calls == ["pkg-short"]

    # 時間を進める（2秒スリープ）
    import time

    time.sleep(2.0)

    # 3回目の照合 -> メモリキャッシュがTTL切れで破棄され、再びAPIが呼ばれる
    hits3 = service.lookup("python", "pkg-short", "1.0")
    assert len(hits3) == 1
    assert calls == ["pkg-short", "pkg-short"]


def test_vuln_lookup_service_concurrent_access(monkeypatch):
    import threading

    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")

    service = VulnLookupService()

    def fake_query(provider, ecosystem, name, version):
        time.sleep(0.05)
        return [
            vuln_module.VulnHit(
                vuln_id="CVE-2099-9999",
                source=provider,
                summary="concurrent vuln",
                severity_score=9.0,
                references=(),
            )
        ]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    errors = []

    def run_lookup():
        try:
            service.lookup("python", "pkg-concurrent-test", "1.0")
            monkeypatch.setenv("VULN_CACHE_TTL_SEC", "0")
            service.lookup("python", "pkg-concurrent-test", "1.0")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run_lookup) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors


def test_vuln_lookup_service_inherits_file_cache_timestamp(tmp_path, monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "100")
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")

    service = VulnLookupService()
    calls = []

    def fake_query(provider, ecosystem, name, version):
        calls.append(name)
        return [vuln_module.VulnHit("CVE-TS", provider, "vuln", 5.0, ())]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    # 1. 最初の照合
    service.lookup("python", "pkg-ts", "1.0")

    cache_files = list(tmp_path.glob("*.json"))
    assert len(cache_files) == 1
    cache_file = cache_files[0]

    with cache_file.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    past_time = time.time() - 50.0
    data["timestamp"] = past_time

    with cache_file.open("w", encoding="utf-8") as fh:
        json.dump(data, fh)

    os.utime(cache_file, (past_time, past_time))

    VulnLookupService._process_cache.clear()

    # 2. ファイルキャッシュからの読み込み
    service.lookup("python", "pkg-ts", "1.0")

    providers_str = ",".join(service._provider_order)
    key = ("python", "pkg-ts", "1.0", providers_str, service._enable_fallback)

    cached_val = VulnLookupService._process_cache.get(key)
    assert cached_val is not None
    ts, _ = cached_val
    assert ts == pytest.approx(past_time, abs=1.0)


def test_vuln_lookup_service_does_not_cache_schema_violations(monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")

    service = VulnLookupService()

    def fake_request(url, method="GET", headers=None, payload=None):
        return {"invalid_key_no_vulns": []}

    monkeypatch.setattr(service, "_request_json", fake_request)

    hits = service.lookup("python", "pkg-schema-violation", "1.0")
    assert hits == []

    providers_str = ",".join(service._provider_order)
    key = (
        "python",
        "pkg-schema-violation",
        "1.0",
        providers_str,
        service._enable_fallback,
    )
    assert key not in VulnLookupService._process_cache


def test_vuln_lookup_service_process_cache_size_limit(monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    service = VulnLookupService()

    monkeypatch.setattr(service, "MAX_PROCESS_CACHE_SIZE", 3)

    def fake_query(provider, ecosystem, name, version):
        return [vuln_module.VulnHit(f"CVE-{name}", provider, "vuln", 5.0, ())]

    monkeypatch.setattr(service, "_query_provider", fake_query)

    service.lookup("python", "pkg-a", "1.0")
    service.lookup("python", "pkg-b", "1.0")
    service.lookup("python", "pkg-c", "1.0")
    service.lookup("python", "pkg-d", "1.0")

    assert len(VulnLookupService._process_cache) == 3

    providers_str = ",".join(service._provider_order)
    key_a = ("python", "pkg-a", "1.0", providers_str, service._enable_fallback)
    assert key_a not in VulnLookupService._process_cache


def test_vuln_lookup_service_file_cache_type_validation(tmp_path, monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    service = VulnLookupService()

    providers_str = ",".join(service._provider_order)
    key = ("python", "pkg-invalid-type", "1.0", providers_str, service._enable_fallback)
    file_path = service._get_cache_file_path(key)

    bad_data = {
        "timestamp": time.time(),
        "hits": [
            {
                "vuln_id": "CVE-BAD",
                "source": "osv",
                "summary": "bad summary",
                "severity_score": "HIGH",
                "references": [],
            }
        ],
    }
    tmp_path.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as fh:
        json.dump(bad_data, fh)

    calls = []

    def fake_query(provider, ecosystem, name, version):
        calls.append(name)
        return []

    monkeypatch.setattr(service, "_query_provider", fake_query)

    hits = service.lookup("python", "pkg-invalid-type", "1.0")
    assert hits == []
    assert calls == ["pkg-invalid-type"]


def test_vuln_lookup_service_file_cache_deleted_on_expiry(tmp_path, monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "100")
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    service = VulnLookupService()

    providers_str = ",".join(service._provider_order)
    key = ("python", "pkg-del-expiry", "1.0", providers_str, service._enable_fallback)
    file_path = service._get_cache_file_path(key)

    past_time = time.time() - 150.0
    bad_data = {
        "timestamp": past_time,
        "hits": [],
    }
    tmp_path.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as fh:
        json.dump(bad_data, fh)

    assert file_path.exists()

    res = service._read_file_cache(key)
    assert res is None
    assert not file_path.exists()


def test_vuln_lookup_service_file_cache_corrupted_deleted(tmp_path, monkeypatch):
    VulnLookupService._process_cache.clear()
    monkeypatch.setenv("VULN_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("VULN_CACHE_TTL_SEC", "100")
    monkeypatch.setenv("VULN_PROVIDER_ORDER", "osv")
    service = VulnLookupService()

    providers_str = ",".join(service._provider_order)
    key = ("python", "pkg-del-corrupt", "1.0", providers_str, service._enable_fallback)
    file_path = service._get_cache_file_path(key)

    bad_data = {"this-is-not-valid-json-schema": True}
    tmp_path.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as fh:
        json.dump(bad_data, fh)

    assert file_path.exists()

    res = service._read_file_cache(key)
    assert res is None
    assert not file_path.exists()
