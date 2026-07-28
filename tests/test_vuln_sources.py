from __future__ import annotations

import json
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
