from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class VulnHit:
    vuln_id: str
    source: str
    summary: str
    severity_score: Optional[float]
    references: Sequence[str]


class VulnLookupService:
    def __init__(self) -> None:
        order_raw = os.environ.get("VULN_PROVIDER_ORDER", "osv,github,nvd")
        self._provider_order = [
            x.strip().lower() for x in order_raw.split(",") if x.strip()
        ]
        self._timeout_sec = int(os.environ.get("VULN_API_TIMEOUT_SEC", "10") or "10")
        self._max_retries = int(os.environ.get("VULN_MAX_RETRIES", "2") or "2")
        self._enable_fallback = (
            os.environ.get("VULN_ENABLE_FALLBACK", "true").strip().lower() == "true"
        )
        self._cache: Dict[tuple[str, str, str], List[VulnHit]] = {}

    def lookup(self, ecosystem: str, name: str, version: str) -> List[VulnHit]:
        key = (ecosystem.lower(), name.lower(), version)
        if key in self._cache:
            return self._cache[key]

        providers = self._provider_order or ["osv"]
        all_hits: List[VulnHit] = []
        seen_ids = set()

        for provider in providers:
            hits = self._query_provider(provider, ecosystem, name, version)
            for hit in hits:
                if hit.vuln_id in seen_ids:
                    continue
                seen_ids.add(hit.vuln_id)
                all_hits.append(hit)

            if hits and not self._enable_fallback:
                break

        self._cache[key] = all_hits
        return all_hits

    def _query_provider(
        self, provider: str, ecosystem: str, name: str, version: str
    ) -> List[VulnHit]:
        if provider == "osv":
            return self._query_osv(ecosystem, name, version)
        if provider == "github":
            return self._query_github_advisory(ecosystem, name)
        if provider == "nvd":
            return self._query_nvd(name, version)
        return []

    def _request_json(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        payload: Optional[dict] = None,
    ) -> Optional[dict]:
        body = None
        req_headers = {"User-Agent": "oss-security-risk-check-agent"}
        if headers:
            req_headers.update(headers)
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")

        for attempt in range(self._max_retries + 1):
            try:
                req = Request(url, data=body, headers=req_headers, method=method)
                with urlopen(req, timeout=self._timeout_sec) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                    return json.loads(raw)
            except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
                if attempt >= self._max_retries:
                    return None
                time.sleep(min(0.5 * (2**attempt), 2.0))
        return None

    def _query_osv(self, ecosystem: str, name: str, version: str) -> List[VulnHit]:
        osv_ecosystem = "PyPI" if ecosystem == "python" else "npm"
        payload = {
            "package": {"name": name, "ecosystem": osv_ecosystem},
            "version": version,
        }
        data = self._request_json(
            "https://api.osv.dev/v1/query",
            method="POST",
            payload=payload,
            headers={
                "Authorization": f"Bearer {os.environ.get('OSV_API_KEY', '').strip()}"
            }
            if os.environ.get("OSV_API_KEY", "").strip()
            else None,
        )
        if not data:
            return []
        vulns = data.get("vulns")
        if not isinstance(vulns, list):
            return []

        hits: List[VulnHit] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            refs = []
            for r in v.get("references", []) or []:
                if isinstance(r, dict) and isinstance(r.get("url"), str):
                    refs.append(r["url"])

            score = None
            for sev in v.get("severity", []) or []:
                if not isinstance(sev, dict):
                    continue
                raw = sev.get("score")
                if isinstance(raw, str) and "CVSS:" in raw:
                    try:
                        score = float(raw.rsplit("/", 1)[-1])
                        break
                    except ValueError:
                        pass

            hits.append(
                VulnHit(
                    vuln_id=str(v.get("id", "OSV-UNKNOWN")),
                    source="osv",
                    summary=str(v.get("summary") or "Known vulnerability found"),
                    severity_score=score,
                    references=refs,
                )
            )
        return hits

    def _query_github_advisory(self, ecosystem: str, name: str) -> List[VulnHit]:
        eco = "pip" if ecosystem == "python" else "npm"
        query = urlencode({"ecosystem": eco, "affects": name, "per_page": "20"})
        headers = {"Accept": "application/vnd.github+json"}
        token = (
            os.environ.get("GITHUB_TOKEN", "").strip()
            or os.environ.get("GH_TOKEN", "").strip()
        )
        if token:
            headers["Authorization"] = f"Bearer {token}"

        data = self._request_json(
            f"https://api.github.com/advisories?{query}", headers=headers
        )
        if not isinstance(data, list):
            return []

        hits: List[VulnHit] = []
        for adv in data:
            if not isinstance(adv, dict):
                continue
            ghsa = str(adv.get("ghsa_id") or "GHSA-UNKNOWN")
            summary = str(adv.get("summary") or "GitHub advisory found")
            url = adv.get("html_url")
            score = None
            cvss = adv.get("cvss")
            if isinstance(cvss, dict):
                cvss_score = cvss.get("score")
                if isinstance(cvss_score, (int, float)):
                    score = float(cvss_score)
            refs = [url] if isinstance(url, str) else []
            hits.append(
                VulnHit(
                    vuln_id=ghsa,
                    source="github",
                    summary=summary,
                    severity_score=score,
                    references=refs,
                )
            )
        return hits

    def _query_nvd(self, name: str, version: str) -> List[VulnHit]:
        query = urlencode(
            {"keywordSearch": f"{name} {version}", "resultsPerPage": "20"}
        )
        headers: Dict[str, str] = {}
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if api_key:
            headers["apiKey"] = api_key
        data = self._request_json(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
            headers=headers,
        )
        if not data:
            return []

        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list):
            return []

        hits: List[VulnHit] = []
        for item in vulns:
            if not isinstance(item, dict):
                continue
            cve = item.get("cve")
            if not isinstance(cve, dict):
                continue
            vuln_id = str(cve.get("id") or "CVE-UNKNOWN")
            summary = "NVD vulnerability found"
            descs = cve.get("descriptions")
            if isinstance(descs, list):
                for d in descs:
                    if (
                        isinstance(d, dict)
                        and d.get("lang") == "en"
                        and isinstance(d.get("value"), str)
                    ):
                        summary = d["value"]
                        break

            score = None
            metrics = cve.get("metrics")
            if isinstance(metrics, dict):
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = metrics.get(key)
                    if isinstance(arr, list) and arr:
                        m0 = arr[0]
                        if isinstance(m0, dict):
                            cvss_data = m0.get("cvssData")
                            if isinstance(cvss_data, dict) and isinstance(
                                cvss_data.get("baseScore"), (int, float)
                            ):
                                score = float(cvss_data["baseScore"])
                                break

            refs = []
            references = cve.get("references")
            if isinstance(references, list):
                for r in references:
                    if isinstance(r, dict) and isinstance(r.get("url"), str):
                        refs.append(r["url"])

            hits.append(
                VulnHit(
                    vuln_id=vuln_id,
                    source="nvd",
                    summary=summary,
                    severity_score=score,
                    references=refs,
                )
            )

        return hits
