from __future__ import annotations

import json
import logging
import threading
import os
import time
import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VulnHit:
    vuln_id: str
    source: str
    summary: str
    severity_score: Optional[float]
    references: Sequence[str]


class Flight:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.ref_count = 1
        self.has_result = False
        self.result: List[VulnHit] = []


class VulnLookupService:
    _process_cache: Dict[
        tuple[str, str, str, str, bool], tuple[float, List[VulnHit]]
    ] = {}
    _inflight_locks: Dict[tuple[str, str, str, str, bool], Flight] = {}
    _inflight_locks_lock = threading.Lock()
    _file_cache_write_counter = 0
    _file_cache_write_lock = threading.Lock()
    _active_config = threading.local()

    @classmethod
    @contextlib.contextmanager
    def use_config(cls, cache_dir: Path | None, cache_ttl: int | None):
        old_dir = getattr(cls._active_config, "cache_dir", None)
        old_ttl = getattr(cls._active_config, "cache_ttl", None)
        cls._active_config.cache_dir = cache_dir
        cls._active_config.cache_ttl = cache_ttl
        try:
            yield
        finally:
            cls._active_config.cache_dir = old_dir
            cls._active_config.cache_ttl = old_ttl

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

        cache_dir_raw = (
            os.environ.get("VULN_CACHE_DIR", "").strip().strip('"').strip("'")
        )
        if cache_dir_raw:
            self._default_cache_dir = (
                Path(cache_dir_raw).expanduser().resolve() / "vuln_cache"
            )
        else:
            import tempfile

            self._default_cache_dir = Path(tempfile.gettempdir()) / "oss_vuln_cache"

        cache_ttl_raw = (
            os.environ.get("VULN_CACHE_TTL_SEC", "").strip().strip('"').strip("'")
        )
        self._default_cache_ttl = int(cache_ttl_raw or "86400")
        self._local_state = threading.local()

    @property
    def _cache_dir(self) -> Path:
        active_dir = getattr(self._active_config, "cache_dir", None)
        if active_dir is not None:
            if active_dir.name == "vuln_cache":
                return active_dir
            return active_dir / "vuln_cache"
        return self._default_cache_dir

    @property
    def _cache_ttl(self) -> int:
        active_ttl = getattr(self._active_config, "cache_ttl", None)
        if active_ttl is not None:
            return active_ttl
        return self._default_cache_ttl

    MAX_PROCESS_CACHE_SIZE = 2000
    MAX_FILE_CACHE_SIZE = 5000

    def _decrement_flight(self, key: tuple[str, str, str, str, bool]) -> None:
        with self._inflight_locks_lock:
            flight = self._inflight_locks.get(key)
            if flight is not None:
                flight.ref_count -= 1
                if flight.ref_count <= 0:
                    self._inflight_locks.pop(key, None)

    def _enforce_process_cache_limit(self) -> None:
        now = time.time()
        expired_keys = []
        for k, (ts, _) in list(self._process_cache.items()):
            if self._cache_ttl > 0 and now - ts > self._cache_ttl:
                expired_keys.append(k)

        for k in expired_keys:
            self._process_cache.pop(k, None)

        while len(self._process_cache) > self.MAX_PROCESS_CACHE_SIZE:
            first_key = next(iter(self._process_cache))
            self._process_cache.pop(first_key, None)

    def _enforce_file_cache_limit(self, force: bool = False) -> None:
        try:
            if not force:
                with self._file_cache_write_lock:
                    self.__class__._file_cache_write_counter += 1
                    if self.__class__._file_cache_write_counter < 100:
                        return
                    self.__class__._file_cache_write_counter = 0

            if not self._cache_dir.exists():
                return

            json_files = list(self._cache_dir.glob("vuln_cache_*.json"))
            now = time.time()
            valid_files = []

            for file_path in json_files:
                try:
                    mtime = file_path.stat().st_mtime
                    if self._cache_ttl > 0 and now - mtime > self._cache_ttl:
                        file_path.unlink(missing_ok=True)
                        continue
                    valid_files.append((mtime, file_path))
                except Exception:
                    pass

            if len(valid_files) > self.MAX_FILE_CACHE_SIZE:
                valid_files.sort(key=lambda x: x[0])
                to_delete_count = len(valid_files) - self.MAX_FILE_CACHE_SIZE
                for i in range(to_delete_count):
                    try:
                        _, file_path = valid_files[i]
                        file_path.unlink(missing_ok=True)
                    except Exception:
                        pass
        except Exception as exc:
            logger.warning(f"Failed to enforce file cache limits: {exc}")

    def lookup(self, ecosystem: str, name: str, version: str) -> List[VulnHit]:
        providers_str = ",".join(self._provider_order)
        key = (
            ecosystem.lower(),
            name.lower(),
            version,
            providers_str,
            self._enable_fallback,
        )

        # 1. 最初のキャッシュチェック（ロックなし高速解決）
        val = self._process_cache.get(key)
        if val is not None:
            ts, cached_hits = val
            if self._cache_ttl <= 0 or time.time() - ts <= self._cache_ttl:
                logger.debug(f"Memory cache hit for {key}")
                return cached_hits
            else:
                logger.debug(f"Memory cache expired for {key}")
                self._process_cache.pop(key, None)

        if self._cache_ttl > 0:
            file_cache_data = self._read_file_cache(key)
            if file_cache_data is not None:
                file_ts, file_hits = file_cache_data
                logger.debug(f"File cache hit for {key}")
                self._process_cache[key] = (file_ts, file_hits)
                self._enforce_process_cache_limit()
                return file_hits

        # 2. 同一キーの照会を単一化する Single Flight ロック制御
        with self._inflight_locks_lock:
            if key not in self._inflight_locks:
                self._inflight_locks[key] = Flight()
            else:
                self._inflight_locks[key].ref_count += 1
            flight = self._inflight_locks[key]

        with flight.lock:
            try:
                # ロック獲得後の再チェック
                if flight.has_result:
                    return flight.result

                val = self._process_cache.get(key)
                if val is not None:
                    ts, cached_hits = val
                    if self._cache_ttl <= 0 or time.time() - ts <= self._cache_ttl:
                        return cached_hits

                if self._cache_ttl > 0:
                    file_cache_data = self._read_file_cache(key)
                    if file_cache_data is not None:
                        file_ts, file_hits = file_cache_data
                        self._process_cache[key] = (file_ts, file_hits)
                        self._enforce_process_cache_limit()
                        return file_hits

                logger.info(
                    f"Querying vulnerability providers for {ecosystem}:{name}:{version}"
                )
                providers = self._provider_order or ["osv"]
                all_hits: List[VulnHit] = []
                seen_ids = set()
                has_failure = False

                self._local_state.had_invalid = False
                for provider in providers:
                    hits = self._query_provider(provider, ecosystem, name, version)
                    if hits is None:
                        logger.warning(
                            f"Vulnerability provider '{provider}' query failed."
                        )
                        has_failure = True
                        continue

                    if getattr(self._local_state, "had_invalid", False):
                        logger.warning(
                            f"Vulnerability provider '{provider}' returned some invalid schema elements. "
                            "Results will not be cached."
                        )
                        has_failure = True

                    for hit in hits:
                        if hit.vuln_id in seen_ids:
                            continue
                        seen_ids.add(hit.vuln_id)
                        all_hits.append(hit)

                    if hits and not self._enable_fallback:
                        break

                flight.result = all_hits
                flight.has_result = True

                if not has_failure:
                    self._process_cache[key] = (time.time(), all_hits)
                    self._enforce_process_cache_limit()
                    if self._cache_ttl > 0:
                        self._write_file_cache(key, all_hits)
                else:
                    logger.info(
                        "Skipped caching vulnerability query result due to provider failure."
                    )
                return all_hits
            finally:
                self._decrement_flight(key)

    def _get_cache_file_path(self, key: tuple[str, str, str, str, bool]) -> Path:
        import hashlib

        ecosystem, name, version, providers, fallback = key
        hash_val = hashlib.md5(
            f"{ecosystem}:{name}:{version}:{providers}:{fallback}".encode("utf-8")
        ).hexdigest()
        return self._cache_dir / f"vuln_cache_{hash_val}.json"

    def _read_file_cache(
        self, key: tuple[str, str, str, str, bool]
    ) -> tuple[float, List[VulnHit]] | None:
        file_path = self._get_cache_file_path(key)
        if not file_path.exists():
            return None

        def _safe_unlink() -> None:
            try:
                file_path.unlink(missing_ok=True)
            except Exception as exc:
                logger.warning(
                    f"Failed to delete expired or corrupted cache file ({file_path}): {exc}"
                )

        try:
            mtime = file_path.stat().st_mtime
            if time.time() - mtime > self._cache_ttl:
                _safe_unlink()
                return None

            with file_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)

            if not isinstance(data, dict):
                _safe_unlink()
                return None

            timestamp = data.get("timestamp")
            if timestamp is None:
                timestamp = mtime

            if not isinstance(timestamp, (int, float)):
                _safe_unlink()
                return None

            if time.time() - timestamp > self._cache_ttl:
                _safe_unlink()
                return None

            hits_data = data.get("hits")
            if not isinstance(hits_data, list):
                _safe_unlink()
                return None

            hits: List[VulnHit] = []
            for item in hits_data:
                if not isinstance(item, dict):
                    _safe_unlink()
                    return None

                vuln_id = item.get("vuln_id")
                source = item.get("source")
                summary = item.get("summary")
                severity_score = item.get("severity_score")
                references = item.get("references")

                if not isinstance(vuln_id, str):
                    _safe_unlink()
                    return None
                if not isinstance(source, str):
                    _safe_unlink()
                    return None
                if not isinstance(summary, str):
                    _safe_unlink()
                    return None
                if severity_score is not None and not isinstance(
                    severity_score, (int, float)
                ):
                    _safe_unlink()
                    return None
                if not isinstance(references, (list, tuple)):
                    _safe_unlink()
                    return None
                if not all(isinstance(r, str) for r in references):
                    _safe_unlink()
                    return None

                hits.append(
                    VulnHit(
                        vuln_id=vuln_id,
                        source=source,
                        summary=summary,
                        severity_score=float(severity_score)
                        if severity_score is not None
                        else None,
                        references=tuple(references),
                    )
                )
            return timestamp, hits
        except Exception:
            _safe_unlink()
            return None

    def _write_file_cache(
        self, key: tuple[str, str, str, str, bool], hits: List[VulnHit]
    ) -> None:
        file_path = self._get_cache_file_path(key)
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            data = {
                "timestamp": time.time(),
                "hits": [
                    {
                        "vuln_id": h.vuln_id,
                        "source": h.source,
                        "summary": h.summary,
                        "severity_score": h.severity_score,
                        "references": h.references,
                    }
                    for h in hits
                ],
            }

            import tempfile

            with tempfile.NamedTemporaryFile(
                "w", dir=str(self._cache_dir), delete=False, encoding="utf-8"
            ) as tf:
                json.dump(data, tf)
                temp_name = tf.name

            try:
                os.replace(temp_name, str(file_path))
                self._enforce_file_cache_limit()
            except Exception:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
                raise
        except Exception as exc:
            logger.warning(
                f"Failed to write vulnerability cache file ({file_path}): {exc}",
                exc_info=True,
            )

    def _query_provider(
        self, provider: str, ecosystem: str, name: str, version: str
    ) -> List[VulnHit] | None:
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

    def _query_osv(
        self, ecosystem: str, name: str, version: str
    ) -> List[VulnHit] | None:
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
        if data is None:
            return None
        if not isinstance(data, dict):
            return None
        if not data:
            return []
        if "vulns" in data and isinstance(data["vulns"], list):
            vulns = data["vulns"]
        else:
            return None

        hits: List[VulnHit] = []

        for v in vulns:
            if not isinstance(v, dict):
                self._local_state.had_invalid = True
                continue

            vuln_id = v.get("id")
            if not isinstance(vuln_id, str):
                self._local_state.had_invalid = True
                continue

            summary = v.get("summary")
            if summary is not None and not isinstance(summary, str):
                self._local_state.had_invalid = True
                continue

            refs = []
            references_raw = v.get("references")
            if references_raw is not None:
                if not isinstance(references_raw, list):
                    self._local_state.had_invalid = True
                    continue
                ref_err = False
                for r in references_raw:
                    if not isinstance(r, dict):
                        ref_err = True
                        break
                    url = r.get("url")
                    if not isinstance(url, str):
                        ref_err = True
                        break
                    refs.append(url)
                if ref_err:
                    self._local_state.had_invalid = True
                    continue

            score = None
            severity_raw = v.get("severity")
            if severity_raw is not None:
                if not isinstance(severity_raw, list):
                    self._local_state.had_invalid = True
                    continue
                sev_err = False
                for sev in severity_raw:
                    if not isinstance(sev, dict):
                        sev_err = True
                        break
                    raw = sev.get("score")
                    if isinstance(raw, str) and "CVSS:" in raw:
                        try:
                            score = float(raw.rsplit("/", 1)[-1])
                            break
                        except ValueError:
                            pass
                if sev_err:
                    self._local_state.had_invalid = True
                    continue

            hits.append(
                VulnHit(
                    vuln_id=vuln_id,
                    source="osv",
                    summary=summary if summary else "Known vulnerability found",
                    severity_score=score,
                    references=refs,
                )
            )
        return hits

    def _query_github_advisory(self, ecosystem: str, name: str) -> List[VulnHit] | None:
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
        if data is None:
            return None
        if not isinstance(data, list):
            return None

        hits: List[VulnHit] = []

        for adv in data:
            if not isinstance(adv, dict):
                self._local_state.had_invalid = True
                continue

            ghsa = adv.get("ghsa_id")
            if not isinstance(ghsa, str):
                self._local_state.had_invalid = True
                continue

            summary = adv.get("summary")
            if summary is not None and not isinstance(summary, str):
                self._local_state.had_invalid = True
                continue

            url = adv.get("html_url")
            if url is not None and not isinstance(url, str):
                self._local_state.had_invalid = True
                continue

            score = None
            cvss = adv.get("cvss")
            if cvss is not None:
                if not isinstance(cvss, dict):
                    self._local_state.had_invalid = True
                    continue
                cvss_score = cvss.get("score")
                if cvss_score is not None:
                    if not isinstance(cvss_score, (int, float)):
                        self._local_state.had_invalid = True
                        continue
                    score = float(cvss_score)

            refs = [url] if url else []
            hits.append(
                VulnHit(
                    vuln_id=ghsa,
                    source="github",
                    summary=summary if summary else "GitHub advisory found",
                    severity_score=score,
                    references=refs,
                )
            )
        return hits

    def _query_nvd(self, name: str, version: str) -> List[VulnHit] | None:
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
        if data is None:
            return None
        if not isinstance(data, dict):
            return None
        if "vulnerabilities" not in data:
            return None
        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list):
            return None

        hits: List[VulnHit] = []

        for item in vulns:
            if not isinstance(item, dict):
                self._local_state.had_invalid = True
                continue
            cve = item.get("cve")
            if not isinstance(cve, dict):
                self._local_state.had_invalid = True
                continue

            vuln_id = cve.get("id")
            if not isinstance(vuln_id, str):
                self._local_state.had_invalid = True
                continue

            summary = "NVD vulnerability found"
            descs = cve.get("descriptions")
            if descs is not None:
                if not isinstance(descs, list):
                    self._local_state.had_invalid = True
                    continue
                desc_err = False
                for d in descs:
                    if not isinstance(d, dict):
                        desc_err = True
                        break
                    if d.get("lang") == "en":
                        val = d.get("value")
                        if not isinstance(val, str):
                            desc_err = True
                            break
                        summary = val
                        break
                if desc_err:
                    self._local_state.had_invalid = True
                    continue

            score = None
            metrics = cve.get("metrics")
            if metrics is not None:
                if not isinstance(metrics, dict):
                    self._local_state.had_invalid = True
                    continue
                metrics_err = False
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = metrics.get(key)
                    if arr is not None:
                        if not isinstance(arr, list):
                            metrics_err = True
                            break
                        if arr:
                            m0 = arr[0]
                            if not isinstance(m0, dict):
                                metrics_err = True
                                break
                            cvss_data = m0.get("cvssData")
                            if cvss_data is not None:
                                if not isinstance(cvss_data, dict):
                                    metrics_err = True
                                    break
                                base_score = cvss_data.get("baseScore")
                                if base_score is not None:
                                    if not isinstance(base_score, (int, float)):
                                        metrics_err = True
                                        break
                                    score = float(base_score)
                                    break
                if metrics_err:
                    self._local_state.had_invalid = True
                    continue

            refs = []
            references = cve.get("references")
            if references is not None:
                if not isinstance(references, list):
                    self._local_state.had_invalid = True
                    continue
                ref_err = False
                for r in references:
                    if not isinstance(r, dict):
                        ref_err = True
                        break
                    url = r.get("url")
                    if not isinstance(url, str):
                        ref_err = True
                        break
                    refs.append(url)
                if ref_err:
                    self._local_state.had_invalid = True
                    continue

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
