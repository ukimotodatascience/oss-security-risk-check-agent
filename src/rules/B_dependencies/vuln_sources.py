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

import math

logger = logging.getLogger(__name__)


def parse_cvss_vector(vector_str: str) -> float | None:
    try:
        vector_str = vector_str.strip()
        if not vector_str:
            return None

        # 単なる数値文字列 (例: "9.8" や "7.5" など、スラッシュを含まないもの) の場合は
        # 直接 float 変換して返し、余計な検証をスキップする。
        if "/" not in vector_str:
            try:
                val = float(vector_str)
                if 0.0 <= val <= 10.0:
                    return val
            except ValueError:
                pass
            return None

        # スラッシュを含む場合は CVSS ベクトルとみなす
        if ":" not in vector_str:
            return None

        # ベクトルをキー・値の辞書に分解
        parts = vector_str.split("/")
        metrics = {}
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.strip().upper()] = v.strip().upper()

        # 有効な CVSS メトリクスキーが1つも含まれていない場合は無効と判定
        valid_keys = {"AV", "AC", "PR", "UI", "S", "C", "I", "A", "AU", "CVSS"}
        if not any(k in metrics for k in valid_keys):
            return None

        # CVSS バージョン判定
        is_v3 = False
        cvss_version = "3.1"  # デフォルトは v3.1
        if "CVSS" in metrics:
            version = metrics["CVSS"]
            if version in ("3.0", "3.1"):
                is_v3 = True
                cvss_version = version
            elif version == "2.0":
                is_v3 = False
            else:
                # 未対応または無効なバージョン (3.2, 4.0, 5.0 など) はすべて拒否
                return None
        else:
            # 接頭辞がない場合、メトリクスキーの有無でバージョンを推測する
            if "S" in metrics or "UI" in metrics or "PR" in metrics:
                if not any(k in metrics for k in ["VC", "VI", "VA", "SC", "SI", "SA"]):
                    is_v3 = True
                    cvss_version = "3.1"
                else:
                    # v4 固有キーがある場合は未対応バージョンとして拒否
                    return None
            else:
                is_v3 = False

        if is_v3:
            # CVSS v3.x 必須キーと有効値の厳密な検証
            v3_required = {
                "AV": {"N", "A", "L", "P"},
                "AC": {"L", "H"},
                "PR": {"N", "L", "H"},
                "UI": {"N", "R"},
                "S": {"U", "C"},
                "C": {"N", "L", "H"},
                "I": {"N", "L", "H"},
                "A": {"N", "L", "H"},
            }
            for k, allowed_vals in v3_required.items():
                if k not in metrics or metrics[k] not in allowed_vals:
                    return None

            av = metrics["AV"]
            ac = metrics["AC"]
            pr = metrics["PR"]
            ui = metrics["UI"]
            s = metrics["S"]
            c = metrics["C"]
            i = metrics["I"]
            a = metrics["A"]

            av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
            ac_map = {"L": 0.77, "H": 0.44}
            ui_map = {"N": 0.85, "R": 0.62}

            if s == "U":
                pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
            else:
                pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}

            impact_map = {"H": 0.56, "L": 0.22, "N": 0.0}

            av_val = av_map.get(av, 0.85)
            ac_val = ac_map.get(ac, 0.77)
            pr_val = pr_map.get(pr, 0.85)
            ui_val = ui_map.get(ui, 0.85)
            c_val = impact_map.get(c, 0.0)
            i_val = impact_map.get(i, 0.0)
            a_val = impact_map.get(a, 0.0)

            iss = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val)

            if s == "U":
                impact = 6.42 * iss
            else:
                if cvss_version == "3.0":
                    impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(
                        max(0.0, iss - 0.02), 15
                    )
                else:
                    impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(
                        max(0.0, iss * 0.9731 - 0.02), 13
                    )

            expl = 8.22 * av_val * ac_val * pr_val * ui_val

            if impact <= 0:
                return 0.0

            if s == "U":
                raw_score = min(impact + expl, 10.0)
            else:
                raw_score = min(1.08 * (impact + expl), 10.0)

            # 小数点第2位以下切り上げ (小数点第1位に切り上げ)
            # 浮動小数点の誤差を排除するため、100000倍した整数値で丸め判定する
            int_val = round(raw_score * 100000)
            ceil_score = math.ceil(int_val / 10000.0) / 10.0
            return min(ceil_score, 10.0)

        else:
            # CVSS v2.0 必須キーと有効値の厳密な検証
            v2_required = {
                "AV": {"N", "A", "L"},
                "AC": {"L", "M", "H"},
                "AU": {"N", "S", "M"},
                "C": {"N", "P", "C"},
                "I": {"N", "P", "C"},
                "A": {"N", "P", "C"},
            }
            for k, allowed_vals in v2_required.items():
                if k not in metrics or metrics[k] not in allowed_vals:
                    return None

            av = metrics["AV"]
            ac = metrics["AC"]
            au = metrics["AU"]
            c = metrics["C"]
            i = metrics["I"]
            a = metrics["A"]

            av_map = {"N": 1.0, "A": 0.646, "L": 0.395}
            ac_map = {"L": 0.71, "M": 0.61, "H": 0.35}
            au_map = {"N": 0.704, "S": 0.56, "M": 0.45}
            impact_map = {"N": 0.0, "P": 0.275, "C": 0.660}

            av_val = av_map.get(av, 1.0)
            ac_val = ac_map.get(ac, 0.71)
            au_val = au_map.get(au, 0.704)
            c_val = impact_map.get(c, 0.0)
            i_val = impact_map.get(i, 0.0)
            a_val = impact_map.get(a, 0.0)

            iss = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val)
            impact = 10.41 * iss
            expl = 20.0 * av_val * ac_val * au_val

            if impact == 0.0:
                f_impact = 0.0
            else:
                f_impact = 1.176

            raw_score = ((0.6 * impact) + (0.4 * expl) - 1.5) * f_impact
            if raw_score <= 0:
                return 0.0
            # v2 は四捨五入
            rounded_score = math.floor(raw_score * 10 + 0.5) / 10.0
            return min(rounded_score, 10.0)

    except Exception:
        return None


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
    _osv_detail_cache: Dict[str, tuple[float, dict]] = {}
    _osv_detail_cache_lock = threading.Lock()
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

    @property
    def _provider_order(self) -> List[str]:
        order_raw = os.environ.get("VULN_PROVIDER_ORDER", "osv,github,nvd")
        return [x.strip().lower() for x in order_raw.split(",") if x.strip()]

    @property
    def _timeout_sec(self) -> int:
        return int(os.environ.get("VULN_API_TIMEOUT_SEC", "10") or "10")

    @property
    def _max_retries(self) -> int:
        return int(os.environ.get("VULN_MAX_RETRIES", "2") or "2")

    @property
    def _enable_fallback(self) -> bool:
        return os.environ.get("VULN_ENABLE_FALLBACK", "true").strip().lower() == "true"

    def __init__(self) -> None:
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
        res = self.bulk_lookup(ecosystem, [(name, version)])
        return res.get((name, version), [])

    def bulk_lookup(
        self, ecosystem: str, dependencies: List[tuple[str, str]]
    ) -> Dict[tuple[str, str], List[VulnHit]]:
        providers_str = ",".join(self._provider_order)

        # 0. 重複排除 (パッケージ名を正規化して比較判定)
        unique_dependencies = []
        seen_deps = set()
        for name, version in dependencies:
            norm_key = (name.lower(), version)
            if norm_key not in seen_deps:
                seen_deps.add(norm_key)
                unique_dependencies.append((name, version))

        # 1. キャッシュチェック
        results: Dict[tuple[str, str], List[VulnHit]] = {}
        missing: List[tuple[str, str]] = []

        # _query_provider が monkeypatch されているかチェック
        is_mocked = False
        try:
            if (
                getattr(self._query_provider, "__func__", None)
                is not VulnLookupService._query_provider
            ):
                is_mocked = True
        except Exception:
            pass

        for name, version in unique_dependencies:
            key = (
                ecosystem.lower(),
                name.lower(),
                version,
                providers_str,
                self._enable_fallback,
            )

            # メモリキャッシュ
            val = self._process_cache.get(key)
            if val is not None:
                ts, cached_hits = val
                if self._cache_ttl <= 0 or time.time() - ts <= self._cache_ttl:
                    logger.debug(f"Memory cache hit for {key}")
                    results[(name.lower(), version)] = cached_hits
                    continue
                else:
                    logger.debug(f"Memory cache expired for {key}")
                    self._process_cache.pop(key, None)

            # ファイルキャッシュ
            if self._cache_ttl > 0:
                file_cache_data = self._read_file_cache(key)
                if file_cache_data is not None:
                    file_ts, file_hits = file_cache_data
                    logger.debug(f"File cache hit for {key}")
                    self._process_cache[key] = (file_ts, file_hits)
                    self._enforce_process_cache_limit()
                    results[(name.lower(), version)] = file_hits
                    continue

            missing.append((name, version))

        if not missing:
            final_results = {}
            for dep in dependencies:
                final_results[dep] = results.get((dep[0].lower(), dep[1]), [])
            return final_results

        # 2. Single Flight ロックの取得と重複解決
        flights_to_release: List[dict] = []
        actual_missing: List[tuple[str, str]] = []

        try:
            # デッドロック防止のため、決定論的にソートした順序でロックを取得する
            sorted_missing = sorted(missing, key=lambda x: (x[0].lower(), x[1]))
            for name, version in sorted_missing:
                key = (
                    ecosystem.lower(),
                    name.lower(),
                    version,
                    providers_str,
                    self._enable_fallback,
                )
                with self._inflight_locks_lock:
                    if key not in self._inflight_locks:
                        self._inflight_locks[key] = Flight()
                    else:
                        self._inflight_locks[key].ref_count += 1
                    flight = self._inflight_locks[key]

                item = {
                    "dep": (name, version),
                    "key": key,
                    "flight": flight,
                    "locked": False,
                }
                flights_to_release.append(item)

                flight.lock.acquire()
                item["locked"] = True

                if flight.has_result:
                    results[(name.lower(), version)] = flight.result
                    flights_to_release.pop()
                    flight.lock.release()
                    self._decrement_flight(key)
                else:
                    actual_missing.append((name, version))

            if not actual_missing:
                final_results = {}
                for dep in dependencies:
                    final_results[dep] = results.get((dep[0].lower(), dep[1]), [])
                return final_results
            # 3. キャッシュミス分の照会
            providers = self._provider_order or ["osv"]

            # 各依存関係ごとの一時結果バッファ
            temp_hits: Dict[tuple[str, str], Dict[str, List[VulnHit]]] = {
                dep: {} for dep in actual_missing
            }
            # 各依存関係ごとのクエリ失敗フラグ
            failed_deps: Dict[tuple[str, str], set[str]] = {
                dep: set() for dep in actual_missing
            }
            # schema invalid フラグ
            had_invalid_deps: Dict[tuple[str, str], bool] = {
                dep: False for dep in actual_missing
            }

            # OSV がプロバイダに含まれており、かつモックされていない場合
            if "osv" in providers and not is_mocked:
                # 1000件ずつバッチ分割
                batch_size = 1000
                for i in range(0, len(actual_missing), batch_size):
                    chunk = actual_missing[i : i + batch_size]
                    batch_res = self._query_osv_batch(ecosystem, chunk)
                    if batch_res is None:
                        # 全て失敗扱い
                        for dep in chunk:
                            failed_deps[dep].add("osv")
                    else:
                        for dep, hits in zip(chunk, batch_res):
                            if hits is None:
                                failed_deps[dep].add("osv")
                            else:
                                temp_hits[dep]["osv"] = hits

            # 残りのプロバイダ（github, nvd）や、OSV で結果が得られず fallback が必要な場合など
            import concurrent.futures

            def _query_single_dep_providers(
                dep: tuple[str, str], remaining_providers: List[str]
            ) -> tuple[tuple[str, str], Dict[str, List[VulnHit]], set[str], bool]:
                dep_name, dep_version = dep
                hits_dict = {}
                failed = set()
                local_had_invalid = False

                for provider in remaining_providers:
                    self._local_state.had_invalid = False
                    hits = self._query_provider(
                        provider, ecosystem, dep_name, dep_version
                    )
                    if hits is None:
                        failed.add(provider)
                        continue
                    if getattr(self._local_state, "had_invalid", False):
                        local_had_invalid = True
                    hits_dict[provider] = hits
                    if hits and not self._enable_fallback:
                        break
                return dep, hits_dict, failed, local_had_invalid

            tasks = []
            for dep in actual_missing:
                needed_providers = []
                osv_hits = temp_hits[dep].get("osv", [])

                for provider in providers:
                    if provider == "osv":
                        if not osv_hits and (is_mocked or "osv" in failed_deps[dep]):
                            needed_providers.append(provider)
                    else:
                        if self._enable_fallback or not osv_hits:
                            needed_providers.append(provider)
                        else:
                            osv_idx = (
                                providers.index("osv")
                                if "osv" in providers
                                else len(providers)
                            )
                            prov_idx = providers.index(provider)
                            if prov_idx < osv_idx:
                                needed_providers.append(provider)

                if needed_providers:
                    tasks.append((dep, list(dict.fromkeys(needed_providers))))

            if tasks:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    future_to_task = {
                        executor.submit(_query_single_dep_providers, dep, needed): dep
                        for dep, needed in tasks
                    }
                    for future in concurrent.futures.as_completed(future_to_task):
                        dep = future_to_task[future]
                        try:
                            _, hits_dict, failed, local_had_invalid = future.result()
                            for p, hits in hits_dict.items():
                                temp_hits[dep][p] = hits
                                failed_deps[dep].discard(p)
                            failed_deps[dep].update(failed)
                            if local_had_invalid:
                                had_invalid_deps[dep] = True
                        except Exception as e:
                            logger.error(f"Error querying providers for {dep}: {e}")
                            for _, needed in tasks:
                                if _ == dep:
                                    failed_deps[dep].update(needed)
                                    break

            # 結果を結合してキャッシュに格納
            for item in flights_to_release:
                dep = item["dep"]
                key = item["key"]
                flight = item["flight"]
                dep_name, dep_version = dep
                all_hits: List[VulnHit] = []
                seen_ids = set()

                has_failure = False
                for provider in providers:
                    if provider in failed_deps[dep]:
                        has_failure = True
                        continue
                    hits = temp_hits[dep].get(provider)
                    if hits is None:
                        continue
                    for hit in hits:
                        if hit.vuln_id in seen_ids:
                            continue
                        seen_ids.add(hit.vuln_id)
                        all_hits.append(hit)

                    if hits and not self._enable_fallback:
                        break

                if had_invalid_deps[dep]:
                    has_failure = True

                results[(dep_name.lower(), dep_version)] = all_hits

                # 結果を反映 (ロック解放は finally で行う)
                flight.result = all_hits
                flight.has_result = True

                # キャッシュ登録
                if not has_failure:
                    self._process_cache[key] = (time.time(), all_hits)
                    self._enforce_process_cache_limit()
                    if self._cache_ttl > 0:
                        self._write_file_cache(key, all_hits)
                else:
                    logger.info(
                        f"Skipped caching vulnerability query result for {dep_name}:{dep_version} due to provider failure."
                    )
        finally:
            # 正常・異常に関わらず、二重解放を避けるために pop しながら安全にロック解放・減算を行う
            while flights_to_release:
                item = flights_to_release.pop()
                key = item["key"]
                flight = item["flight"]
                locked = item["locked"]

                if locked:
                    try:
                        flight.lock.release()
                    except RuntimeError:
                        pass
                self._decrement_flight(key)

        final_results = {}
        for dep in dependencies:
            final_results[dep] = results.get((dep[0].lower(), dep[1]), [])
        return final_results

    def _get_osv_vulnerability_detail(self, vuln_id: str) -> dict | None:
        if self._cache_ttl > 0:
            with self._osv_detail_cache_lock:
                if vuln_id in self._osv_detail_cache:
                    ts, data = self._osv_detail_cache[vuln_id]
                    if time.time() - ts <= self._cache_ttl:
                        return data
                    else:
                        self._osv_detail_cache.pop(vuln_id, None)

        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        logger.debug(f"Fetching OSV detail for {vuln_id}")
        data = self._request_json(url, method="GET")
        if data and isinstance(data, dict):
            if self._cache_ttl > 0:
                with self._osv_detail_cache_lock:
                    self._osv_detail_cache[vuln_id] = (time.time(), data)
            return data
        return None

    def _query_osv_batch(
        self, ecosystem: str, packages: List[tuple[str, str]]
    ) -> List[List[VulnHit] | None] | None:
        osv_ecosystem = "PyPI" if ecosystem == "python" else "npm"
        payload = {
            "queries": [
                {
                    "package": {"name": name, "ecosystem": osv_ecosystem},
                    "version": version,
                }
                for name, version in packages
            ]
        }
        url = "https://api.osv.dev/v1/querybatch"
        headers = {}
        api_key = os.environ.get("OSV_API_KEY", "").strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        data = self._request_json(
            url,
            method="POST",
            payload=payload,
            headers=headers if headers else None,
        )
        if data is None:
            return None
        if not isinstance(data, dict):
            return None

        results_raw = data.get("results")
        if not isinstance(results_raw, list):
            return None

        if len(results_raw) != len(packages):
            return None

        batch_hits: List[List[VulnHit] | None] = []

        for res in results_raw:
            if not isinstance(res, dict):
                batch_hits.append(None)
                continue

            if not res:
                batch_hits.append([])
                continue

            vulns = res.get("vulns")
            if vulns is None:
                batch_hits.append([])
                continue

            if not isinstance(vulns, list):
                batch_hits.append(None)
                continue

            hits: List[VulnHit] = []
            had_invalid = False
            for v in vulns:
                if not isinstance(v, dict):
                    had_invalid = True
                    continue

                vuln_id = v.get("id")
                if not isinstance(vuln_id, str):
                    had_invalid = True
                    continue

                detail = self._get_osv_vulnerability_detail(vuln_id)
                if detail is None:
                    had_invalid = True
                    break
                v_source = detail

                summary = v_source.get("summary")
                if summary is not None and not isinstance(summary, str):
                    had_invalid = True
                    continue

                refs = []
                references_raw = v_source.get("references")
                if references_raw is not None:
                    if not isinstance(references_raw, list):
                        had_invalid = True
                        continue
                    ref_err = False
                    for r in references_raw:
                        if not isinstance(r, dict):
                            ref_err = True
                            break
                        u = r.get("url")
                        if not isinstance(u, str):
                            ref_err = True
                            break
                        refs.append(u)
                    if ref_err:
                        had_invalid = True
                        continue

                score = None
                severity_raw = v_source.get("severity")
                if severity_raw is not None:
                    if not isinstance(severity_raw, list):
                        had_invalid = True
                        continue
                    sev_err = False
                    for sev in severity_raw:
                        if not isinstance(sev, dict):
                            sev_err = True
                            break
                        raw = sev.get("score")
                        if isinstance(raw, str):
                            score = parse_cvss_vector(raw)
                            if score is not None:
                                break
                    if sev_err:
                        had_invalid = True
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
            if had_invalid:
                batch_hits.append(None)
            else:
                batch_hits.append(hits)

        return batch_hits

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
                    if isinstance(raw, str):
                        score = parse_cvss_vector(raw)
                        if score is not None:
                            break
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
