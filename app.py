from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import streamlit as st

from src.mvp_models import Category, OverallResult, OverallStatus
from src.orchestrator import MVPOrchestrator

logger = logging.getLogger(__name__)

# 固定された公式 SHA-256 チェックサムテーブル (P1 レビュー対応)
CHECKSUMS = {
    "trivy": {
        "x86_64": (
            "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
            "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz",
        ),
        "arm64": (
            "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5",
            "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz",
        ),
    },
    "scorecard": {
        "x86_64": (
            "53aa07786f2d985d0755ff9caad4e38c0a22596708de0728c5274f84ae48f785",
            "https://github.com/ossf/scorecard/releases/download/v4.13.1/scorecard_4.13.1_linux_amd64.tar.gz",
        ),
        "arm64": (
            "d59d75eec0e91abbe65365b866fd0f298ddb9f4bcdda207a7f650720015d0f4f",
            "https://github.com/ossf/scorecard/releases/download/v4.13.1/scorecard_4.13.1_linux_arm64.tar.gz",
        ),
    },
}

# 展開後実行バイナリ用の SHA-256 チェックサムテーブル (P2 レビュー対応)
BINARY_CHECKSUMS = {
    "trivy": {
        "x86_64": "d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791",
        "arm64": "fed2c9ca7d27191ada34524b5eaf5216a845c6d6f3246143c3b475552ffe5358",
    },
    "scorecard": {
        "x86_64": "b890538c491ff9bf80707781589b6209792dcaf48a7162c77f32fe5914c2e4d4",
        "arm64": "2042d85a26e1d0f868cb2578b48fccd8cd20c3630e6a7c5779d99bb3809f6867",
    },
}


def project_root() -> Path:
    return Path(__file__).resolve().parent


def _download_binary_safely(
    url: str, max_bytes: int = 100 * 1024 * 1024, timeout: float = 10.0
) -> bytes:
    """URL からバイナリを safe にストリーミングダウンロード (最大サイズ制限・全体絶対タイムアウト付)。"""
    start_time = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "OSS-Risk-Check-Agent"})
    buffer = bytearray()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        while True:
            elapsed = time.monotonic() - start_time
            remaining = timeout - elapsed
            if remaining <= 0:
                raise TimeoutError(
                    f"Downloaded binary streaming exceeded overall time limit ({timeout} seconds)"
                )
            if (
                hasattr(resp, "fp")
                and hasattr(resp.fp, "raw")
                and hasattr(resp.fp.raw, "_sock")
                and resp.fp.raw._sock
            ):
                # ソケットタイムアウトを最小 1 秒 (または remaining) に制限し、ブロッキング read 中も単調時計の期限を動的再確認
                resp.fp.raw._sock.settimeout(max(0.001, min(remaining, 1.0)))

            try:
                if hasattr(resp, "read1"):
                    chunk = resp.read1(8 * 1024)
                elif hasattr(resp, "fp") and hasattr(resp.fp, "read1"):
                    chunk = resp.fp.read1(8 * 1024)
                else:
                    chunk = resp.read(8 * 1024)
            except (TimeoutError, OSError, urllib.error.URLError) as err:
                if time.monotonic() - start_time >= timeout:
                    raise TimeoutError(
                        f"Downloaded binary streaming exceeded overall time limit ({timeout} seconds)"
                    ) from err
                continue

            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > max_bytes:
                raise ValueError(
                    f"Downloaded binary exceeds maximum allowed size ({max_bytes} bytes)"
                )
    return bytes(buffer)


class ScannerBinaryState:
    """Streamlit rerun を超えてプロセス永続保持されるスキャナー状態コンテナ。"""

    def __init__(self) -> None:
        self.secure_tmp_dir: Path | None = None
        self.integrity_cache: dict[str, tuple[float, int, bool]] = {}
        self.failure_cache: dict[str, float] = {}


@st.cache_resource(show_spinner=False)
def _get_scanner_binary_state() -> ScannerBinaryState:
    return ScannerBinaryState()


def _is_secure_directory(dir_path: Path) -> bool:
    """ディレクトリおよび各親階層の所有者 (getuid)、パーミッション (0o700/非 group-world-writable)、非シンボリックリンク性を検証する (P2 レビュー対応)。"""
    try:
        if not hasattr(os, "getuid"):
            return True
        uid = os.getuid()

        # 未 resolve のパスに対してシンボリックリンク性を事前検証
        if dir_path.is_symlink() or os.path.islink(dir_path):
            return False

        try:
            dir_path.chmod(0o700)
        except Exception:
            pass

        st_info = dir_path.stat()
        if st_info.st_uid != uid or (st_info.st_mode & 0o077 != 0):
            return False

        # ホームディレクトリまたはルートに至る祖先階層を未 resolve パスで走査し検証
        home = Path.home()
        home_resolved = home.resolve()
        curr = dir_path
        while True:
            parent = curr.parent
            if parent == curr:
                break
            if parent.exists():
                if parent.is_symlink() or os.path.islink(parent):
                    return False
                p_st = parent.lstat()
                # 所有者が一致し、かつ group/world writable (0o022) でないことを確認
                if p_st.st_uid != uid or (p_st.st_mode & 0o022 != 0):
                    return False
            if parent == home or parent == home_resolved:
                break
            curr = parent

        return True
    except Exception:
        return False


def _get_user_bin_dir() -> Path:
    """ユーザー固有の安全なバイナリ保存ディレクトリを取得・作成する (P2 レビュー対応)。"""
    if os.name == "nt":
        bin_dir = project_root() / ".bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        return bin_dir

    state = _get_scanner_binary_state()
    base_dir = Path.home() / ".cache" / "oss_security_agent" / "bin"
    try:
        base_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        if _is_secure_directory(base_dir):
            return base_dir
    except Exception as e:
        logger.warning(
            f"Failed to use home bin directory ({e}). Falling back to secure random temp directory."
        )

    if state.secure_tmp_dir is None or not state.secure_tmp_dir.exists():
        state.secure_tmp_dir = Path(tempfile.mkdtemp(prefix="oss_agent_bin_"))
    return state.secure_tmp_dir


def _verify_binary_integrity(tool_name: str, arch_key: str | None) -> bool:
    """bin_dir 内に存在する展開済みバイナリのチェックサム検証を行う。mtime/size によるインメモリキャッシュと 1MB ストリーミング計算で高速化 (P2 レビュー対応)。"""
    state = _get_scanner_binary_state()
    bin_dir = _get_user_bin_dir()
    bin_file = bin_dir / tool_name
    if not bin_file.exists():
        return False
    try:
        st_info = bin_file.stat()
        mtime, size = st_info.st_mtime, st_info.st_size
    except Exception:
        return False

    cache_key = str(bin_file)
    if cache_key in state.integrity_cache:
        cached_mtime, cached_size, cached_valid = state.integrity_cache[cache_key]
        if cached_mtime == mtime and cached_size == size:
            return cached_valid

    if (
        not arch_key
        or tool_name not in BINARY_CHECKSUMS
        or arch_key not in BINARY_CHECKSUMS[tool_name]
    ):
        is_valid = bin_file.is_file()
        state.integrity_cache[cache_key] = (mtime, size, is_valid)
        return is_valid

    expected_sha256 = BINARY_CHECKSUMS[tool_name][arch_key]
    try:
        h = hashlib.sha256()
        with bin_file.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        actual_sha256 = h.hexdigest().lower()
        if actual_sha256 == expected_sha256.lower():
            state.integrity_cache[cache_key] = (mtime, size, True)
            return True

        logger.warning(
            f"Existing {tool_name} binary checksum mismatch! Expected: {expected_sha256}, Got: {actual_sha256}. Removing unverified binary."
        )
        state.integrity_cache.pop(cache_key, None)
        bin_file.unlink(missing_ok=True)
        return False
    except Exception as e:
        logger.warning(f"Failed to verify integrity for {tool_name}: {e}")
        state.integrity_cache.pop(cache_key, None)
        bin_file.unlink(missing_ok=True)
        return False


def _check_binaries_present() -> dict[str, bool]:
    """現在 PATH に存在するバイナリ状態を確認し、専用ディレクトリ由来のファイルは完全性を検証する (P2 レビュー対応)。"""
    bin_dir = _get_user_bin_dir()
    path_env = os.environ.get("PATH", "")
    if str(bin_dir) not in path_env:
        os.environ["PATH"] = f"{bin_dir}{os.path.pathsep}" + path_env

    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64", "x64"):
        arch_key = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch_key = "arm64"
    else:
        arch_key = None

    if arch_key:
        _verify_binary_integrity("trivy", arch_key)
        _verify_binary_integrity("scorecard", arch_key)

    return {
        "trivy": shutil.which("trivy") is not None,
        "scorecard": shutil.which("scorecard") is not None,
    }


def _install_scanner_binaries() -> dict[str, bool]:
    """trivy および scorecard バイナリを安全取得 (ユーザー専用パス・SHA-256検証・タイムアウト) する。"""
    bin_dir = _get_user_bin_dir()

    path_env = os.environ.get("PATH", "")
    if str(bin_dir) not in path_env:
        os.environ["PATH"] = f"{bin_dir}{os.path.pathsep}" + path_env

    system_os = platform.system()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64", "x64"):
        arch_key = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch_key = "arm64"
    else:
        arch_key = None

    if arch_key:
        _verify_binary_integrity("trivy", arch_key)
        _verify_binary_integrity("scorecard", arch_key)

    trivy_path = shutil.which("trivy")
    scorecard_path = shutil.which("scorecard")

    if system_os == "Linux" and arch_key:
        try:
            bin_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        except Exception as e:
            logger.warning(f"Failed to create bin_dir {bin_dir}: {e}")
            return _check_binaries_present()

        # 1. Trivy 安全取得
        if not trivy_path and arch_key in CHECKSUMS["trivy"]:
            expected_sha256, download_url = CHECKSUMS["trivy"][arch_key]
            archive_file = bin_dir / "trivy.tar.gz"
            try:
                logger.info(
                    f"Downloading Trivy binary ({arch_key}) with 10s timeout..."
                )
                data = _download_binary_safely(download_url)

                actual_sha256 = hashlib.sha256(data).hexdigest().lower()
                if actual_sha256 != expected_sha256.lower():
                    logger.error(
                        f"Trivy checksum mismatch! Expected: {expected_sha256}, Got: {actual_sha256}"
                    )
                else:
                    archive_file.write_bytes(data)
                    with tarfile.open(archive_file, "r:gz") as tar:
                        tar.extract("trivy", path=bin_dir)
                    (bin_dir / "trivy").chmod(0o755)
                    trivy_path = str(bin_dir / "trivy")
            except Exception as e:
                logger.warning(f"Failed safe download for Trivy: {e}")
            finally:
                archive_file.unlink(missing_ok=True)

        # 2. Scorecard 安全取得
        if not scorecard_path and arch_key in CHECKSUMS["scorecard"]:
            setup_script = project_root() / "setup.sh"
            if setup_script.is_file():
                try:
                    logger.info("Executing setup.sh for Scorecard pre-installation...")
                    import subprocess

                    res = subprocess.run(
                        ["bash", str(setup_script)],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    if res.returncode == 0:
                        logger.info("setup.sh completed successfully.")
                        scorecard_path = shutil.which("scorecard")
                    else:
                        err_msg = res.stderr.strip() if res.stderr else "Unknown error"
                        logger.warning(
                            f"setup.sh failed with exit code {res.returncode}: {err_msg}"
                        )
                except Exception as e:
                    logger.warning(f"Execution of setup.sh failed with exception: {e}")

        if not scorecard_path and arch_key in CHECKSUMS["scorecard"]:
            expected_sha256, download_url = CHECKSUMS["scorecard"][arch_key]
            archive_file = bin_dir / "scorecard.tar.gz"
            try:
                logger.info(
                    f"Downloading Scorecard binary ({arch_key}) with 10s timeout..."
                )
                data = _download_binary_safely(download_url)

                actual_sha256 = hashlib.sha256(data).hexdigest().lower()
                if actual_sha256 != expected_sha256.lower():
                    logger.error(
                        f"Scorecard checksum mismatch! Expected: {expected_sha256}, Got: {actual_sha256}"
                    )
                else:
                    archive_file.write_bytes(data)
                    with tarfile.open(archive_file, "r:gz") as tar:
                        for member in tar.getmembers():
                            if member.name.endswith("scorecard"):
                                member.name = "scorecard"
                                tar.extract(member, path=bin_dir)
                                break
                    (bin_dir / "scorecard").chmod(0o755)
                    scorecard_path = str(bin_dir / "scorecard")
            except Exception as e:
                logger.warning(f"Failed safe download for Scorecard: {e}")
            finally:
                archive_file.unlink(missing_ok=True)

    return _check_binaries_present()


@st.cache_resource(show_spinner=False)
def _ensure_scanner_binaries_cached() -> dict[str, bool]:
    """バイナリ取得を実行し、成功時のみ @st.cache_resource で永続キャッシュする。"""
    res = _install_scanner_binaries()
    if not res.get("trivy") or not res.get("scorecard"):
        raise RuntimeError(f"Scanner binary setup incomplete: {res}")
    return res


def ensure_scanner_binaries() -> dict[str, bool]:
    """trivy および scorecard バイナリを安全取得する。失敗時も短い TTL キャッシュで連続通信ブロックを防止する (P2 レビュー対応)。"""
    state = _get_scanner_binary_state()
    res = _check_binaries_present()
    if res["trivy"] and res["scorecard"]:
        return res

    now = time.monotonic()
    last_fail = state.failure_cache.get("binary_setup_failed", 0.0)
    if now - last_fail < 60.0:
        return res

    try:
        _ensure_scanner_binaries_cached()
        current_res = _check_binaries_present()
        if not (current_res["trivy"] and current_res["scorecard"]):
            _ensure_scanner_binaries_cached.clear()
            current_res = _install_scanner_binaries()
        return current_res
    except Exception as e:
        logger.warning(f"Scanner binary preparation failed or skipped: {e}")
        state.failure_cache["binary_setup_failed"] = time.monotonic()
        return _check_binaries_present()


def sanitize_code_span(text: str | None) -> str:
    """Markdown コード区間 (``) 内で安全に使用するため、バッククォートと改行・制御文字のみを無害化する (P2 レビュー対応)。"""
    if not text:
        return ""
    s = str(text)
    return (
        s.replace("`", "'").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    )


def escape_markdown(text: str | None) -> str:
    """Markdown 記号・生HTML (<, >)・改行文字を安全エスケープする (P2 レビュー対応)。"""
    if not text:
        return ""
    s = str(text)
    # 生 HTML の無害化
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Markdown 記号のエスケープ
    replacements = [
        ("\\", "\\\\"),
        ("`", "'"),
        ("*", "\\*"),
        ("_", "\\_"),
        ("{", "\\{"),
        ("}", "\\}"),
        ("[", "\\["),
        ("]", "\\]"),
        ("(", "\\("),
        (")", "\\)"),
        ("#", "\\#"),
        ("+", "\\+"),
        ("-", "\\-"),
        (".", "\\."),
        ("!", "\\!"),
        ("|", "\\|"),
        ("~", "\\~"),
    ]
    for orig, repl in replacements:
        s = s.replace(orig, repl)
    return s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def generate_markdown_report(result: OverallResult) -> str:
    """OverallResult からスキップ情報を含む完全な Markdown レポートを生成する (P2 レビュー対応)。"""
    lines = [
        "# 🛡️ OSS セキュリティリスク診断レポート",
        "",
        "## 1. 診断概要",
        "",
        f"- **対象リポジトリ:** {escape_markdown(result.repository_url)}",
        f"- **最終診断日時:** {escape_markdown(result.scanned_at)}",
    ]

    if result.scanned_ref:
        lines.append(f"- **対象ブランチ/タグ:** {escape_markdown(result.scanned_ref)}")
    if result.scanned_subdir:
        lines.append(
            f"- **対象サブディレクトリ:** {escape_markdown(result.scanned_subdir)}"
        )

    status_text = (
        result.status.value if hasattr(result.status, "value") else str(result.status)
    )
    lines.extend(
        [
            f"- **総合セキュリティスコア:** {result.overall_score:.1f} / 10.0",
            f"- **総合判定:** {escape_markdown(status_text)}",
            f"- **判定理由:** {escape_markdown(result.status_reason) or 'なし'}",
            "",
        ]
    )

    # スキップされたファイルのセクションを追加 (P2 レビュー対応)
    if result.skipped_files:
        tot_count = (
            result.total_skipped_files_count
            if getattr(result, "total_skipped_files_count", None)
            else len(result.skipped_files)
        )
        count_label = (
            f"全 {tot_count} 件中 {len(result.skipped_files)} 件表示"
            if tot_count > len(result.skipped_files)
            else f"{len(result.skipped_files)} 件"
        )
        lines.extend(
            [
                "---",
                "",
                f"## スキップされたファイル ({count_label})",
                "",
                "安全上限（ファイルサイズ・ファイル数）を超えたため、以下のファイルがスキャン対象から除外されました。",
                "",
                "| ファイルパス | 除外理由 | ファイルサイズ | 上限値 |",
                "| :--- | :--- | :---: | :---: |",
            ]
        )
        for sk in result.skipped_files:
            p_str = escape_markdown(sk.path)
            r_str = escape_markdown(sk.reason)
            sz_str = f"{sk.size_bytes:,} bytes" if sk.size_bytes is not None else "-"
            lm_str = f"{sk.limit_bytes:,} bytes" if sk.limit_bytes is not None else "-"
            lines.append(f"| {p_str} | {r_str} | {sz_str} | {lm_str} |")
        lines.append("")

    # 外部スキャナー実行エラー・制限詳細セクションをレポートに追加 (P2 レビュー対応)
    scanner_st = getattr(result, "scanner_status", {}) or {}
    trivy_err = scanner_st.get("trivy_failure_reason")
    scorecard_err = scanner_st.get("scorecard_failure_reason")
    snapshot_err = scanner_st.get("snapshot_failed_reason")

    if trivy_err or scorecard_err or snapshot_err:
        lines.extend(
            [
                "---",
                "",
                "## 外部スキャナー実行エラー・制限詳細",
                "",
                "一部のスキャナーまたは snapshot 取得処理で以下のエラー・制限が発生しました。",
                "",
            ]
        )
        if snapshot_err:
            lines.append(
                f"- **Snapshot Fetcher エラー**: {escape_markdown(str(snapshot_err))}"
            )
        if trivy_err:
            lines.append(
                f"- **Trivy スキャナーエラー/スキップ**: {escape_markdown(str(trivy_err))}"
            )
        if scorecard_err:
            lines.append(
                f"- **Scorecard スキャナーエラー/スキップ**: {escape_markdown(str(scorecard_err))}"
            )
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## 2. 評価カテゴリ別スコア (8観点)",
            "",
            "| カテゴリ | スコア | 評価状態 | 指摘数 | 概要 |",
            "| :--- | :---: | :---: | :---: | :--- |",
        ]
    )

    category_order = [
        Category.KNOWN_VULNERABILITIES.value,
        Category.SECRETS.value,
        Category.MISCONFIGURATION.value,
        Category.DEPENDENCIES.value,
        Category.DEVELOPMENT.value,
        Category.CICD.value,
        Category.MAINTENANCE.value,
        Category.SOURCE_CODE.value,
    ]

    for key in category_order:
        cat_data = result.categories.get(key)
        if cat_data:
            c_name = escape_markdown(cat_data.category_name)
            c_score = f"{cat_data.score:.1f}" if cat_data.evaluated else "N/A"
            c_eval = "評価済み" if cat_data.evaluated else "未評価"
            c_count = cat_data.findings_count
            c_summary = escape_markdown(cat_data.summary)
        else:
            c_name = escape_markdown(key)
            c_score = "N/A"
            c_eval = "未評価"
            c_count = 0
            c_summary = "未評価"
        lines.append(f"| {c_name} | {c_score} | {c_eval} | {c_count} | {c_summary} |")

    lines.extend(
        [
            "",
            "---",
            "",
            f"## 3. 指摘事項一覧 (Findings: 全 {len(result.all_findings)} 件)",
            "",
        ]
    )

    if not result.all_findings:
        lines.append("指摘事項はありません。")
    else:
        SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            result.all_findings,
            key=lambda f: SEVERITY_ORDER.get((f.severity or "INFO").upper(), 5),
        )

        for idx, f in enumerate(sorted_findings, 1):
            sev = escape_markdown((f.severity or "INFO").upper())
            cat_name = escape_markdown(
                f.category.value if hasattr(f.category, "value") else str(f.category)
            )
            title = escape_markdown(f.title)
            rule_id = sanitize_code_span(f.rule_id)
            source = escape_markdown(f.source)
            lines.append(f"### {idx}. [{sev}] {title}")
            lines.append(f"- **カテゴリ:** {cat_name}")
            lines.append(f"- **ルールID:** `{rule_id}` (Source: {source})")
            if f.target:
                target_loc = sanitize_code_span(f.target)
                if f.location:
                    target_loc += f" ({sanitize_code_span(f.location)})"
                lines.append(f"- **対象:** `{target_loc}`")
            if f.description:
                lines.append(f"- **説明:** {escape_markdown(f.description)}")
            if f.remediation:
                lines.append(f"- **対策案内:** {escape_markdown(f.remediation)}")
            lines.append("")

    return "\n".join(lines)


def inject_custom_theme() -> None:
    """GitHub Pages 版のモダン・サクラチェッカー風 CSS スタイルをインジェクトする。"""
    st.markdown(
        """
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Noto+Sans+JP:wght@400;500;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

            :root {
                --font-main: 'Inter', 'Noto Sans JP', sans-serif;
                --font-mono: 'JetBrains Mono', monospace;
                --bg-primary: #0b0f19;
                --bg-card: rgba(18, 24, 38, 0.85);
                --bg-card-hover: rgba(26, 35, 54, 0.95);
                --border-color: rgba(255, 255, 255, 0.1);
                --text-main: #f3f4f6;
                --text-muted: #9ca3af;
                --text-dim: #6b7280;
                --color-safe: #10b981;
                --color-safe-bg: rgba(16, 185, 129, 0.15);
                --color-safe-border: rgba(16, 185, 129, 0.4);
                --color-moderate: #f59e0b;
                --color-moderate-bg: rgba(245, 158, 11, 0.15);
                --color-moderate-border: rgba(245, 158, 11, 0.4);
                --color-danger: #ef4444;
                --color-danger-bg: rgba(239, 68, 68, 0.15);
                --color-danger-border: rgba(239, 68, 68, 0.4);
                --sev-critical: #dc2626;
                --sev-high: #ea580c;
                --sev-medium: #d97706;
                --sev-low: #2563eb;
                --sev-info: #4b5563;
            }

            .block-container {
                padding-top: 1.5rem;
                padding-bottom: 3rem;
                max-width: 1160px;
            }

            /* ヒーローカード (サクラチェッカー風) */
            .hero-card-custom {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 30px 36px;
                box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.5);
                margin-bottom: 30px;
            }

            .repo-info-header {
                border-bottom: 1px solid var(--border-color);
                padding-bottom: 16px;
                margin-bottom: 24px;
            }

            .label-muted {
                font-size: 0.8rem;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: var(--text-dim);
            }

            .repo-title {
                font-size: 1.65rem;
                font-weight: 800;
                color: #ffffff;
                word-break: break-all;
                margin: 4px 0 6px;
            }

            .scanned-time {
                font-size: 0.85rem;
                color: var(--text-muted);
            }

            .overall-grid {
                display: grid;
                grid-template-columns: 220px 1fr;
                gap: 36px;
                align-items: center;
            }

            .score-box {
                display: flex;
                flex-direction: column;
                align-items: center;
                text-align: center;
            }

            .score-circle-wrapper {
                position: relative;
                width: 150px;
                height: 150px;
            }

            .score-circle-svg {
                width: 150px;
                height: 150px;
                transform: rotate(-90deg);
            }

            .circle-bg {
                fill: none;
                stroke: rgba(255, 255, 255, 0.08);
                stroke-width: 12;
            }

            .circle-progress {
                fill: none;
                stroke-width: 12;
                stroke-linecap: round;
                transition: stroke-dashoffset 1s ease-out, stroke 0.4s ease;
            }

            .score-circle-text {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                display: flex;
                flex-direction: column;
                align-items: center;
                line-height: 1;
            }

            .score-val {
                font-size: 2.3rem;
                font-weight: 800;
                color: #ffffff;
            }

            .score-max {
                font-size: 0.82rem;
                color: var(--text-muted);
                margin-top: 4px;
            }

            .score-label {
                font-weight: 700;
                font-size: 0.88rem;
                color: var(--text-muted);
                margin-top: 12px;
            }

            /* ステータスバッジ */
            .status-box {
                display: flex;
                flex-direction: column;
                justify-content: center;
            }

            .status-badge {
                display: inline-block;
                font-size: 1.3rem;
                font-weight: 800;
                padding: 6px 20px;
                border-radius: 999px;
                letter-spacing: 0.02em;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
            }

            .status-safe {
                background: var(--color-safe-bg);
                color: var(--color-safe);
                border: 2px solid var(--color-safe-border);
            }

            .status-moderate {
                background: var(--color-moderate-bg);
                color: var(--color-moderate);
                border: 2px solid var(--color-moderate-border);
            }

            .status-dangerous {
                background: var(--color-danger-bg);
                color: var(--color-danger);
                border: 2px solid var(--color-danger-border);
            }

            .status-unknown {
                background: rgba(255, 255, 255, 0.05);
                color: var(--text-muted);
                border: 2px solid var(--border-color);
            }

            .status-reason-text {
                font-size: 1rem;
                color: #e5e7eb;
                line-height: 1.6;
                margin: 12px 0 16px;
            }

            .risk-legend {
                display: flex;
                gap: 16px;
                font-size: 0.8rem;
                color: var(--text-muted);
                background: rgba(0, 0, 0, 0.2);
                padding: 8px 14px;
                border-radius: 8px;
                border: 1px solid var(--border-color);
                width: fit-content;
            }

            .legend-item {
                display: flex;
                align-items: center;
                gap: 6px;
            }

            .dot {
                width: 8px;
                height: 8px;
                border-radius: 50%;
            }
            .dot.safe { background: var(--color-safe); }
            .dot.moderate { background: var(--color-moderate); }
            .dot.dangerous { background: var(--color-danger); }

            /* 8カテゴリカード */
            .categories-grid-custom {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                gap: 16px;
                margin-bottom: 30px;
            }

            .category-card-custom {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 14px;
                padding: 18px;
            }

            .cat-header-custom {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 10px;
            }

            .cat-title-custom {
                font-weight: 700;
                font-size: 0.95rem;
                color: #f3f4f6;
            }

            .cat-score-badge-custom {
                font-weight: 800;
                font-size: 1.05rem;
                padding: 2px 8px;
                border-radius: 6px;
                font-family: var(--font-mono);
            }

            .cat-progress-bg-custom {
                width: 100%;
                height: 7px;
                background: rgba(255, 255, 255, 0.08);
                border-radius: 999px;
                overflow: hidden;
                margin-bottom: 10px;
            }

            .cat-progress-bar-custom {
                height: 100%;
                border-radius: 999px;
            }

            .cat-footer-custom {
                display: flex;
                justify-content: space-between;
                font-size: 0.78rem;
                color: var(--text-muted);
            }

            .findings-count-tag-custom {
                background: rgba(255, 255, 255, 0.06);
                padding: 2px 6px;
                border-radius: 4px;
            }

            /* Finding カード */
            .finding-card-custom {
                background: rgba(15, 23, 42, 0.7);
                border: 1px solid var(--border-color);
                border-left: 4px solid var(--sev-info);
                border-radius: 8px;
                padding: 16px 20px;
                margin-bottom: 12px;
            }
            .finding-card-custom.CRITICAL { border-left-color: var(--sev-critical); }
            .finding-card-custom.HIGH { border-left-color: var(--sev-high); }
            .finding-card-custom.MEDIUM { border-left-color: var(--sev-medium); }
            .finding-card-custom.LOW { border-left-color: var(--sev-low); }

            .finding-meta-custom {
                display: flex;
                gap: 8px;
                align-items: center;
                margin-bottom: 6px;
                flex-wrap: wrap;
            }

            .sev-tag-custom {
                font-weight: 800;
                font-size: 0.72rem;
                padding: 2px 7px;
                border-radius: 4px;
                color: #ffffff;
                font-family: var(--font-mono);
            }
            .sev-tag-custom.CRITICAL { background: var(--sev-critical); }
            .sev-tag-custom.HIGH { background: var(--sev-high); }
            .sev-tag-custom.MEDIUM { background: var(--sev-medium); }
            .sev-tag-custom.LOW { background: var(--sev-low); }
            .sev-tag-custom.INFO { background: var(--sev-info); }

            .cat-pill-custom {
                font-size: 0.72rem;
                background: rgba(255, 255, 255, 0.08);
                color: var(--text-muted);
                padding: 2px 7px;
                border-radius: 4px;
            }

            .rule-id-custom {
                font-family: var(--font-mono);
                font-size: 0.78rem;
                color: #93c5fd;
            }

            .finding-title-custom {
                font-size: 1rem;
                font-weight: 700;
                color: #ffffff;
                margin-bottom: 4px;
            }

            .finding-desc-custom {
                font-size: 0.88rem;
                color: #d1d5db;
                line-height: 1.5;
                margin-bottom: 6px;
            }

            .finding-target-custom {
                font-family: var(--font-mono);
                font-size: 0.8rem;
                color: #a7f3d0;
                background: rgba(6, 78, 59, 0.3);
                padding: 3px 8px;
                border-radius: 4px;
                display: inline-block;
                margin-bottom: 6px;
            }

            .finding-remediation-custom {
                font-size: 0.82rem;
                color: #9cd37b;
                background: rgba(20, 83, 45, 0.2);
                border-left: 3px solid #22c55e;
                padding: 6px 10px;
                border-radius: 0 4px 4px 0;
                margin-top: 6px;
            }

            @media (max-width: 768px) {
                .overall-grid {
                    grid-template-columns: 1fr;
                    gap: 20px;
                }
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


@dataclass(frozen=True)
class WebScanOptions:
    """Streamlit フォームから受け取るスキャンオプション。"""

    target_url: str | None = None
    target_ref: str | None = None
    target_subdir: str | None = None
    output_dir: str | None = None
    mvp: bool = True


def normalize_optional(value: str | None) -> str | None:
    if not value:
        return None
    stripped = value.strip()
    return stripped or None


def escape_html(text: str | None) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def render_hero_score(result: OverallResult) -> None:
    """サクラチェッカー風の総合スコア＆ステータスカードを描画する。"""
    score = float(result.overall_score)
    status_text = (
        result.status.value if hasattr(result.status, "value") else str(result.status)
    )
    status_reason = escape_html(result.status_reason)

    if status_text in ("安全", "SAFE"):
        color = "var(--color-safe)"
        badge_class = "status-safe"
    elif status_text in ("普通", "MODERATE"):
        color = "var(--color-moderate)"
        badge_class = "status-moderate"
    elif status_text in ("危険", "DANGEROUS"):
        color = "var(--color-danger)"
        badge_class = "status-dangerous"
    else:
        color = "var(--text-dim)"
        badge_class = "status-unknown"

    circumference = 410
    offset = circumference - (score / 10.0) * circumference

    target_disp = escape_html(result.repository_url)
    extra_meta = []
    if result.scanned_ref:
        extra_meta.append(f"ref: {escape_html(result.scanned_ref)}")
    if result.scanned_subdir:
        extra_meta.append(f"subdir: {escape_html(result.scanned_subdir)}")
    if extra_meta:
        target_disp += f" ({', '.join(extra_meta)})"

    st.markdown(
        f"""
        <div class="hero-card-custom">
            <div class="repo-info-header">
                <span class="label-muted">Target Repository</span>
                <div class="repo-title">{target_disp}</div>
                <div class="scanned-time">最終診断日時: {escape_html(result.scanned_at)}</div>
            </div>
            <div class="overall-grid">
                <div class="score-box">
                    <div class="score-circle-wrapper">
                        <svg class="score-circle-svg" viewBox="0 0 150 150">
                            <circle class="circle-bg" cx="75" cy="75" r="65"></circle>
                            <circle class="circle-progress" cx="75" cy="75" r="65"
                                    stroke="{color}"
                                    stroke-dasharray="{circumference}"
                                    stroke-dashoffset="{offset}"></circle>
                        </svg>
                        <div class="score-circle-text">
                            <span class="score-val">{score:.1f}</span>
                            <span class="score-max">/ 10.0</span>
                        </div>
                    </div>
                    <div class="score-label">総合セキュリティスコア</div>
                </div>
                <div class="status-box">
                    <div>
                        <span class="status-badge {badge_class}">{escape_html(status_text)}</span>
                    </div>
                    <p class="status-reason-text">{status_reason}</p>
                    <div class="risk-legend">
                        <span class="legend-item"><span class="dot safe"></span> 良好 (7.5 - 10.0)</span>
                        <span class="legend-item"><span class="dot moderate"></span> 注意・普通 (5.0 - 7.4)</span>
                        <span class="legend-item"><span class="dot dangerous"></span> 危険 (0.0 - 4.9)</span>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Markdown レポートのダウンロードボタン (P2 レビュー対応)
    md_content = generate_markdown_report(result)
    file_timestamp = (
        result.scanned_at.replace(":", "-").replace(" ", "_").replace("/", "-")
    )
    st.download_button(
        label="📥 Markdown レポートをダウンロード",
        data=md_content,
        file_name=f"security_report_{file_timestamp}.md",
        mime="text/markdown",
        use_container_width=True,
    )


def render_skipped_files_alert(result: OverallResult) -> None:
    """サイズ上限等によりスキップされたファイルの詳細一覧を表示する (P2 レビュー対応)。"""
    if not result.skipped_files:
        return

    tot_count = (
        result.total_skipped_files_count
        if getattr(result, "total_skipped_files_count", None)
        else len(result.skipped_files)
    )
    count_label = (
        f"全 {tot_count} 件中 {len(result.skipped_files)} 件を表示"
        if tot_count > len(result.skipped_files)
        else f"{len(result.skipped_files)} 件"
    )

    with st.expander(
        f"⚠️ 安全上限によりスキャン除外・スキップされたファイル ({count_label})"
    ):
        st.caption(
            "以下のファイルは設定されたサイズ上限・安全上限を超えたためスキャン対象から除外されました。"
        )
        table_data = []
        for sk in result.skipped_files:
            table_data.append(
                {
                    "ファイルパス": sk.path,
                    "除外理由": sk.reason,
                    "ファイルサイズ": (
                        f"{sk.size_bytes:,} bytes"
                        if sk.size_bytes is not None
                        else "不明"
                    ),
                    "上限値": (
                        f"{sk.limit_bytes:,} bytes"
                        if sk.limit_bytes is not None
                        else "不明"
                    ),
                }
            )
        st.dataframe(table_data, use_container_width=True)


def render_scanner_status_alert(result: OverallResult) -> None:
    """外部スキャナー (Trivy / Scorecard) の実行エラー理由・スキップ詳細を表示する (P2 レビュー対応)。"""
    scanner_st = getattr(result, "scanner_status", {}) or {}
    trivy_err = scanner_st.get("trivy_failure_reason")
    scorecard_err = scanner_st.get("scorecard_failure_reason")
    snapshot_err = scanner_st.get("snapshot_failed_reason")

    if not (trivy_err or scorecard_err or snapshot_err):
        return

    with st.expander("⚠️ 外部スキャナー実行エラー・制限詳細"):
        if snapshot_err:
            st.error(f"**Snapshot Fetcher エラー**: {escape_html(str(snapshot_err))}")
        if trivy_err:
            st.warning(
                f"**Trivy スキャナーエラー/スキップ**: {escape_html(str(trivy_err))}"
            )
        if scorecard_err:
            st.warning(
                f"**Scorecard スキャナーエラー/スキップ**: {escape_html(str(scorecard_err))}"
            )


def render_category_cards(result: OverallResult) -> None:
    """8カテゴリ別スコアカードを動的グリッド描画する。"""
    category_order = [
        Category.KNOWN_VULNERABILITIES.value,
        Category.SECRETS.value,
        Category.MISCONFIGURATION.value,
        Category.DEPENDENCIES.value,
        Category.DEVELOPMENT.value,
        Category.CICD.value,
        Category.MAINTENANCE.value,
        Category.SOURCE_CODE.value,
    ]

    cards_html = []
    for key in category_order:
        cat_data = result.categories.get(key)
        if cat_data:
            cat_name = escape_html(cat_data.category_name)
            score = float(cat_data.score)
            evaluated = cat_data.evaluated
            count = cat_data.findings_count
            summary = escape_html(cat_data.summary)
        else:
            cat_name = key
            score = 0.0
            evaluated = False
            count = 0
            summary = "未評価"

        score_text = f"{score:.1f}" if evaluated else "N/A"
        bar_width = (score * 10.0) if evaluated else 0

        if not evaluated:
            color = "var(--text-dim)"
            bg_score = "rgba(255, 255, 255, 0.05)"
        elif score < 5.0:
            color = "var(--color-danger)"
            bg_score = "var(--color-danger-bg)"
        elif score < 7.5:
            color = "var(--color-moderate)"
            bg_score = "var(--color-moderate-bg)"
        else:
            color = "var(--color-safe)"
            bg_score = "var(--color-safe-bg)"

        cards_html.append(
            f'<div class="category-card-custom">'
            f'<div class="cat-header-custom">'
            f'<div class="cat-title-custom">{cat_name}</div>'
            f'<div class="cat-score-badge-custom" style="color: {color}; background: {bg_score};">{score_text}</div>'
            f"</div>"
            f'<div class="cat-progress-bg-custom">'
            f'<div class="cat-progress-bar-custom" style="width: {bar_width}%; background: {color};"></div>'
            f"</div>"
            f'<div class="cat-footer-custom">'
            f"<span>{summary}</span>"
            f'<span class="findings-count-tag-custom">{count} 指摘</span>'
            f"</div>"
            f"</div>"
        )

    st.markdown("### 📊 評価カテゴリ別スコア (8観点)")
    st.caption("Trivy、OpenSSF Scorecard、コード固有ルールの診断結果を10点満点で可視化")
    st.markdown(
        f'<div class="categories-grid-custom">{"".join(cards_html)}</div>',
        unsafe_allow_html=True,
    )


def render_findings_summary(result: OverallResult) -> dict[str, int]:
    """検知総数と深刻度別件数の集計メトリクス & バーチャートを描画する (P2 レビュー対応)。"""
    findings = result.all_findings or []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.severity or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["INFO"] += 1

    st.markdown("### 📈 検知件数サマリ & 深刻度別分布")

    col_tot, col_crit, col_high, col_med, col_low, col_info = st.columns(6)
    with col_tot:
        st.metric("総検知数", f"{len(findings)} 件")
    with col_crit:
        st.metric("🚨 Critical", f"{counts['CRITICAL']} 件")
    with col_high:
        st.metric("⚠️ High", f"{counts['HIGH']} 件")
    with col_med:
        st.metric("⚡ Medium", f"{counts['MEDIUM']} 件")
    with col_low:
        st.metric("ℹ️ Low", f"{counts['LOW']} 件")
    with col_info:
        st.metric("💡 Info", f"{counts['INFO']} 件")

    if findings:
        st.caption("深刻度別件数グラフ")
        chart_data = {
            "深刻度": ["Critical", "High", "Medium", "Low", "Info"],
            "件数": [
                counts["CRITICAL"],
                counts["HIGH"],
                counts["MEDIUM"],
                counts["LOW"],
                counts["INFO"],
            ],
        }
        st.bar_chart(chart_data, x="深刻度", y="件数", color="#ea580c")

    return counts


def render_findings_list(
    result: OverallResult, selected_category: str, selected_severity: str
) -> None:
    """Finding (指摘事項) カード一覧をフィルタリング & 重要度順ソートの上描画する。"""
    st.markdown("### 🔍 発見されたリスク・指摘事項 (Findings)")

    allowed_sevs = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    findings = result.all_findings or []
    filtered = []
    for f in findings:
        cat_val = f.category.value if hasattr(f.category, "value") else str(f.category)
        raw_sev = (f.severity or "INFO").upper()
        sev_val = raw_sev if raw_sev in allowed_sevs else "INFO"

        match_cat = selected_category == "ALL" or cat_val == selected_category
        match_sev = selected_severity == "ALL" or sev_val == selected_severity

        if match_cat and match_sev:
            filtered.append(f)

    if not filtered:
        st.info("該当する指摘事項 (Findings) はありません。")
        return

    # 表示上限の前に重要度順で Findings をソート (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    filtered.sort(key=lambda f: SEVERITY_ORDER.get((f.severity or "INFO").upper(), 5))

    allowed_sevs = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    cards_html = []
    for f in filtered[:500]:  # 重要度上位最大500件まで描画
        raw_sev = (f.severity or "INFO").upper()
        sev_class = raw_sev if raw_sev in allowed_sevs else "INFO"

        cat_name = f.category.value if hasattr(f.category, "value") else str(f.category)
        rule_id = escape_html(f.rule_id)
        title = escape_html(f.title)
        desc = escape_html(f.description)
        source = escape_html(f.source)

        target_html = ""
        if f.target:
            target_str = escape_html(f.target)
            if f.location:
                target_str += f" ({escape_html(f.location)})"
            target_html = f'<div class="finding-target-custom">📄 {target_str}</div>'

        remed_html = ""
        if f.remediation:
            remed_html = f'<div class="finding-remediation-custom">💡 対策案内: {escape_html(f.remediation)}</div>'

        cards_html.append(
            f'<div class="finding-card-custom {sev_class}">'
            f'<div class="finding-meta-custom">'
            f'<span class="sev-tag-custom {sev_class}">{sev_class}</span>'
            f'<span class="cat-pill-custom">{escape_html(cat_name)}</span>'
            f'<span class="rule-id-custom">{rule_id}</span>'
            f'<span class="label-muted" style="margin-left: auto;">[{source}]</span>'
            f"</div>"
            f'<div class="finding-title-custom">{title}</div>'
            f'<div class="finding-desc-custom">{desc}</div>'
            f"{target_html}"
            f"{remed_html}"
            f"</div>"
        )

    st.markdown("".join(cards_html), unsafe_allow_html=True)
    if len(filtered) > 500:
        st.caption(
            f"表示上限 (500 件) を超えたため、一部の指摘事項の表示を省略しています (全 {len(filtered)} 件)。"
        )


def check_has_partial_failure(result: OverallResult) -> bool:
    """リポジトリスキャンにおける一部失敗・制限・非評価・スキャナー失敗を判定する。"""
    scanner_st = getattr(result, "scanner_status", {}) or {}
    snapshot_failed = bool(scanner_st.get("snapshot_failed"))
    has_skipped_files = bool(result.skipped_files) or bool(
        scanner_st.get("has_skipped_files")
    )
    trivy_failed = scanner_st.get("trivy") is False
    scorecard_failed = scanner_st.get("scorecard") is False
    rule_based_failed = scanner_st.get("rule_based") is False

    scorecard_unevaluated_check = any(
        f.source == "scorecard" and f.raw_score is None for f in result.all_findings
    )

    return (
        snapshot_failed
        or has_skipped_files
        or trivy_failed
        or scorecard_failed
        or rule_based_failed
        or scorecard_unevaluated_check
        or any(
            (
                f.rule_id.endswith("-UNEVALUATED")
                and f.rule_id != "GIT-HISTORY-UNEVALUATED"
            )
            or f.rule_id.endswith("-EXCEEDED")
            or f.rule_id.endswith("-FAILED")
            or f.rule_id.endswith("-LIMIT")
            or f.rule_id
            in (
                "SKIPPED-FILES-LIMIT",
                "SNAPSHOT-FETCH-FAILED",
                "FALLBACK-SCAN-FAILED-UNEVALUATED",
                "GLOBAL-LIMIT-EXCEEDED",
                "FINDINGS-LIMIT-EXCEEDED",
                "TRIVY-FINDINGS-LIMIT-EXCEEDED",
            )
            for f in result.all_findings
        )
    )


def main() -> None:
    from src.config import ScanConfig
    from src.logger import setup_logging

    config = ScanConfig(project_root())
    setup_logging(level=config.resolve_log_level(), log_file=config.resolve_log_file())

    st.set_page_config(
        page_title="OSS Security Risk Check Agent",
        page_icon="🛡️",
        layout="wide",
    )

    inject_custom_theme()

    # ヘッダーエリア
    st.title("🛡️ OSS Security Risk Check Agent")
    st.caption(
        "GitHub リポジトリ URL を入力して診断を実行すると、裏側で Python スキャンが自動実行され、リアルタイムにスコアと詳細結果が表示されます。"
    )

    # 外部スキャンツールの安全自動取得・検証 (P1 & P2 レビュー対応)
    try:
        binaries = ensure_scanner_binaries()
    except Exception as e:
        logger.warning(f"バイナリ検出処理で例外が発生しました: {e}")
        binaries = {"trivy": False, "scorecard": False}
    missing_tools = [t for t, exists in binaries.items() if not exists]
    if missing_tools:
        st.warning(
            f"⚠️ **外部スキャンツールの案内**: システムに `{'`, `'.join(missing_tools)}` バイナリが検出されませんでした。"
            "ツール未導入環境では、ルールベース診断を中心に自動実行されます。"
        )

    # 入力フォームエリア
    with st.container(border=True):
        col_url, col_ref, col_sub = st.columns([3, 1, 1])
        with col_url:
            repo_url = st.text_input(
                "GitHub リポジトリ URL",
                placeholder="https://github.com/owner/repo",
                help="GitHub の公開リポジトリ URL を指定してください。",
            )
        with col_ref:
            ref = st.text_input(
                "ブランチ / タグ（任意）",
                placeholder="main",
            )
        with col_sub:
            subdir = st.text_input(
                "サブディレクトリ（任意）",
                placeholder="backend",
            )

        btn_scan = st.button(
            "🚀 診断・スキャンを実行", type="primary", use_container_width=True
        )

    if not btn_scan:
        cached_result = st.session_state.get("mvp_result")
        if cached_result:
            is_cached_fetch_failed = (
                cached_result.status == OverallStatus.UNKNOWN
                or "fetch failed" in (cached_result.status_reason or "").lower()
                or "invalid" in (cached_result.status_reason or "").lower()
            )
            if is_cached_fetch_failed:
                st.error(
                    f"❌ リポジトリの取得またはスキャンに失敗しました: {escape_html(cached_result.status_reason)}"
                )
            elif check_has_partial_failure(cached_result):
                st.warning(
                    "⚠️ リポジトリ snapshot の取得制限や一部カテゴリ診断の制限・エラーが発生したため、一部の診断がスキップされました。詳細は下記レポートをご確認ください。"
                )
            render_hero_score(cached_result)
            render_skipped_files_alert(cached_result)
            render_scanner_status_alert(cached_result)
            render_category_cards(cached_result)

            counts = render_findings_summary(cached_result)

            filter_col1, filter_col2 = st.columns(2)
            with filter_col1:
                cat_filter = st.selectbox(
                    "表示カテゴリ絞り込み",
                    options=["ALL"] + [c.value for c in Category],
                    index=0,
                )
            with filter_col2:
                sev_options = [
                    f"ALL (全 {len(cached_result.all_findings)} 件)",
                    f"CRITICAL ({counts['CRITICAL']} 件)",
                    f"HIGH ({counts['HIGH']} 件)",
                    f"MEDIUM ({counts['MEDIUM']} 件)",
                    f"LOW ({counts['LOW']} 件)",
                    f"INFO ({counts['INFO']} 件)",
                ]
                selected_sev_idx = st.selectbox(
                    "表示重要度絞り込み",
                    options=range(len(sev_options)),
                    format_func=lambda i: sev_options[i],
                    index=0,
                )
                sev_map = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                sev_filter = sev_map[selected_sev_idx]

            render_findings_list(cached_result, cat_filter, sev_filter)
        else:
            st.info(
                "👆 上のフォームに GitHub リポジトリ URL を入力し、「🚀 診断・スキャンを実行」ボタンを押してください。"
            )
        return

    if not repo_url or not repo_url.strip():
        st.error("GitHub リポジトリ URL を入力してください。")
        return

    options = WebScanOptions(
        target_url=normalize_optional(repo_url),
        target_ref=normalize_optional(ref),
        target_subdir=normalize_optional(subdir),
    )

    try:
        with st.spinner(
            "リポジトリ snapshot を安全取得し、8カテゴリのルール診断を実行中..."
        ):
            orchestrator = MVPOrchestrator(project_root(), cli_options=options)
            result = orchestrator.run_full_scan(options.target_url, save_to_docs=False)

        # 1. 致命的な取得失敗や評価不能のチェック
        is_fetch_failed = (
            result.status == OverallStatus.UNKNOWN
            or "fetch failed" in (result.status_reason or "").lower()
            or "invalid" in (result.status_reason or "").lower()
        )
        if is_fetch_failed:
            st.error(
                f"❌ リポジトリの取得またはスキャンに失敗しました: {escape_html(result.status_reason)}"
            )
            if not result.all_findings and not result.categories:
                return

        # 2. 一部スキャンや snapshot fetcher 制限・失敗の検出 (P2 レビュー対応)
        has_partial_failure = check_has_partial_failure(result)

        if has_partial_failure:
            st.warning(
                "⚠️ リポジトリ snapshot の取得制限や一部カテゴリ診断の制限・エラーが発生したため、一部の診断がスキップされました。詳細は下記レポートをご確認ください。"
            )
        else:
            st.toast("スキャンが完了しました！", icon="✅")

        st.session_state["mvp_result"] = result

        render_hero_score(result)
        render_skipped_files_alert(result)
        render_scanner_status_alert(result)
        render_category_cards(result)

        counts = render_findings_summary(result)

        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            cat_filter = st.selectbox(
                "表示カテゴリ絞り込み",
                options=["ALL"] + [c.value for c in Category],
                index=0,
            )
        with filter_col2:
            sev_options = [
                f"ALL (全 {len(result.all_findings)} 件)",
                f"CRITICAL ({counts['CRITICAL']} 件)",
                f"HIGH ({counts['HIGH']} 件)",
                f"MEDIUM ({counts['MEDIUM']} 件)",
                f"LOW ({counts['LOW']} 件)",
                f"INFO ({counts['INFO']} 件)",
            ]
            selected_sev_idx = st.selectbox(
                "表示重要度絞り込み",
                options=range(len(sev_options)),
                format_func=lambda i: sev_options[i],
                index=0,
            )
            sev_map = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sev_filter = sev_map[selected_sev_idx]

        render_findings_list(result, cat_filter, sev_filter)

    except ValueError as val_err:
        st.error(f"入力エラー: {val_err}")
    except SystemExit as sys_exit:
        logger.warning(f"スキャン処理がシステム終了を呼び出しました: {sys_exit}")
        st.error(f"設定エラーが発生しました: {sys_exit}")
    except Exception:
        logger.exception("スキャン処理中に予期しないエラーが発生しました。")
        st.error(
            "スキャン処理中に予期しないエラーが発生しました。詳細はサーバーログを確認してください。"
        )


if __name__ == "__main__":
    main()
