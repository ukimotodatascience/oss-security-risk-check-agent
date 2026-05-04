from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import streamlit as st

from src.models import RiskRecord, Severity
from src.reporting import ReportWriter
from src.scan import ScanResult
from src.scan import SecurityScan


@dataclass(frozen=True)
class WebScanOptions:
    """Streamlit フォームから受け取る URL スキャン指定。"""

    target_url: str | None = None
    target_ref: str | None = None
    target_subdir: str | None = None
    output_dir: str | None = None


def project_root() -> Path:
    """Streamlit 起動位置に依存せず、プロジェクトルートを返す。"""

    return Path(__file__).resolve().parent


def normalize_optional(value: str) -> str | None:
    """空文字を設定未指定として扱う。"""

    stripped = value.strip()
    return stripped or None


def severity_counts(records: Sequence[RiskRecord]) -> dict[str, int]:
    """Streamlit 表示用に深刻度別件数を集計する。"""

    return {
        severity.value: sum(1 for record in records if record.severity == severity)
        for severity in Severity
    }


def render_result(result: ScanResult, report_text: str) -> None:
    """保存済みのスキャン結果を画面に描画する。"""

    st.success("スキャンが完了しました。")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("検知件数", len(result.records))
    col2.metric("ルール実行エラー", len(result.errors))
    col3.metric("読み込みルール数", result.loaded_rule_count)
    col4.metric("実行ルール数", result.executed_rule_count)

    st.subheader("実行情報")
    st.json(
        {
            "target": result.target.display_name,
            "fetch_mode": result.target.fetch_mode,
            "ref": result.target.ref or "-",
            "subdir": result.target.subdir or "-",
            "report": "ファイル保存なし（画面表示・ダウンロードのみ）",
        }
    )

    counts = {
        key: value for key, value in severity_counts(result.records).items() if value
    }
    st.subheader("深刻度別件数")
    if counts:
        st.bar_chart(counts)
    else:
        st.write("検知はありませんでした。")

    st.subheader("検知一覧")
    if result.records:
        st.dataframe(
            [
                {
                    "Severity": record.severity.value,
                    "Rule": record.rule_id,
                    "Title": record.title,
                    "Category": record.category,
                    "Location": ReportWriter._location(record),
                    "Message": record.message or "-",
                }
                for record in result.records
            ],
            width="stretch",
            hide_index=True,
        )
    else:
        st.write("該当するリスクはありませんでした。")

    st.download_button(
        "Markdown レポートをダウンロード",
        data=report_text,
        file_name=f"report_{result.generated_at.strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown",
    )

    st.subheader("Markdown レポートプレビュー")
    st.markdown(report_text)

    if result.errors:
        with st.expander("ルール実行エラー"):
            for rule_id, traceback_text in result.errors:
                st.code(f"[{rule_id}]\n{traceback_text}")


def main() -> None:
    st.set_page_config(
        page_title="OSS Security Risk Check Agent",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ OSS Security Risk Check Agent")
    st.caption(
        "GitHub URL を指定して archive snapshot を静的解析し、Markdown レポートを生成します。"
    )

    with st.sidebar:
        st.header("スキャン設定")
        repo_url = st.text_input(
            "GitHub リポジトリ URL",
            placeholder="https://github.com/owner/repo",
        )
        ref = st.text_input("ブランチ / タグ / コミット（任意）", placeholder="main")
        subdir = st.text_input("サブディレクトリ（任意）", placeholder="backend")
        submitted = st.button("スキャン実行", type="primary", width="stretch")

    st.info(
        "このアプリは `git clone` や対象リポジトリ内スクリプトの実行を行わず、"
        "GitHub archive zipball を一時ディレクトリへ展開して静的解析します。"
    )

    cached_result = st.session_state.get("scan_result")
    cached_report_text = st.session_state.get("report_text")

    if not submitted:
        if cached_result and cached_report_text:
            render_result(cached_result, cached_report_text)
            return
        st.markdown(
            "左側のフォームに GitHub URL を入力して **スキャン実行** を押してください。"
        )
        return

    if not repo_url.strip():
        st.error("GitHub リポジトリ URL を入力してください。")
        return

    options = WebScanOptions(
        target_url=normalize_optional(repo_url),
        target_ref=normalize_optional(ref),
        target_subdir=normalize_optional(subdir),
    )

    try:
        with st.spinner("リポジトリ snapshot を取得し、ルールを実行しています..."):
            result = SecurityScan(
                project_root(), cli_options=options, persist_report=False
            ).run()
    except SystemExit as exc:
        st.error(str(exc))
        return
    except Exception as exc:  # noqa: BLE001 - Web UI では例外内容を画面へ返す
        st.exception(exc)
        return

    report_text = result.report_markdown
    st.session_state["scan_result"] = result
    st.session_state["report_text"] = report_text
    render_result(result, report_text)


if __name__ == "__main__":
    main()
