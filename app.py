from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import streamlit as st

from src.models import RiskRecord, Severity
from src.reporting import ReportWriter
from src.scan import ScanResult
from src.scan import SecurityScan


SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#64748b",
}


def inject_theme() -> None:
    """アプリ全体の余白・カード・アラート表現を整える。"""

    st.markdown(
        """
        <style>
            .block-container {
                padding-top: 2rem;
                padding-bottom: 3rem;
            }

            [data-testid="stSidebar"] {
                background: linear-gradient(180deg, #0f172a 0%, #111827 100%);
            }

            [data-testid="stSidebar"] h1,
            [data-testid="stSidebar"] h2,
            [data-testid="stSidebar"] h3,
            [data-testid="stSidebar"] p,
            [data-testid="stSidebar"] label,
            [data-testid="stSidebar"] .stMarkdown,
            [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
                color: #f8fafc;
            }

            [data-testid="stSidebar"] input,
            [data-testid="stSidebar"] textarea,
            [data-testid="stSidebar"] [data-baseweb="input"] input {
                color: #0f172a !important;
                background-color: #ffffff !important;
            }

            [data-testid="stSidebar"] input::placeholder {
                color: #64748b !important;
                opacity: 1;
            }

            [data-testid="stSidebar"] button p {
                color: inherit;
            }

            .hero-card {
                padding: 2rem;
                border-radius: 1.4rem;
                background:
                    radial-gradient(circle at top right, rgba(59, 130, 246, 0.25), transparent 32%),
                    linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
                color: white;
                box-shadow: 0 20px 45px rgba(15, 23, 42, 0.18);
                margin-bottom: 1.5rem;
            }

            .hero-card h1 {
                margin: 0 0 .5rem 0;
                font-size: 2.45rem;
                line-height: 1.15;
            }

            .hero-card p {
                margin: 0;
                color: #dbeafe;
                font-size: 1.05rem;
            }

            .hero-badges {
                display: flex;
                flex-wrap: wrap;
                gap: .6rem;
                margin-top: 1.25rem;
            }

            .hero-badge {
                padding: .35rem .7rem;
                border-radius: 999px;
                background: rgba(255, 255, 255, .13);
                border: 1px solid rgba(255, 255, 255, .18);
                color: #eff6ff;
                font-size: .86rem;
            }

            .section-card {
                padding: 1.15rem 1.2rem;
                border: 1px solid #e2e8f0;
                border-radius: 1rem;
                background: #ffffff;
                box-shadow: 0 10px 28px rgba(15, 23, 42, .06);
                margin: .7rem 0 1rem;
            }

            .subtle-note {
                padding: 1rem 1.1rem;
                border-radius: .95rem;
                border: 1px solid #bfdbfe;
                background: #eff6ff;
                color: #1e3a8a;
            }

            .subtle-note strong {
                color: #1e40af;
            }

            .empty-state {
                padding: 2rem;
                border: 1px dashed #cbd5e1;
                border-radius: 1rem;
                background: #f8fafc;
                text-align: center;
                color: #475569;
            }

            .empty-state h3 {
                color: #0f172a;
            }

            .empty-state p {
                color: #475569;
            }

            .severity-pill {
                display: inline-block;
                padding: .18rem .55rem;
                border-radius: 999px;
                color: white;
                font-weight: 700;
                font-size: .78rem;
                letter-spacing: .01em;
            }

            .stDownloadButton button {
                border-radius: .8rem;
                font-weight: 700;
            }

        </style>
        """,
        unsafe_allow_html=True,
    )


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


def render_hero() -> None:
    """ファーストビューとしてアプリの価値と安全性を端的に伝える。"""

    st.markdown(
        """
        <div class="hero-card">
            <h1>🛡️ OSS Security Risk Check Agent</h1>
            <p>
                GitHub リポジトリの archive snapshot を安全に取得し、OSS 利用前のセキュリティリスクを素早く可視化します。
            </p>
            <div class="hero-badges">
                <span class="hero-badge">No git clone</span>
                <span class="hero-badge">Static analysis</span>
                <span class="hero-badge">Markdown report</span>
                <span class="hero-badge">Safe archive extraction</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state() -> None:
    """初回表示時の案内をカードとして描画する。"""

    st.markdown(
        """
        <div class="empty-state">
            <h3>🔍 まずはスキャン対象を指定してください</h3>
            <p>
                左側のフォームに GitHub リポジトリ URL を入力し、必要に応じてブランチ・タグ・サブディレクトリを指定できます。
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_safety_note() -> None:
    """解析時の安全な実行方針を表示する。"""

    st.markdown(
        """
        <div class="subtle-note">
            <strong>安全な解析方針:</strong>
            対象リポジトリ内のスクリプトは実行せず、GitHub archive zipball を一時ディレクトリへ展開して静的解析します。
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_label(severity: str) -> str:
    """検知一覧で使う深刻度ラベルを返す。"""

    icons = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🔵",
        "Info": "⚪",
    }
    return f"{icons.get(severity, '⚪')} {severity}"


def render_result(result: ScanResult, report_text: str) -> None:
    """保存済みのスキャン結果を画面に描画する。"""

    st.toast("スキャンが完了しました。", icon="✅")
    st.success("スキャンが完了しました。結果を確認できます。")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("検知件数", f"{len(result.records):,}")
    col2.metric("ルール実行エラー", f"{len(result.errors):,}")
    col3.metric("読み込みルール数", f"{result.loaded_rule_count:,}")
    col4.metric("実行ルール数", f"{result.executed_rule_count:,}")

    with st.container(border=True):
        st.subheader("📌 実行情報")
        info_col1, info_col2, info_col3 = st.columns([2, 1, 1])
        info_col1.write("**Target**")
        info_col1.code(result.target.display_name, language=None)
        info_col2.write("**Fetch mode**")
        info_col2.code(result.target.fetch_mode, language=None)
        info_col3.write("**Report**")
        info_col3.code("画面表示・DLのみ", language=None)

        ref_col, subdir_col = st.columns(2)
        ref_col.write(f"**Ref:** `{result.target.ref or '-'}`")
        subdir_col.write(f"**Subdir:** `{result.target.subdir or '-'}`")

    counts = {
        key: value for key, value in severity_counts(result.records).items() if value
    }
    chart_col, action_col = st.columns([2, 1])
    with chart_col:
        with st.container(border=True):
            st.subheader("📊 深刻度別件数")
            if counts:
                st.bar_chart(counts)
            else:
                st.write("検知はありませんでした。")

    with action_col:
        with st.container(border=True):
            st.subheader("📄 レポート")
            st.write("Markdown形式のレポートをダウンロードできます。")
            st.download_button(
                "Markdown レポートをダウンロード",
                data=report_text,
                file_name=f"report_{result.generated_at.strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                type="primary",
                width="stretch",
            )

    st.subheader("🧾 検知一覧")
    if result.records:
        with st.container(border=True):
            st.dataframe(
                [
                    {
                        "Severity": severity_label(record.severity.value),
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
                column_config={
                    "Severity": st.column_config.TextColumn("Severity", width="small"),
                    "Rule": st.column_config.TextColumn("Rule", width="medium"),
                    "Title": st.column_config.TextColumn("Title", width="large"),
                    "Category": st.column_config.TextColumn("Category", width="medium"),
                    "Location": st.column_config.TextColumn("Location", width="large"),
                    "Message": st.column_config.TextColumn("Message", width="large"),
                },
            )
    else:
        st.markdown(
            """
            <div class="empty-state">
                <h3>✅ 該当するリスクはありませんでした</h3>
                <p>現時点のルールでは検知されていません。Markdown レポートとして結果を保存できます。</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with st.expander("Markdown レポートプレビュー", expanded=False):
        st.markdown(report_text)

    if result.errors:
        with st.expander("⚠️ ルール実行エラー"):
            for rule_id, traceback_text in result.errors:
                st.code(f"[{rule_id}]\n{traceback_text}")


def main() -> None:
    st.set_page_config(
        page_title="OSS Security Risk Check Agent",
        page_icon="🛡️",
        layout="wide",
    )
    inject_theme()

    render_hero()

    with st.sidebar:
        st.header("⚙️ スキャン設定")
        st.caption("GitHub URL を入力して、対象 snapshot を静的解析します。")
        repo_url = st.text_input(
            "GitHub リポジトリ URL",
            placeholder="https://github.com/owner/repo",
            help="GitHub の公開リポジトリURLを指定してください。",
        )
        ref = st.text_input(
            "ブランチ / タグ / コミット（任意）",
            placeholder="main",
            help="未指定の場合はリポジトリのデフォルトブランチを使用します。",
        )
        subdir = st.text_input(
            "サブディレクトリ（任意）",
            placeholder="backend",
            help="モノレポ等で解析対象を絞りたい場合に指定します。",
        )
        submitted = st.button("🚀 スキャン実行", type="primary", width="stretch")

        st.divider()
        st.markdown("**解析ポリシー**")
        st.markdown(
            "- 対象コードは実行しません\n- archive snapshot を利用します\n- レポートは画面上で生成します"
        )

    render_safety_note()

    cached_result = st.session_state.get("scan_result")
    cached_report_text = st.session_state.get("report_text")

    if not submitted:
        if cached_result and cached_report_text:
            render_result(cached_result, cached_report_text)
            return
        render_empty_state()
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
