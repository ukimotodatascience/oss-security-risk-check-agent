"""検知結果のレポート生成（Markdown）。"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, Sequence, Tuple

from src.models import RiskRecord, Severity


class ReportWriter:
    """検知結果を Markdown ファイルに書き出す。"""

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir

    @staticmethod
    def _severity_sort_key(sev: Severity) -> int:
        order = (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )
        try:
            return order.index(sev)
        except ValueError:
            return len(order)

    def build_markdown(
        self,
        target: Path,
        records: Sequence[RiskRecord],
        errors: Sequence[Tuple[str, str]],
        generated_at: datetime,
    ) -> str:
        """人間向け Markdown レポート文字列を組み立てる。"""
        lines: List[str] = [
            "# OSS Security Risk Report",
            "",
            f"- **対象ディレクトリ:** `{target}`",
            f"- **生成日時 (UTC):** {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"- **検知件数:** {len(records)}",
            "",
        ]

        by_severity: dict[str, int] = {}
        for r in records:
            s = r.severity.value if isinstance(r.severity, Severity) else str(r.severity)
            by_severity[s] = by_severity.get(s, 0) + 1

        lines.append("## 深刻度別サマリ")
        lines.append("")
        if not records:
            lines.append("（検知なし）")
        else:
            for sev in sorted(
                by_severity.keys(),
                key=lambda x: self._severity_sort_key(Severity(x)),
            ):
                lines.append(f"- **{sev}:** {by_severity[sev]}")
        lines.append("")

        lines.append("## 検知一覧")
        lines.append("")
        if not records:
            lines.append("該当するリスクはありませんでした。")
        else:
            sorted_records = sorted(
                records,
                key=lambda x: (
                    self._severity_sort_key(x.severity)
                    if isinstance(x.severity, Severity)
                    else 99,
                    x.rule_id,
                    x.file_path or "",
                    x.line or 0,
                ),
            )
            for r in sorted_records:
                loc = ""
                if r.file_path:
                    loc = f"`{r.file_path}`"
                    if r.line is not None:
                        loc += f" (行 {r.line})"
                sev = (
                    r.severity.value
                    if isinstance(r.severity, Severity)
                    else str(r.severity)
                )
                lines.append(f"### [{r.rule_id}] {r.title} — **{sev}**")
                lines.append("")
                lines.append(f"- **カテゴリ:** {r.category}")
                if loc:
                    lines.append(f"- **場所:** {loc}")
                if r.message:
                    lines.append(f"- **メッセージ:** {r.message}")
                lines.append("")

        if errors:
            lines.append("## ルール実行エラー")
            lines.append("")
            lines.append("以下のルールは例外により完了できませんでした。")
            lines.append("")
            for rid, tb in errors:
                lines.append(f"### {rid}")
                lines.append("")
                lines.append("```")
                lines.append(tb.rstrip())
                lines.append("```")
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def write(
        self,
        target: Path,
        records: Sequence[RiskRecord],
        errors: Sequence[Tuple[str, str]],
        generated_at: datetime,
    ) -> Path:
        """`OUTPUT_DIR`（解決済みパス）に Markdown を書き出し、保存パスを返す。"""
        self._output_dir.mkdir(parents=True, exist_ok=True)
        stamp = generated_at.strftime("%Y%m%d_%H%M%S")
        base = f"report_{stamp}"
        md_path = self._output_dir / f"{base}.md"

        md_body = self.build_markdown(target, records, errors, generated_at)
        md_path.write_text(md_body, encoding="utf-8")

        return md_path
