"""検知結果のレポート生成（Markdown）。"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from src.models import RiskRecord, Severity


class ReportWriter:
    """検知結果を Markdown ファイルに書き出す。"""

    SUMMARY_LIMIT = 10
    PRIORITY_FINDINGS_LIMIT = 20

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

    @classmethod
    def _severity_value(cls, record: RiskRecord) -> str:
        return (
            record.severity.value
            if isinstance(record.severity, Severity)
            else str(record.severity)
        )

    @classmethod
    def _record_sort_key(cls, record: RiskRecord) -> tuple[int, str, str, int]:
        return (
            cls._severity_sort_key(record.severity)
            if isinstance(record.severity, Severity)
            else 99,
            record.rule_id,
            record.file_path or "",
            record.line or 0,
        )

    @staticmethod
    def _normalize_path(path: str | None) -> str:
        if not path:
            return ""
        return path.replace("\\", "/")

    @classmethod
    def _location(cls, record: RiskRecord) -> str:
        if not record.file_path:
            return "-"
        location = cls._normalize_path(record.file_path)
        if record.line is not None:
            return f"{location}:{record.line}"
        return location

    @staticmethod
    def _escape_table_cell(value: object) -> str:
        text = "" if value is None else str(value)
        text = text.replace("\n", "<br>").replace("|", "\\|")
        return text or "-"

    @classmethod
    def _append_table(
        cls,
        lines: List[str],
        headers: Sequence[str],
        rows: Iterable[Sequence[object]],
    ) -> None:
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            lines.append(
                "| " + " | ".join(cls._escape_table_cell(value) for value in row) + " |"
            )
        lines.append("")

    @classmethod
    def _directory_bucket(cls, record: RiskRecord) -> str:
        path = cls._normalize_path(record.file_path)
        if not path:
            return "(場所なし)"
        parts = path.split("/")
        if len(parts) >= 2:
            return "/".join(parts[:2])
        return parts[0]

    def build_markdown(
        self,
        target: Path,
        records: Sequence[RiskRecord],
        errors: Sequence[Tuple[str, str]],
        generated_at: datetime,
    ) -> str:
        """人間向け Markdown レポート文字列を組み立てる。"""
        sorted_records = sorted(records, key=self._record_sort_key)
        lines: List[str] = [
            "# OSS Security Risk Report",
            "",
            "## 1. 実行情報",
            "",
            f"- **対象ディレクトリ:** `{self._normalize_path(str(target))}`",
            f"- **生成日時 (UTC):** {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"- **検知件数:** {len(records)}",
            f"- **ルール実行エラー件数:** {len(errors)}",
            "",
        ]

        by_severity = Counter(self._severity_value(r) for r in records)
        by_category = Counter(r.category for r in records)
        by_rule = Counter(
            (r.rule_id, r.title, self._severity_value(r)) for r in records
        )
        by_directory = Counter(self._directory_bucket(r) for r in records)

        lines.append("## 2. エグゼクティブサマリ")
        lines.append("")
        if not records:
            lines.append("該当するリスクはありませんでした。")
            lines.append("")
        else:
            critical_high_count = by_severity.get(
                Severity.CRITICAL.value, 0
            ) + by_severity.get(Severity.HIGH.value, 0)
            lines.append(
                f"Critical / High が **{critical_high_count}件** 検出されています。"
                "まずは下記の「対応優先リスク」と、件数の多いルールを確認してください。"
            )
            lines.append("")

        lines.append("## 3. 集計")
        lines.append("")

        lines.append("### 3.1 深刻度別")
        lines.append("")
        severity_rows = []
        for sev in Severity:
            count = by_severity.get(sev.value, 0)
            if count:
                severity_rows.append((sev.value, count))
        if severity_rows:
            self._append_table(lines, ("Severity", "Count"), severity_rows)
        else:
            lines.append("（検知なし）")
            lines.append("")

        lines.append("### 3.2 カテゴリ別")
        lines.append("")
        if by_category:
            self._append_table(
                lines,
                ("Category", "Count"),
                by_category.most_common(self.SUMMARY_LIMIT),
            )
        else:
            lines.append("（検知なし）")
            lines.append("")

        lines.append("### 3.3 ルール別 Top 10")
        lines.append("")
        if by_rule:
            rule_rows = [
                (rule_id, title, severity, count)
                for (rule_id, title, severity), count in by_rule.most_common(
                    self.SUMMARY_LIMIT
                )
            ]
            self._append_table(
                lines,
                ("Rule", "Title", "Severity", "Count"),
                rule_rows,
            )
        else:
            lines.append("（検知なし）")
            lines.append("")

        lines.append("### 3.4 ディレクトリ別 Top 10")
        lines.append("")
        if by_directory:
            self._append_table(
                lines,
                ("Directory", "Count"),
                by_directory.most_common(self.SUMMARY_LIMIT),
            )
        else:
            lines.append("（ファイルパス付き検知なし）")
            lines.append("")

        lines.append("## 4. 対応優先リスク")
        lines.append("")
        priority_records = [
            r
            for r in sorted_records
            if self._severity_value(r) in {Severity.CRITICAL.value, Severity.HIGH.value}
        ][: self.PRIORITY_FINDINGS_LIMIT]
        if priority_records:
            self._append_table(
                lines,
                ("Severity", "Rule", "Category", "Location", "Message"),
                (
                    (
                        self._severity_value(r),
                        f"{r.rule_id} {r.title}",
                        r.category,
                        self._location(r),
                        r.message or "-",
                    )
                    for r in priority_records
                ),
            )
            remaining_priority = max(
                0,
                len(
                    [
                        r
                        for r in sorted_records
                        if self._severity_value(r)
                        in {Severity.CRITICAL.value, Severity.HIGH.value}
                    ]
                )
                - len(priority_records),
            )
            if remaining_priority:
                lines.append(
                    f"> Critical / High の残り {remaining_priority} 件は詳細検知一覧を確認してください。"
                )
                lines.append("")
        else:
            lines.append("Critical / High の検知はありません。")
            lines.append("")

        lines.append("## 5. 詳細検知一覧")
        lines.append("")
        if not records:
            lines.append("該当するリスクはありませんでした。")
        else:
            grouped: dict[str, dict[tuple[str, str, str], list[RiskRecord]]] = (
                defaultdict(lambda: defaultdict(list))
            )
            for r in sorted_records:
                grouped[self._severity_value(r)][
                    (r.rule_id, r.title, r.category)
                ].append(r)

            for sev in [s.value for s in Severity if by_severity.get(s.value, 0)]:
                lines.append(f"### {sev}")
                lines.append("")
                for rule_key in sorted(grouped[sev].keys()):
                    rule_id, title, category = rule_key
                    rule_records = grouped[sev][rule_key]
                    lines.append(f"#### [{rule_id}] {title} — {len(rule_records)}件")
                    lines.append("")
                    lines.append(f"- **カテゴリ:** {category}")
                    lines.append("")
                    self._append_table(
                        lines,
                        ("Location", "Message"),
                        ((self._location(r), r.message or "-") for r in rule_records),
                    )
                lines.append("")

        if errors:
            lines.append("## 6. ルール実行エラー")
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
