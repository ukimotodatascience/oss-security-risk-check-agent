from datetime import datetime, timezone

from src.models import RiskRecord, Severity
from src.reporting import ReportWriter


def test_report_writer_builds_summary_priority_details_and_errors(tmp_path):
    records = [
        RiskRecord(
            rule_id="F-5",
            category="secrets",
            title="Private Keys Detected",
            severity=Severity.CRITICAL,
            file_path="src/app.py",
            line=10,
            message="secret | leaked\nrotate immediately",
        ),
        RiskRecord(
            rule_id="B-2",
            category="dependencies",
            title="Unpinned Versions",
            severity=Severity.MEDIUM,
            file_path="requirements.txt",
            line=1,
            message="requests is unpinned",
        ),
    ]
    generated_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    markdown = ReportWriter(tmp_path).build_markdown(
        tmp_path,
        records,
        errors=(("X-1", "Traceback line 1\nTraceback line 2"),),
        generated_at=generated_at,
    )

    assert "# OSS Security Risk Report" in markdown
    assert "- **検知件数:** 2" in markdown
    assert "- **ルール実行エラー件数:** 1" in markdown
    assert "### 2.1 総合評価" in markdown
    assert "| Risk Score | Rating | Critical / High | Total Findings |" in markdown
    assert "| 14/100 | Low | 1 | 2 |" in markdown
    assert "**推奨対応:** 重大な検知は限定的です。" in markdown
    assert "Critical=10, High=7, Medium=4, Low=1, Info=0" in markdown
    assert "Critical / High が **1件**" in markdown
    assert "| Severity | Count |" in markdown
    assert "| Critical | 1 |" in markdown
    assert "| Medium | 1 |" in markdown
    assert "| secrets | 1 |" in markdown
    assert "| F-5 | Private Keys Detected | Critical | 1 |" in markdown
    assert (
        "| Critical | F-5 Private Keys Detected | secrets | src/app.py:10 |" in markdown
    )
    assert "secret \\| leaked<br>rotate immediately" in markdown
    assert "#### [F-5] Private Keys Detected — 1件" in markdown
    assert "## 6. ルール実行エラー" in markdown
    assert "### X-1" in markdown
    assert "Traceback line 2" in markdown


def test_report_writer_reports_no_findings(tmp_path):
    markdown = ReportWriter(tmp_path).build_markdown(
        tmp_path,
        records=(),
        errors=(),
        generated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )

    assert "- **検知件数:** 0" in markdown
    assert "| 0/100 | No findings | 0 | 0 |" in markdown
    assert "今回のルールセットでは検知されませんでした。" in markdown
    assert "該当するリスクはありませんでした。" in markdown
    assert "Critical / High の検知はありません。" in markdown
    assert "## 6. ルール実行エラー" not in markdown


def test_report_writer_caps_overall_risk_score_at_100(tmp_path):
    records = [
        RiskRecord(
            rule_id=f"F-{index}",
            category="secrets",
            title="Critical Finding",
            severity=Severity.CRITICAL,
        )
        for index in range(11)
    ]

    markdown = ReportWriter(tmp_path).build_markdown(
        tmp_path,
        records=records,
        errors=(),
        generated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )

    assert "| 100/100 | Critical | 11 | 11 |" in markdown
    assert "公開・リリース前に即時対応が必要です。" in markdown
