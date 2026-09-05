from __future__ import annotations

import pytest
from src.mvp_models import Category, Finding, OverallStatus
from src.scoring.engine import ScoringEngine


def test_scoring_engine_basic() -> None:
    engine = ScoringEngine()
    findings = [
        Finding(
            category=Category.KNOWN_VULNERABILITIES,
            source="trivy",
            rule_id="CVE-2023-0001",
            severity="HIGH",
            title="Test Vulnerability",
        ),
        Finding(
            category=Category.SOURCE_CODE,
            source="rule_based",
            rule_id="RB-A1-001",
            severity="CRITICAL",
            title="Command Injection",
        ),
    ]

    result = engine.evaluate("https://github.com/example/test", findings)

    assert result.repository_url == "https://github.com/example/test"
    assert "known_vulnerabilities" in result.categories
    assert "source_code" in result.categories

    # KNOWN_VULNERABILITIES: 10 - 1.5 (HIGH) = 8.5
    assert result.categories["known_vulnerabilities"].score == 8.5

    # SOURCE_CODE: 10 - 3.0 (CRITICAL) = 7.0
    assert result.categories["source_code"].score == 7.0


def test_scoring_engine_cutoff_rule() -> None:
    engine = ScoringEngine()

    # 1つのカテゴリに大量のCRITICALを入れて 2.0 点以下にする
    findings = [
        Finding(
            category=Category.SECRETS,
            source="trivy",
            rule_id="SECRET-1",
            severity="CRITICAL",
            title="Secret 1",
        ),
        Finding(
            category=Category.SECRETS,
            source="trivy",
            rule_id="SECRET-2",
            severity="CRITICAL",
            title="Secret 2",
        ),
        Finding(
            category=Category.SECRETS,
            source="trivy",
            rule_id="SECRET-3",
            severity="CRITICAL",
            title="Secret 3",
        ),
    ]

    result = engine.evaluate("https://github.com/example/test", findings)

    # SECRETS カテゴリは 10 - 9.0 = 1.0 点
    assert result.categories["secrets"].score == 1.0

    # 足切りルールにより「危険」と判定される
    assert result.status == OverallStatus.DANGEROUS
    assert "足切りルール" in result.status_reason
