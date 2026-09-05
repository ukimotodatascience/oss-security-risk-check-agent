from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from src.mvp_models import (
    CATEGORY_NAMES_JA,
    Category,
    CategoryResult,
    Finding,
    OverallResult,
    OverallStatus,
)


class ScoringEngine:
    def __init__(self) -> None:
        pass

    def evaluate(
        self,
        repo_url: str,
        findings: List[Finding],
        scanner_status: Optional[Dict[str, bool]] = None,
    ) -> OverallResult:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        status_map = scanner_status or {
            "trivy": True,
            "scorecard": True,
            "rule_based": True,
        }

        # カテゴリごとに Finding を分類
        cat_findings: Dict[Category, List[Finding]] = {cat: [] for cat in Category}
        for f in findings:
            if f.category in cat_findings:
                cat_findings[f.category].append(f)
            else:
                cat_findings[Category.SOURCE_CODE].append(f)

        category_results: Dict[str, CategoryResult] = {}
        valid_scores: List[float] = []
        risk_findings: List[Finding] = []

        for cat in Category:
            c_findings = cat_findings[cat]
            cat_name = CATEGORY_NAMES_JA.get(cat, cat.value)

            evaluated, score, summary, filtered_risk_findings = (
                self._calculate_category_score(cat, c_findings, status_map)
            )

            cat_res = CategoryResult(
                category=cat,
                category_name=cat_name,
                score=round(score, 1) if score is not None else 0.0,
                evaluated=evaluated,
                findings_count=len(filtered_risk_findings),
                findings=filtered_risk_findings,
                summary=summary,
            )
            category_results[cat.value] = cat_res
            if evaluated and score is not None:
                valid_scores.append(cat_res.score)
            risk_findings.extend(filtered_risk_findings)

        # 総合スコア = 評価成功カテゴリの平均
        overall_score = (
            round(sum(valid_scores) / len(valid_scores), 1) if valid_scores else 0.0
        )

        # 足切りルールと総合判定
        status, status_reason = self._determine_overall_status(
            valid_scores,
            overall_score,
            risk_findings,
            len(valid_scores) == len(Category),
        )

        return OverallResult(
            repository_url=repo_url,
            scanned_at=now_str,
            overall_score=overall_score,
            status=status,
            status_reason=status_reason,
            categories=category_results,
            all_findings=risk_findings,
        )

    def _calculate_category_score(
        self,
        category: Category,
        findings: List[Finding],
        scanner_status: Dict[str, bool],
    ) -> Tuple[bool, float | None, str, List[Finding]]:
        """カテゴリごとの 0〜10 点スコア算出とリスク Finding のフィルタリング"""
        # 1. Scorecard 対象カテゴリ
        if category in (
            Category.DEPENDENCIES,
            Category.DEVELOPMENT,
            Category.CICD,
            Category.MAINTENANCE,
        ):
            if not scanner_status.get("scorecard", False):
                return False, None, "Scorecard スキャナー未実行または評価不能です。", []

            scorecard_findings = [
                f
                for f in findings
                if f.source == "scorecard" and f.raw_score is not None
            ]
            if not scorecard_findings:
                return False, None, "Scorecard 指標データが得られませんでした。", []

            raw_scores = [
                f.raw_score for f in scorecard_findings if f.raw_score is not None
            ]
            base_score = sum(raw_scores) / len(raw_scores)

            risk_list = [
                f
                for f in findings
                if f.severity.upper() != "INFO"
                and (f.raw_score is None or f.raw_score < 7.0)
            ]
            summary = f"OpenSSF Scorecard 指標 {len(raw_scores)} 件から算出。"
            return True, max(0.0, min(10.0, base_score)), summary, risk_list

        # 2. Trivy 対象カテゴリ
        if category in (
            Category.KNOWN_VULNERABILITIES,
            Category.SECRETS,
            Category.MISCONFIGURATION,
        ):
            if not scanner_status.get("trivy", False):
                return False, None, "Trivy スキャナー未実行または評価不能です。", []

        # 3. ルールベース対象カテゴリ
        if category == Category.SOURCE_CODE:
            if not scanner_status.get("rule_based", False):
                return (
                    False,
                    None,
                    "ルールベーススキャナー未実行または評価不能です。",
                    [],
                )

        risk_list = [f for f in findings if f.severity.upper() != "INFO"]

        base = 10.0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for f in risk_list:
            sev = f.severity.upper()
            if sev == "CRITICAL":
                base -= 3.0
                critical_count += 1
            elif sev == "HIGH":
                base -= 1.5
                high_count += 1
            elif sev == "MEDIUM":
                base -= 0.5
                medium_count += 1
            elif sev == "LOW":
                base -= 0.2
                low_count += 1

        final_score = max(0.0, min(10.0, base))
        if len(risk_list) == 0:
            summary = "検出された問題・懸念点はありません。"
        else:
            summary = f"指摘事項 {len(risk_list)} 件 (Critical:{critical_count}, High:{high_count}, Med:{medium_count}, Low:{low_count})"

        return True, final_score, summary, risk_list

    def _determine_overall_status(
        self,
        valid_scores: List[float],
        overall_score: float,
        findings: List[Finding],
        all_evaluated: bool,
    ) -> Tuple[OverallStatus, str]:
        """足切りルールと判定ロジック"""
        if not valid_scores:
            return (
                OverallStatus.MODERATE,
                "すべてのスキャナーが未評価・未実行のため、総合セキュリティスコアを正常算出できませんでした。",
            )

        min_score = min(valid_scores)
        critical_count = sum(
            1 for f in findings if (f.severity or "").upper() == "CRITICAL"
        )

        if min_score <= 2.0:
            return (
                OverallStatus.DANGEROUS,
                f"評価スコアが極めて低いカテゴリ (最小 {min_score:.1f} 点) が存在するため、足切りルールにより「危険」と判定されました。",
            )

        if overall_score >= 7.5:
            if critical_count > 0:
                return (
                    OverallStatus.MODERATE,
                    f"総合スコアは高得点 ({overall_score:.1f}) ですが、Critical リスクが {critical_count} 件検出されているため、安全指定から「普通」に調整されました。",
                )
            if min_score <= 4.0:
                return (
                    OverallStatus.MODERATE,
                    f"総合スコアは高得点 ({overall_score:.1f}) ですが、一部のカテゴリで低い点数 ({min_score:.1f} 点) があるため「普通」判定に調整されました。",
                )
            if not all_evaluated:
                return (
                    OverallStatus.MODERATE,
                    f"評価されたカテゴリは良好 ({overall_score:.1f} 点) ですが、一部の評価ツールが未実行のため最高判定を抑制しています。",
                )
            return (
                OverallStatus.SAFE,
                f"全体としてセキュリティ対策・プロジェクト健全性が非常に良好です ({overall_score:.1f} 点)。",
            )

        if overall_score >= 5.0:
            return (
                OverallStatus.MODERATE,
                f"一定の対策は講じられていますが、一部に改善が望まれるリスクが存在します ({overall_score:.1f} 点)。",
            )

        return (
            OverallStatus.DANGEROUS,
            f"複数のカテゴリで問題・リスクが確認されており、「危険」と判定されました ({overall_score:.1f} 点)。",
        )
