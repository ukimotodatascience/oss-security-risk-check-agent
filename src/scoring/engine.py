from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

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

    def evaluate(self, repo_url: str, findings: List[Finding]) -> OverallResult:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # カテゴリごとに Finding を分類
        cat_findings: Dict[Category, List[Finding]] = {cat: [] for cat in Category}
        for f in findings:
            if f.category in cat_findings:
                cat_findings[f.category].append(f)
            else:
                cat_findings[Category.SOURCE_CODE].append(f)

        category_results: Dict[str, CategoryResult] = {}
        scores: List[float] = []

        for cat in Category:
            c_findings = cat_findings[cat]
            cat_name = CATEGORY_NAMES_JA.get(cat, cat.value)
            score, summary = self._calculate_category_score(cat, c_findings)

            cat_res = CategoryResult(
                category=cat,
                category_name=cat_name,
                score=round(score, 1),
                findings_count=len(c_findings),
                findings=c_findings,
                summary=summary,
            )
            category_results[cat.value] = cat_res
            scores.append(cat_res.score)

        # 総合スコア = 8カテゴリの平均
        overall_score = round(sum(scores) / len(scores), 1) if scores else 0.0

        # 足切りルールと総合判定
        status, status_reason = self._determine_overall_status(
            scores, overall_score, findings
        )

        return OverallResult(
            repository_url=repo_url,
            scanned_at=now_str,
            overall_score=overall_score,
            status=status,
            status_reason=status_reason,
            categories=category_results,
            all_findings=findings,
        )

    def _calculate_category_score(
        self, category: Category, findings: List[Finding]
    ) -> tuple[float, str]:
        """カテゴリごとの 0〜10 点スコア算出"""
        # Scorecard の raw_score が含まれる場合の優先集計
        scorecard_scores = [
            f.raw_score
            for f in findings
            if f.source == "scorecard" and f.raw_score is not None
        ]
        if scorecard_scores and category in (
            Category.DEPENDENCIES,
            Category.DEVELOPMENT,
            Category.CICD,
            Category.MAINTENANCE,
        ):
            base_score = sum(scorecard_scores) / len(scorecard_scores)
            summary = (
                f"OpenSSF Scorecard の評価指標 {len(scorecard_scores)} 件から算出。"
            )
            return max(0.0, min(10.0, base_score)), summary

        # 減点方式 (10.0 点から減点)
        base = 10.0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for f in findings:
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
        if len(findings) == 0:
            summary = "検出された問題・懸念点はありません。"
        else:
            summary = f"指摘事項 {len(findings)} 件 (Critical:{critical_count}, High:{high_count}, Med:{medium_count}, Low:{low_count})"

        return final_score, summary

    def _determine_overall_status(
        self, scores: List[float], overall_score: float, findings: List[Finding]
    ) -> tuple[OverallStatus, str]:
        """足切りルールと判定ロジック"""
        min_score = min(scores) if scores else 0.0
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
