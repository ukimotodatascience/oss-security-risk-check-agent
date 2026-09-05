from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Category(str, Enum):
    KNOWN_VULNERABILITIES = "known_vulnerabilities"
    SECRETS = "secrets"
    MISCONFIGURATION = "misconfiguration"
    DEPENDENCIES = "dependencies"
    DEVELOPMENT = "development"
    CICD = "cicd"
    MAINTENANCE = "maintenance"
    SOURCE_CODE = "source_code"


CATEGORY_NAMES_JA: Dict[Category, str] = {
    Category.KNOWN_VULNERABILITIES: "既知脆弱性",
    Category.SECRETS: "機密情報・Secret管理",
    Category.MISCONFIGURATION: "設定セキュリティ",
    Category.DEPENDENCIES: "依存関係・Supply Chain",
    Category.DEVELOPMENT: "開発・変更管理",
    Category.CICD: "CI/CD・リリースセキュリティ",
    Category.MAINTENANCE: "プロジェクト保守・セキュリティ体制",
    Category.SOURCE_CODE: "ソースコードセキュリティ",
}


class OverallStatus(str, Enum):
    SAFE = "安全"
    MODERATE = "普通"
    DANGEROUS = "危険"


class Finding(BaseModel):
    category: Category
    source: str  # "trivy", "scorecard", "rule_based"
    rule_id: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    title: str
    target: Optional[str] = None
    location: Optional[str] = None
    description: str = ""
    remediation: Optional[str] = None
    raw_score: Optional[float] = None


class CategoryResult(BaseModel):
    category: Category
    category_name: str
    score: float  # 0.0 ~ 10.0
    evaluated: bool = True
    findings_count: int = 0
    findings: List[Finding] = Field(default_factory=list)
    summary: str = ""


class OverallResult(BaseModel):
    repository_url: str
    scanned_at: str
    overall_score: float  # 0.0 ~ 10.0
    status: OverallStatus
    status_reason: str = ""
    categories: Dict[str, CategoryResult] = Field(default_factory=dict)
    all_findings: List[Finding] = Field(default_factory=list)
