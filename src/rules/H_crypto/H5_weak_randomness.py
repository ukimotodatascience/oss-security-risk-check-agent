from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class H5WeakRandomnessRule:
    """脆弱なランダム性がないか"""

    rule_id = "H-5"
    category = "crypto"
    title = "Weak Randomness"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".sh",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".md",
    }
    _WEAK_RNG_PATTERNS = (
        re.compile(r"\brandom\.random\s*\("),
        re.compile(r"\brandom\.rand(?:int|range|choice|choices)\s*\("),
        re.compile(r"\bMath\.random\s*\(", re.IGNORECASE),
        re.compile(r"\bjava\.util\.Random\b", re.IGNORECASE),
    )
    _SECRET_CONTEXT_HINT = re.compile(
        r"\b(?:token|secret|password|passwd|session|auth|apikey|api_key|nonce|otp|csrf|jwt)\b",
        re.IGNORECASE,
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._TEXT_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for file_path in self._iter_candidate_files(target):
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not any(
                    pattern.search(stripped) for pattern in self._WEAK_RNG_PATTERNS
                ):
                    continue

                prev_line = lines[idx - 2].strip() if idx > 1 else ""
                next_line = lines[idx].strip() if idx < len(lines) else ""
                context = " ".join([prev_line, stripped, next_line])
                severity = (
                    Severity.HIGH
                    if self._SECRET_CONTEXT_HINT.search(context)
                    else Severity.MEDIUM
                )

                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=severity,
                        file_path=rel_path,
                        line=idx,
                        message=(
                            "機密値生成の文脈で予測可能な乱数が利用されています"
                            if severity == Severity.HIGH
                            else "予測可能な乱数 API が検出されました（機密用途は secrets/crypto RNG を使用してください）"
                        ),
                    )
                )

        return records
