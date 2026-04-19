from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G5ExposedCodeExecutionRule:
    """コード実行が外部から制御可能になっていないか"""

    rule_id = "G-5"
    category = "runtime"
    title = "Exposed Code Execution"
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
        ".md",
    }
    _RCE_PATTERNS = (
        re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
        re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
        re.compile(
            r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\(", re.IGNORECASE
        ),
        re.compile(
            r"\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(", re.IGNORECASE
        ),
    )
    _EXTERNAL_INPUT_HINT = re.compile(
        r"\b(?:request\.|req\.|query\b|params\b|body\b|input\(|stdin\b|argv\b|webhook\b|payload\b)"
    )
    _NO_AUTH_HINT = re.compile(
        r"\b(?:without\s+auth|no\s+auth|unauthenticated|public\s+endpoint|allow_anonymous)\b",
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

                if not any(p.search(stripped) for p in self._RCE_PATTERNS):
                    continue

                prev_line = lines[idx - 2].strip() if idx > 1 else ""
                next_line = lines[idx].strip() if idx < len(lines) else ""
                context = " ".join([prev_line, stripped, next_line])
                has_external_input = (
                    self._EXTERNAL_INPUT_HINT.search(context) is not None
                )
                no_auth_hint = self._NO_AUTH_HINT.search(context) is not None
                severity = (
                    Severity.HIGH
                    if (has_external_input or no_auth_hint)
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
                            "外部入力/認証不足の文脈でコード実行 API が利用されている可能性があります"
                            if severity == Severity.HIGH
                            else "コード実行 API が利用されています（公開経路での利用は避けてください）"
                        ),
                    )
                )

        return records
