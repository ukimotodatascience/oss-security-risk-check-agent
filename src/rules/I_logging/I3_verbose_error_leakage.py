from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class I3VerboseErrorLeakageRule:
    """詳細なエラー情報が漏れていないか"""

    rule_id = "I-3"
    category = "logging"
    title = "Verbose Error Leakage"
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
        ".yml",
        ".yaml",
    }
    _EXCEPTION_RESPONSE_PATTERN = re.compile(
        r"(?i)(?:return|respond|res\.|jsonify|HttpResponse|Response)[^\n]*(?:str\(e\)|repr\(e\)|traceback|stack\s*trace|exc_info|exception)"
    )
    _PATH_LEAK_PATTERN = re.compile(
        r"(?i)(?:/home/|/usr/|/var/|[A-Za-z]:\\\\|site-packages|Traceback \(most recent call last\))"
    )
    _DEBUG_HINT_PATTERN = re.compile(
        r"(?i)\b(?:debug\s*=\s*True|app\.debug\s*=\s*True|NODE_ENV\s*=\s*development|FLASK_DEBUG\s*=\s*1)"
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
                if not stripped:
                    continue
                if not (
                    self._EXCEPTION_RESPONSE_PATTERN.search(stripped)
                    or self._PATH_LEAK_PATTERN.search(stripped)
                ):
                    continue

                window_start = max(0, idx - 4)
                window_end = min(len(lines), idx + 3)
                context = "\n".join(lines[window_start:window_end])
                sev = (
                    Severity.HIGH
                    if self._DEBUG_HINT_PATTERN.search(context)
                    or self._PATH_LEAK_PATTERN.search(stripped)
                    else Severity.MEDIUM
                )
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=sev,
                        file_path=rel_path,
                        line=idx,
                        message="スタックトレースや内部実装情報をユーザー向けレスポンスへ返している可能性があります",
                    )
                )

        return records
