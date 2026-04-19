from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class E3WeakJWTValidationRule:
    """脆弱なJWT検証がないか"""

    rule_id = "E-3"
    category = "auth"
    title = "Weak JWT Validation"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
    }
    _JWT_USAGE_PATTERN = re.compile(
        r"(?i)(?:jwt\.|jsonwebtoken|pyjwt|jws|decode\(|verify\(|parseClaimsJws|JwtParser)"
    )
    _HIGH_RISK_PATTERNS = (
        re.compile(r"(?i)algorithms?\s*=\s*\[[^\]]*none[^\]]*\]"),
        re.compile(r"(?i)algorithm\s*[:=]\s*[\"']none[\"']"),
        re.compile(r"(?i)verify(?:_signature)?\s*[:=]\s*(?:false|0)"),
        re.compile(r"(?i)options\s*=\s*\{[^\}]*verify_signature\s*[:=]\s*(?:false|0)"),
    )
    _MEDIUM_RISK_PATTERNS = (
        re.compile(r"(?i)jwt\.decode\([^\)]*\)"),
        re.compile(r"(?i)jsonwebtoken\.verify\([^\)]*\)"),
        re.compile(r"(?i)parseClaimsJws\([^\)]*\)"),
    )
    _SAFE_HINT_PATTERN = re.compile(
        r"(?i)(?:algorithms?\s*=\s*\[[^\]]*(?:hs256|rs256|es256)[^\]]*\]|issuer\s*=|audience\s*=|require\(|verify_signature\s*[:=]\s*true|secret|public[_-]?key|cert)"
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
                if not self._JWT_USAGE_PATTERN.search(stripped):
                    continue

                window_start = max(0, idx - 3)
                window_end = min(len(lines), idx + 4)
                context = "\n".join(lines[window_start:window_end])

                if any(pat.search(context) for pat in self._HIGH_RISK_PATTERNS):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=idx,
                            message="JWT 検証で none アルゴリズム許可または署名検証無効化の可能性があります",
                        )
                    )
                    continue

                if any(
                    pat.search(stripped) for pat in self._MEDIUM_RISK_PATTERNS
                ) and not self._SAFE_HINT_PATTERN.search(context):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="JWT の検証パラメータ（許可アルゴリズム/鍵/検証オプション）が不十分な可能性があります",
                        )
                    )

        return records
