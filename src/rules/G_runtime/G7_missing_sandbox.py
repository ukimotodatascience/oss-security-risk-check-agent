from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G7MissingSandboxRule:
    """サンドボックスがないか"""

    rule_id = "G-7"
    category = "runtime"
    title = "Missing Sandbox"
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
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".md",
    }
    _EXEC_PATTERNS = (
        re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
        re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
        re.compile(
            r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\(", re.IGNORECASE
        ),
        re.compile(r"\bvm\.runIn(?:NewContext|Context)\s*\(", re.IGNORECASE),
    )
    _UNTRUSTED_HINT = re.compile(
        r"\b(?:user(?:_provided)?|untrusted|plugin|script|request\.|req\.|query|params|body|payload)\b",
        re.IGNORECASE,
    )
    _SANDBOX_HINT = re.compile(
        r"\b(?:sandbox|seccomp|gvisor|firejail|isolate|nsjail|chroot|runsc|wasm|vm2|jail)\b",
        re.IGNORECASE,
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._TEXT_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        has_any_sandbox_control = False
        for file_path in self._iter_candidate_files(target):
            try:
                src = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if self._SANDBOX_HINT.search(src):
                has_any_sandbox_control = True
                break

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
                if not any(p.search(stripped) for p in self._EXEC_PATTERNS):
                    continue

                prev_line = lines[idx - 2].strip() if idx > 1 else ""
                next_line = lines[idx].strip() if idx < len(lines) else ""
                context = " ".join([prev_line, stripped, next_line])
                if self._UNTRUSTED_HINT.search(context) is None:
                    continue

                sev = Severity.HIGH if not has_any_sandbox_control else Severity.MEDIUM
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=sev,
                        file_path=rel_path,
                        line=idx,
                        message=(
                            "ユーザー提供コード/拡張の実行が検出され、サンドボックス分離が不足している可能性があります"
                            if sev == Severity.HIGH
                            else "ユーザー提供コード/拡張の実行が検出されました（サンドボックス設定の有効性を確認してください）"
                        ),
                    )
                )

        return records
