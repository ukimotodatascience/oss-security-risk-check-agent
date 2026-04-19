from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G6UnsafePluginExecutionRule:
    """危険なプラグイン実行がないか"""

    rule_id = "G-6"
    category = "runtime"
    title = "Unsafe Plugin Execution"
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
    _PLUGIN_LOAD_PATTERNS = (
        re.compile(r"\bimportlib\.import_module\s*\(", re.IGNORECASE),
        re.compile(r"\b__import__\s*\(", re.IGNORECASE),
        re.compile(r"\brequire\s*\([^\)]*plugin", re.IGNORECASE),
        re.compile(r"\bdlopen\s*\(", re.IGNORECASE),
        re.compile(r"\bload_plugin\b", re.IGNORECASE),
    )
    _UNTRUSTED_SOURCE_HINT = re.compile(
        r"\b(?:plugin_url|remote|download|http://|https://|request\.|req\.|query|params|env\[|os\.environ)\b",
        re.IGNORECASE,
    )
    _VERIFY_HINT = re.compile(
        r"\b(?:signature|signed|verify|checksum|sha256|gpg|cosign|allowlist|whitelist)\b",
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
                src = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            lines = src.splitlines()
            has_verify_control = self._VERIFY_HINT.search(src) is not None
            rel_path = str(file_path.relative_to(target))

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not any(p.search(stripped) for p in self._PLUGIN_LOAD_PATTERNS):
                    continue

                prev_line = lines[idx - 2].strip() if idx > 1 else ""
                next_line = lines[idx].strip() if idx < len(lines) else ""
                context = " ".join([prev_line, stripped, next_line])
                untrusted_hint = self._UNTRUSTED_SOURCE_HINT.search(context) is not None
                sev = (
                    Severity.HIGH
                    if (untrusted_hint and not has_verify_control)
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
                        message=(
                            "未検証のプラグイン動的ロードが行われている可能性があります"
                            if sev == Severity.HIGH
                            else "プラグインの動的ロードが検出されました（署名検証/サンドボックスを確認してください）"
                        ),
                    )
                )

        return records
