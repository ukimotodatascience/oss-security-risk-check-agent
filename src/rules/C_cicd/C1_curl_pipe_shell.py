from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C1CurlPipeShellRule:
    """curl | shやwget | bashなどの危険なコマンド実行がないか"""

    rule_id = "C-1"
    category = "cicd"
    title = "Curl Pipe Shell"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".yml",
        ".yaml",
        ".mk",
        ".txt",
    }

    _DIRECT_EXEC_PATTERN = re.compile(
        r"\b(?:curl|wget)\b[^\n\r]*\|\s*(?:sh|bash|zsh|ksh)\b",
        re.IGNORECASE,
    )
    _DOWNLOAD_ONLY_PATTERN = re.compile(
        r"\b(?:curl|wget)\b[^\n\r]*(?:-o|--output|>)[^\n\r]+",
        re.IGNORECASE,
    )
    _VERIFY_HINT_PATTERN = re.compile(
        r"\b(?:sha256sum|shasum\s+-a\s+256|gpg\s+--verify|cosign\s+verify)\b",
        re.IGNORECASE,
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if p.name.lower().startswith("makefile"):
                yield p
                continue
            if p.suffix.lower() in self._TEXT_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for file_path in self._iter_candidate_files(target):
            try:
                src = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(target))
            lines = src.splitlines()
            has_verify_hint = bool(self._VERIFY_HINT_PATTERN.search(src))

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if self._DIRECT_EXEC_PATTERN.search(stripped):
                    sev = Severity.MEDIUM if has_verify_hint else Severity.HIGH
                    msg = (
                        "外部取得スクリプトを検証後にシェル実行しています（検証手順の十分性を確認してください）"
                        if has_verify_hint
                        else "外部取得スクリプトを検証せずシェルに直接パイプ実行しています"
                    )
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=sev,
                            file_path=rel_path,
                            line=idx,
                            message=msg,
                        )
                    )
                    continue

                if self._DOWNLOAD_ONLY_PATTERN.search(stripped):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="外部スクリプトをダウンロードしています。実行時はハッシュ/署名検証を行ってください",
                        )
                    )

        return records
