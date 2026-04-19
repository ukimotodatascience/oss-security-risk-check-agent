from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C6InsecureArtifactHandlingRule:
    """成果物の検証不在になっていないか"""

    rule_id = "C-6"
    category = "cicd"
    title = "Insecure Artifact Handling"
    severity = Severity.MEDIUM

    _UPLOAD_PATTERN = re.compile(
        r"^\s*uses\s*:\s*actions/upload-artifact@", re.IGNORECASE
    )
    _DOWNLOAD_PATTERN = re.compile(
        r"^\s*uses\s*:\s*actions/download-artifact@", re.IGNORECASE
    )
    _VERIFY_HINT_PATTERN = re.compile(
        r"\b(?:sha256sum|shasum\s+-a\s+256|gpg\s+--verify|cosign\s+verify|slsa-verifier)\b",
        re.IGNORECASE,
    )
    _RETENTION_PATTERN = re.compile(
        r"^\s*retention-days\s*:\s*(\d+)\s*$", re.IGNORECASE
    )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        workflows = target / ".github" / "workflows"
        if not workflows.exists():
            return records

        for wf in workflows.rglob("*.y*ml"):
            try:
                src = wf.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            lines = src.splitlines()
            has_upload = False
            has_download = False
            first_artifact_line = None
            retention_days = []
            for idx, line in enumerate(lines, start=1):
                if self._UPLOAD_PATTERN.search(line):
                    has_upload = True
                    if first_artifact_line is None:
                        first_artifact_line = idx
                if self._DOWNLOAD_PATTERN.search(line):
                    has_download = True
                    if first_artifact_line is None:
                        first_artifact_line = idx
                m = self._RETENTION_PATTERN.match(line)
                if m:
                    try:
                        retention_days.append(int(m.group(1)))
                    except ValueError:
                        pass

            if not (has_upload or has_download):
                continue

            has_verify = bool(self._VERIFY_HINT_PATTERN.search(src))
            rel_path = str(wf.relative_to(target))

            if has_download and not has_verify:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=first_artifact_line,
                        message="ダウンロードした成果物の完全性検証（ハッシュ/署名）が見当たりません",
                    )
                )

            if has_upload and retention_days and max(retention_days) > 30:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line=first_artifact_line,
                        message="artifact の retention-days が長すぎます（30日超）",
                    )
                )

        return records
