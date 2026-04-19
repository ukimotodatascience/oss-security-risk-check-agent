from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G4HostMountRiskRule:
    """ホストマウントの危険性がないか"""

    rule_id = "G-4"
    category = "runtime"
    title = "Host Mount Risk"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {
        ".yml",
        ".yaml",
        ".json",
        ".env",
        ".conf",
        ".ini",
        ".txt",
        ".md",
        ".sh",
    }
    _SENSITIVE_HOST_PATH = (
        r"(?:/|/etc|/root|/home|/var|/proc|/sys|/boot|/var/run/docker\.sock)"
    )
    _PATTERNS = (
        (
            "危険なホストマウント",
            re.compile(
                r"\b(?:docker|podman)\b[^\n\r]*\s(?:-v|--volume)\s*=?\s*"
                + _SENSITIVE_HOST_PATH
                + r"(?::|\s|$)",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "危険なホストマウント",
            re.compile(
                r"^\s*-\s*" + _SENSITIVE_HOST_PATH + r"\s*:[^\n\r]+",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "危険な hostPath マウント",
            re.compile(r"^\s*hostPath\s*:\s*$", re.IGNORECASE),
            Severity.MEDIUM,
        ),
        (
            "危険な hostPath マウント",
            re.compile(
                r"^\s*path\s*:\s*" + _SENSITIVE_HOST_PATH + r"\b", re.IGNORECASE
            ),
            Severity.HIGH,
        ),
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

                for label, pattern, sev in self._PATTERNS:
                    if pattern.search(stripped):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=sev,
                                file_path=rel_path,
                                line=idx,
                                message=f"{label} が検出されました（ホスト機密領域の直接マウントを避けてください）",
                            )
                        )
                        break

        return records
