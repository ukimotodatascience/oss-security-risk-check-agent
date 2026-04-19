from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G2PrivilegedContainerRule:
    """特権コンテナがないか"""

    rule_id = "G-2"
    category = "runtime"
    title = "Privileged Container"
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
    _PATTERNS = (
        (
            "特権フラグ",
            re.compile(r"\b(?:docker|podman)\b[^\n\r]*\s--privileged\b", re.IGNORECASE),
            Severity.HIGH,
        ),
        (
            "特権モード",
            re.compile(
                r"^\s*privileged\s*:\s*(?:true|\"true\"|'true')\b", re.IGNORECASE
            ),
            Severity.HIGH,
        ),
        (
            "危険なデバイスマウント",
            re.compile(
                r"\b(?:--device\s*=\s*|--device\s+)(?:/dev/|/dev$)", re.IGNORECASE
            ),
            Severity.MEDIUM,
        ),
        (
            "危険なデバイスマウント",
            re.compile(r"^\s*devices\s*:\s*$", re.IGNORECASE),
            Severity.MEDIUM,
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
                                message=f"{label} が検出されました（不要な特権付与を避けてください）",
                            )
                        )
                        break

        return records
