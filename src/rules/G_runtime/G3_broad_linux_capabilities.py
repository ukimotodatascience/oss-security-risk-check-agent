from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G3BroadLinuxCapabilitiesRule:
    """広範囲のLinux Capabilitiesがないか"""

    rule_id = "G-3"
    category = "runtime"
    title = "Broad Linux Capabilities"
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
    _DANGEROUS_CAPS = r"(?:CAP_)?(?:ALL|SYS_ADMIN|SYS_MODULE|SYS_PTRACE|NET_ADMIN|SYS_RAWIO|DAC_READ_SEARCH|DAC_OVERRIDE)"
    _PATTERNS = (
        (
            "過剰な Linux capability",
            re.compile(
                r"\b--cap-add(?:=|\s+)" + _DANGEROUS_CAPS + r"\b", re.IGNORECASE
            ),
            Severity.HIGH,
        ),
        (
            "過剰な Linux capability",
            re.compile(
                r"\b(?:cap_add|capabilities|securityContext)\b[^\n\r]*"
                + _DANGEROUS_CAPS,
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "過剰な Linux capability",
            re.compile(r"^\s*-\s*" + _DANGEROUS_CAPS + r"\b", re.IGNORECASE),
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
                                message=f"{label} の設定が検出されました（最小権限原則を確認してください）",
                            )
                        )
                        break

        return records
