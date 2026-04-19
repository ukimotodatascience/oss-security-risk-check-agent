from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity


class J7MissingSbomRule:
    """SBOMが不足していないか"""

    rule_id = "J-7"
    category = "maintenance"
    title = "Missing SBOM"
    severity = Severity.MEDIUM

    _SUPPORTED_SBOM_FILES = (
        "sbom.json",  # CycloneDX / SPDX JSON
        "sbom.xml",  # CycloneDX XML
        "bom.json",
        "bom.xml",
        "cyclonedx.json",
        "cyclonedx.xml",
        "spdx.json",
        "spdx.yaml",
        "spdx.yml",
        "spdx.spdx",
    )

    _SBOM_DIRS = (
        "sbom",
        "sboms",
        ".github",
        "docs",
    )

    def _find_sbom_files(self, target: Path) -> List[Path]:
        found: List[Path] = []

        for name in self._SUPPORTED_SBOM_FILES:
            p = target / name
            if p.is_file():
                found.append(p)

        for rel_dir in self._SBOM_DIRS:
            d = target / rel_dir
            if not d.is_dir():
                continue
            for p in d.rglob("*"):
                if not p.is_file():
                    continue
                lowered = p.name.lower()
                if "sbom" in lowered or "cyclonedx" in lowered or "spdx" in lowered:
                    found.append(p)

        # 重複排除（順序維持）
        unique: List[Path] = []
        seen: set[str] = set()
        for p in found:
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        return unique

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        sbom_files = self._find_sbom_files(target)

        if not sbom_files:
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=None,
                    line=None,
                    message="SBOM（CycloneDX/SPDX）ファイルが見つかりませんでした",
                )
            )
            return records

        # 拡張子が想定外の SBOM 名ファイルを注意喚起
        allowed_exts = {".json", ".xml", ".yml", ".yaml", ".spdx"}
        for p in sbom_files:
            ext = p.suffix.lower()
            if ext and ext not in allowed_exts:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.LOW,
                        file_path=str(p.relative_to(target)),
                        line=1,
                        message="SBOM らしきファイルですが形式が想定外です（json/xml/yaml/spdx 推奨）",
                    )
                )

        return records
