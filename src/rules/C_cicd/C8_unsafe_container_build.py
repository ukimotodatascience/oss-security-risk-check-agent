from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C8UnsafeContainerBuildRule:
    """危険なコンテナビルドがないか"""

    rule_id = "C-8"
    category = "cicd"
    title = "Unsafe Container Build"
    severity = Severity.MEDIUM

    _DOCKER_BUILD_PATTERN = re.compile(r"\bdocker\s+build\b", re.IGNORECASE)
    _HOST_NETWORK_PATTERN = re.compile(r"--network(?:=|\s+)host\b", re.IGNORECASE)
    _FROM_PATTERN = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE)

    def _is_untrusted_base(self, image_ref: str) -> bool:
        ref = image_ref.strip().lower()
        if "@sha256:" in ref:
            return False
        if ref.startswith(("gcr.io/", "ghcr.io/", "mcr.microsoft.com/", "docker.io/")):
            return False
        if "/" not in ref:
            # 公式イメージの可能性はあるが、タグ固定なしは注意
            return True
        return True

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for p in target.rglob("*"):
            if not p.is_file():
                continue

            name_low = p.name.lower()
            is_dockerfile = name_low == "dockerfile" or name_low.startswith(
                "dockerfile."
            )
            is_workflow = p.suffix.lower() in {".yml", ".yaml"} and ".github" in str(p)
            if not (is_dockerfile or is_workflow):
                continue

            try:
                lines = p.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(p.relative_to(target))

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if self._DOCKER_BUILD_PATTERN.search(
                    stripped
                ) and self._HOST_NETWORK_PATTERN.search(stripped):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=idx,
                            message="docker build で --network=host が指定されています",
                        )
                    )

                m = self._FROM_PATTERN.match(stripped)
                if m and self._is_untrusted_base(m.group(1)):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="信頼性確認が難しいベースイメージ参照です（digest pin を推奨）",
                        )
                    )

        return records
