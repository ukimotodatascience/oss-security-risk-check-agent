from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G1RunsAsRootRule:
    """root権限で実行されていないか"""

    rule_id = "G-1"
    category = "runtime"
    title = "Runs as Root"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {".yml", ".yaml", ".json", ".env", ".conf", ".ini", ".txt", ".md"}
    _USER_ROOT_PATTERN = re.compile(r"^\s*USER\s+(?:root|0)(?:\b|:)", re.IGNORECASE)
    _USER_SET_PATTERN = re.compile(r"^\s*USER\s+", re.IGNORECASE)
    _COMPOSE_ROOT_PATTERN = re.compile(
        r"^\s*user\s*:\s*[\"']?(?:root|0(?::0)?)\b", re.IGNORECASE
    )
    _K8S_RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser\s*:\s*0\b", re.IGNORECASE)

    def _iter_dockerfiles(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.name.lower().startswith("dockerfile"):
                yield p

    def _iter_runtime_text_files(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._TEXT_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for dockerfile in self._iter_dockerfiles(target):
            try:
                lines = dockerfile.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(dockerfile.relative_to(target))
            user_line = None
            root_line = None
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if self._USER_SET_PATTERN.search(stripped):
                    user_line = idx
                if self._USER_ROOT_PATTERN.search(stripped):
                    root_line = idx

            if root_line is not None:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=root_line,
                        message="Dockerfile で root ユーザー実行が明示されています",
                    )
                )
            elif user_line is None:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line=1,
                        message="Dockerfile に USER 指定がなく、root 実行となる可能性があります",
                    )
                )

        for file_path in self._iter_runtime_text_files(target):
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if self._COMPOSE_ROOT_PATTERN.search(
                    stripped
                ) or self._K8S_RUN_AS_ROOT_PATTERN.search(stripped):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=idx,
                            message="コンテナ実行ユーザーが root (UID 0) に設定されている可能性があります",
                        )
                    )

        return records
