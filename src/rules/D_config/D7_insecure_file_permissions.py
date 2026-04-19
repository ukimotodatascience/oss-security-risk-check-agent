from pathlib import Path
import stat
from typing import List
from src.models import RiskRecord, Severity


class D7InsecureFilePermissionsRule:
    """危険なファイルパーミッションがないか"""

    rule_id = "D-7"
    category = "config"
    title = "Insecure File Permissions"
    severity = Severity.MEDIUM

    _SENSITIVE_SUFFIXES = {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".kdb",
    }
    _SENSITIVE_NAME_HINTS = (
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "private_key",
        "secret",
        "credentials",
        "token",
    )

    def _is_sensitive_file(self, p: Path) -> bool:
        name = p.name.lower()
        if p.suffix.lower() in self._SENSITIVE_SUFFIXES:
            return True
        return any(hint in name for hint in self._SENSITIVE_NAME_HINTS)

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for p in target.rglob("*"):
            if not p.is_file() or not self._is_sensitive_file(p):
                continue

            try:
                mode = p.stat().st_mode
            except OSError:
                continue

            rel_path = str(p.relative_to(target))
            world_readable = bool(mode & stat.S_IROTH)
            world_writable = bool(mode & stat.S_IWOTH)
            group_writable = bool(mode & stat.S_IWGRP)

            if world_writable:
                sev = Severity.HIGH
                msg = (
                    "機密ファイルが world-writable です。アクセス権を厳格化してください"
                )
            elif world_readable:
                sev = Severity.HIGH
                msg = (
                    "機密ファイルが world-readable です。アクセス権を厳格化してください"
                )
            elif group_writable:
                sev = Severity.MEDIUM
                msg = "機密ファイルが group-writable です。不要な書き込み権限を削除してください"
            else:
                continue

            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=sev,
                    file_path=rel_path,
                    line=1,
                    message=msg,
                )
            )

        return records
