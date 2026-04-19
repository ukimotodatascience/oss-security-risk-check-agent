from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class H6ExpiredOrMissingTLSDocsRule:
    """TLS証明書の有効期限が切れていないか"""

    rule_id = "H-6"
    category = "crypto"
    title = "Expired or Missing TLS Docs"
    severity = Severity.MEDIUM

    _DOC_FILE_PATTERNS = (
        re.compile(
            r"(?:^|[\\/])(?:README|SECURITY|TLS|SSL|CERTIFICATE|CERTS)(?:\.[^\\/]*)?$",
            re.IGNORECASE,
        ),
        re.compile(r"(?:^|[\\/])docs?[\\/].*(?:tls|ssl|cert)", re.IGNORECASE),
    )
    _DOC_EXTS = {".md", ".rst", ".txt", ".adoc", ".yml", ".yaml"}
    _EXPIRED_HINT = re.compile(
        r"\b(?:expired|期限切れ|失効|not\s+valid\s+after|certificate\s+expired)\b",
        re.IGNORECASE,
    )
    _TLS_OPERATION_HINT = re.compile(
        r"\b(?:tls|ssl|certificate|cert|renew|rotation|acme|letsencrypt)\b",
        re.IGNORECASE,
    )

    def _iter_doc_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in self._DOC_EXTS:
                continue
            rel = str(p.relative_to(target)).replace("\\", "/")
            if any(pattern.search(rel) for pattern in self._DOC_FILE_PATTERNS):
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        doc_files = list(self._iter_doc_files(target))

        if not doc_files:
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=None,
                    line=None,
                    message="TLS/証明書運用に関するドキュメントが見つかりませんでした",
                )
            )
            return records

        has_tls_operation_doc = False

        for doc in doc_files:
            try:
                lines = doc.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            rel_path = str(doc.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                if self._TLS_OPERATION_HINT.search(stripped):
                    has_tls_operation_doc = True

                if self._EXPIRED_HINT.search(stripped):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=idx,
                            message="TLS 証明書の期限切れを示唆する記述が検出されました",
                        )
                    )

        if not has_tls_operation_doc:
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=None,
                    line=None,
                    message="TLS 証明書更新や運用手順を示す記述が不足している可能性があります",
                )
            )

        return records
