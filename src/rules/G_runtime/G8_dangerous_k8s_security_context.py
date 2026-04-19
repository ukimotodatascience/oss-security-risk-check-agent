from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class G8DangerousK8SSecurityContextRule:
    """危険なK8S Security Contextがないか"""

    rule_id = "G-8"
    category = "runtime"
    title = "Dangerous K8S Security Context"
    severity = Severity.MEDIUM

    _K8S_EXTS = {".yml", ".yaml", ".json"}
    _K8S_FILE_HINT = re.compile(
        r"(?:k8s|kubernetes|deployment|daemonset|statefulset|pod|helm|chart)",
        re.IGNORECASE,
    )
    _DANGEROUS_PATTERNS = (
        (
            "runAsUser: 0",
            re.compile(r"^\s*runAsUser\s*:\s*0\b", re.IGNORECASE),
            Severity.HIGH,
        ),
        (
            "privileged: true",
            re.compile(
                r"^\s*privileged\s*:\s*(?:true|\"true\"|'true')\b", re.IGNORECASE
            ),
            Severity.HIGH,
        ),
        (
            "allowPrivilegeEscalation: true",
            re.compile(
                r"^\s*allowPrivilegeEscalation\s*:\s*(?:true|\"true\"|'true')\b",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "hostPID/hostIPC/hostNetwork",
            re.compile(
                r"^\s*(?:hostPID|hostIPC|hostNetwork)\s*:\s*(?:true|\"true\"|'true')\b",
                re.IGNORECASE,
            ),
            Severity.MEDIUM,
        ),
        (
            "危険な capabilities 追加",
            re.compile(
                r"\b(?:CAP_)?(?:ALL|SYS_ADMIN|SYS_MODULE|SYS_PTRACE|NET_ADMIN)\b",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in self._K8S_EXTS:
                continue
            rel = str(p.relative_to(target))
            if self._K8S_FILE_HINT.search(rel):
                yield p
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="ignore")[:2000]
            except OSError:
                continue
            if re.search(r"\b(?:apiVersion|kind|securityContext)\b", head):
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

                for label, pattern, sev in self._DANGEROUS_PATTERNS:
                    if not pattern.search(stripped):
                        continue
                    if (
                        "CAP_" in stripped.upper()
                        or "capabilities" in stripped.lower()
                        or label != "危険な capabilities 追加"
                    ):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=sev,
                                file_path=rel_path,
                                line=idx,
                                message=f"Kubernetes SecurityContext で {label} が検出されました",
                            )
                        )
                        break

        return records
