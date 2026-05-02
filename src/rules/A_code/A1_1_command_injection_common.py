from typing import Iterable, List, Optional, Set, Tuple

from src.models import RiskRecord, Severity


RULE_ID = "A-1"
CATEGORY = "code"
TITLE = "Command Injection"
DEFAULT_SEVERITY = Severity.MEDIUM

_SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh"}


def ts_node_text(src_bytes: bytes, node: object) -> str:
    start = getattr(node, "start_byte", 0)
    end = getattr(node, "end_byte", 0)
    return src_bytes[start:end].decode("utf-8", errors="ignore")


def iter_ts_nodes(node: object) -> Iterable[object]:
    yield node
    for child in getattr(node, "children", []):
        yield from iter_ts_nodes(child)


def ts_child_by_field_name(node: object, field_name: str) -> Optional[object]:
    child_by_field_name = getattr(node, "child_by_field_name", None)
    if not child_by_field_name:
        return None
    return child_by_field_name(field_name)


def get_tree_sitter_parser(suffix: str) -> Optional[object]:
    try:
        from tree_sitter_languages import get_parser  # type: ignore
    except Exception:
        return None

    for language in tree_sitter_language_candidates(suffix):
        try:
            return get_parser(language)
        except Exception:
            continue
    return None


def tree_sitter_language_candidates(suffix: str) -> List[str]:
    if suffix in {".tsx", ".jsx"}:
        return ["tsx", "typescript", "javascript"]
    if suffix == ".ts":
        return ["typescript"]
    if suffix in _SHELL_EXTENSIONS:
        return ["bash"]
    return ["javascript"]


def dedupe_records(records: List[RiskRecord]) -> List[RiskRecord]:
    seen: Set[Tuple[Optional[str], Optional[int], str, Severity]] = set()
    unique: List[RiskRecord] = []
    for record in records:
        key = (
            record.file_path,
            record.line,
            record.message or "",
            record.severity,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique
