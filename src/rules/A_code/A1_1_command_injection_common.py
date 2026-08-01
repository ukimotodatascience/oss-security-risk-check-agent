from typing import Iterable, List, Optional

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
    _SEVERITY_ORDER = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }

    def get_sink_type_key(message: str) -> str:
        msg_lower = message.lower()
        if "spawn" in msg_lower:
            return "spawn"
        if "file execution" in msg_lower:
            return "file_execution"
        if "command execution helper" in msg_lower:
            return "helper"
        if "command execution" in msg_lower:
            return "command_execution"
        if "eval" in msg_lower:
            return "eval"
        if "-c execution" in msg_lower:
            return "dash_c"
        if "backtick" in msg_lower:
            return "backtick_substitution"
        if "$()" in msg_lower:
            return "dollar_paren_substitution"
        if "command substitution" in msg_lower:
            return "substitution"
        if "source execution" in msg_lower:
            return "source"
        if "here-string" in msg_lower:
            return "here_string"
        if "command name execution" in msg_lower:
            return "command_name"
        return msg_lower

    merged = {}
    counts = {}
    for record in records:
        sink_type = get_sink_type_key(record.message or "")
        counter_key = (record.file_path, record.line, sink_type)
        idx = counts.get(counter_key, 0)
        counts[counter_key] = idx + 1

        key = (record.file_path, record.line, record.rule_id, sink_type, idx)
        if key not in merged:
            merged[key] = record
        else:
            existing = merged[key]
            p_existing = _SEVERITY_ORDER.get(existing.severity, 0)
            p_new = _SEVERITY_ORDER.get(record.severity, 0)
            if p_new > p_existing:
                merged[key] = record
            elif p_new == p_existing:
                if len(record.message or "") > len(existing.message or ""):
                    merged[key] = record

    unique: List[RiskRecord] = []
    seen = set()
    counts_for_unique = {}
    for r in records:
        sink_type = get_sink_type_key(r.message or "")
        counter_key = (r.file_path, r.line, sink_type)
        idx = counts_for_unique.get(counter_key, 0)
        counts_for_unique[counter_key] = idx + 1

        key = (r.file_path, r.line, r.rule_id, sink_type, idx)
        if key in seen:
            continue
        seen.add(key)
        unique.append(merged[key])
    return unique
