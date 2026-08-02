from typing import Iterable, List, Optional, Tuple

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


def line_col_to_offset(src: str, line_1indexed: int, col_0indexed: int) -> int:
    lines = src.splitlines(keepends=True)
    offset = 0
    for i in range(line_1indexed - 1):
        if i < len(lines):
            offset += len(lines[i])
    return offset + col_0indexed


def offset_to_line_col(src: str, offset: int) -> Tuple[int, int]:
    lines = src.splitlines(keepends=True)
    curr_offset = 0
    for idx, line in enumerate(lines):
        if curr_offset <= offset < curr_offset + len(line):
            return idx + 1, offset - curr_offset
        curr_offset += len(line)
    return len(lines), len(lines[-1]) if lines else 0


def dedupe_records(records: List[RiskRecord]) -> List[RiskRecord]:
    _SEVERITY_ORDER = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }

    # 1. 同一解析元内での完全重複レコードの排除
    raw_records = []
    seen_raw = set()
    for r in records:
        key = (
            r.file_path,
            r.line,
            r.message or "",
            r.severity,
            getattr(r, "_char_offset", None),
            getattr(r, "_column", None),
            getattr(r, "_from_ts", False),
        )
        if key in seen_raw:
            continue
        seen_raw.add(key)
        raw_records.append(r)

    def get_sink_type_key(message: str) -> str:
        msg_lower = message.lower()
        if "spawn" in msg_lower:
            return "spawn"
        if "file execution" in msg_lower:
            return "file_execution"
        if "command execution helper" in msg_lower:
            return "command_execution"
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

    ts_records = [r for r in raw_records if getattr(r, "_from_ts", False)]
    regex_records = [r for r in raw_records if not getattr(r, "_from_ts", False)]

    ts_groups = {}
    for r in ts_records:
        sink_type = get_sink_type_key(r.message or "")
        g_key = (r.file_path, r.rule_id, sink_type)
        ts_groups.setdefault(g_key, []).append(r)

    regex_groups = {}
    for r in regex_records:
        sink_type = get_sink_type_key(r.message or "")
        g_key = (r.file_path, r.rule_id, sink_type)
        regex_groups.setdefault(g_key, []).append(r)

    all_keys_ordered = []
    seen_keys = set()
    for r in raw_records:
        sink_type = get_sink_type_key(r.message or "")
        g_key = (r.file_path, r.rule_id, sink_type)
        if g_key not in seen_keys:
            seen_keys.add(g_key)
            all_keys_ordered.append(g_key)

    unique: List[RiskRecord] = []
    for g_key in all_keys_ordered:
        ts_list = ts_groups.get(g_key, [])
        regex_list = regex_groups.get(g_key, [])

        if ts_list and regex_list:
            matched_regex_indices = set()
            for ts_rec in ts_list:
                ts_offset = getattr(ts_rec, "_char_offset", None)
                if ts_offset is None:
                    close_regex_rec = regex_list[0] if regex_list else None
                    if close_regex_rec:
                        matched_regex_indices.add(0)
                else:
                    close_regex_rec = None
                    for idx_reg, reg_rec in enumerate(regex_list):
                        reg_offset = getattr(reg_rec, "_char_offset", None)
                        if reg_offset is not None and abs(ts_offset - reg_offset) <= 2:
                            close_regex_rec = reg_rec
                            matched_regex_indices.add(idx_reg)
                            break

                if close_regex_rec:
                    if _SEVERITY_ORDER.get(
                        close_regex_rec.severity, 0
                    ) > _SEVERITY_ORDER.get(ts_rec.severity, 0):
                        ts_rec.severity = close_regex_rec.severity
                        ts_rec.message = close_regex_rec.message

            unique.extend(ts_list)
            for idx_reg, reg_rec in enumerate(regex_list):
                if idx_reg not in matched_regex_indices:
                    unique.append(reg_rec)
        elif ts_list:
            unique.extend(ts_list)
        elif regex_list:
            unique.extend(regex_list)

    return unique
