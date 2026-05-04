from src.rules.A_code.A1_3_1_command_injection_js_ts_sources import JsTsSourceMixin
from src.rules.A_code.A1_3_2_command_injection_js_ts_sinks import JsTsSinkMixin
from src.rules.A_code.A1_4_1_command_injection_shell_sources import ShellSourceMixin


def test_js_external_input_tokens_and_tainted_names():
    helper = JsTsSourceMixin()

    assert helper._js_has_external_input("req.query.cmd", set())
    assert helper._js_has_external_input("exec(cmd)", {"cmd"})
    assert not helper._js_has_external_input("exec('date')", {"cmd"})


def test_registers_child_process_aliases():
    helper = JsTsSinkMixin()
    sinks: set[str] = set()

    helper._register_child_process_imports(
        'const cp = require("node:child_process");',
        sinks,
    )

    assert "cp.exec" in sinks
    assert helper._is_child_process_alias_assignment("cp.exec", sinks)


def test_tracks_read_and_assignment_taint():
    helper = ShellSourceMixin()
    tainted: set[str] = set()

    helper._track_shell_taint_from_text("read cmd", tainted)
    helper._track_shell_taint_from_text('wrapped="$cmd"', tainted)

    assert "cmd" in tainted
    assert "wrapped" in tainted
    assert helper._shell_expands_external_input("eval $wrapped", tainted)
