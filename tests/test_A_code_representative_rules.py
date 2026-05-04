from src.models import Severity
from src.rules.A_code.A1_command_injection import A1CommandInjectionRule
from src.rules.A_code.A2_sql_injection import A2SqlInjectionRule
from src.rules.A_code.A3_unsafe_deserialization import A3UnsafeDeserializationRule
from src.rules.A_code.A4_path_traversal import A4PathTraversalRule
from src.rules.A_code.A5_ssrf import A5SsrfRule
from src.rules.A_code.A6_xss import A6XssRule
from src.rules.A_code.A7_template_injection import A7TemplateInjectionRule
from src.rules.A_code.A8_unsafe_eval import A8UnsafeEvalRule


def test_A1_detects_os_system_from_external_input(tmp_path):
    (tmp_path / "app.py").write_text(
        """
import os

cmd = input()
os.system(cmd)
""",
        encoding="utf-8",
    )

    records = A1CommandInjectionRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-1"
    assert records[0].severity == Severity.HIGH


def test_A1_ignores_os_system_constant_command(tmp_path):
    (tmp_path / "app.py").write_text(
        """
import os

os.system('date')
""",
        encoding="utf-8",
    )

    assert A1CommandInjectionRule().evaluate(tmp_path) == []


def test_A2_detects_f_string_sql_from_external_input(tmp_path):
    (tmp_path / "app.py").write_text(
        """
import sqlite3

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
user_id = input()
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
""",
        encoding="utf-8",
    )

    records = A2SqlInjectionRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-2"
    assert records[0].severity == Severity.HIGH


def test_A2_ignores_parameterized_sql(tmp_path):
    (tmp_path / "app.py").write_text(
        """
import sqlite3

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
user_id = input()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",
        encoding="utf-8",
    )

    assert A2SqlInjectionRule().evaluate(tmp_path) == []


def test_A3_detects_pickle_loads_from_external_input(tmp_path):
    (tmp_path / "worker.py").write_text(
        """
import pickle

payload = input()
pickle.loads(payload)
""",
        encoding="utf-8",
    )

    records = A3UnsafeDeserializationRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-3"
    assert records[0].severity == Severity.HIGH


def test_A3_ignores_yaml_safe_load(tmp_path):
    (tmp_path / "worker.py").write_text(
        """
import yaml

payload = input()
yaml.safe_load(payload)
""",
        encoding="utf-8",
    )

    assert A3UnsafeDeserializationRule().evaluate(tmp_path) == []


def test_A4_detects_open_with_external_path(tmp_path):
    (tmp_path / "files.py").write_text(
        """
filename = input()
open(filename).read()
""",
        encoding="utf-8",
    )

    records = A4PathTraversalRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-4"
    assert records[0].severity == Severity.HIGH


def test_A4_ignores_fixed_file_path(tmp_path):
    (tmp_path / "files.py").write_text(
        "open('static/config.json').read()\n",
        encoding="utf-8",
    )

    assert A4PathTraversalRule().evaluate(tmp_path) == []


def test_A5_detects_requests_get_external_url(tmp_path):
    (tmp_path / "client.py").write_text(
        """
import requests

url = input()
requests.get(url)
""",
        encoding="utf-8",
    )

    records = A5SsrfRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-5"
    assert records[0].severity == Severity.HIGH


def test_A5_ignores_fixed_url(tmp_path):
    (tmp_path / "client.py").write_text(
        """
import requests

requests.get('https://api.example.com/health')
""",
        encoding="utf-8",
    )

    assert A5SsrfRule().evaluate(tmp_path) == []


def test_A6_detects_render_template_string_external_input(tmp_path):
    (tmp_path / "views.py").write_text(
        """
from flask import render_template_string

html = input()
render_template_string(html)
""",
        encoding="utf-8",
    )

    records = A6XssRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-6"
    assert records[0].severity == Severity.HIGH


def test_A6_ignores_render_template_string_constant(tmp_path):
    (tmp_path / "views.py").write_text(
        """
from flask import render_template_string

render_template_string('<p>Hello</p>')
""",
        encoding="utf-8",
    )

    assert A6XssRule().evaluate(tmp_path) == []


def test_A7_detects_template_from_external_input(tmp_path):
    (tmp_path / "templates.py").write_text(
        """
from jinja2 import Template

template_source = input()
Template(template_source)
""",
        encoding="utf-8",
    )

    records = A7TemplateInjectionRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-7"
    assert records[0].severity == Severity.HIGH


def test_A7_ignores_template_constant(tmp_path):
    (tmp_path / "templates.py").write_text(
        """
from jinja2 import Template

Template('Hello {{ name }}')
""",
        encoding="utf-8",
    )

    assert A7TemplateInjectionRule().evaluate(tmp_path) == []


def test_A8_detects_eval_from_external_input(tmp_path):
    (tmp_path / "calculator.py").write_text(
        """
expr = input()
eval(expr)
""",
        encoding="utf-8",
    )

    records = A8UnsafeEvalRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "A-8"
    assert records[0].severity == Severity.HIGH


def test_A8_ignores_eval_of_constant_string(tmp_path):
    (tmp_path / "calculator.py").write_text(
        "result = eval('1 + 2')\n",
        encoding="utf-8",
    )

    assert A8UnsafeEvalRule().evaluate(tmp_path) == []
