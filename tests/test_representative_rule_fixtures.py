from src.models import Severity
from src.rules.B_dependencies.B2_unpinnedversions import B2UnpinnedVersionsRule
from src.rules.C_cicd.C1_curl_pipe_shell import C1CurlPipeShellRule
from src.rules.F_secrets.F5_private_keys_detected import F5PrivateKeysDetectedRule
from src.rules.H_crypto.H2_tls_verification_disabled import (
    H2TLSVerificationDisabledRule,
)


def test_B2_detects_unpinned_python_dependency(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")

    records = B2UnpinnedVersionsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "B-2"
    assert records[0].file_path == "requirements.txt"


def test_B2_ignores_pinned_python_dependency(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    assert B2UnpinnedVersionsRule().evaluate(tmp_path) == []


def test_C1_detects_curl_pipe_shell(tmp_path):
    (tmp_path / "install.sh").write_text(
        "curl https://example.com/install.sh | sh\n", encoding="utf-8"
    )

    records = C1CurlPipeShellRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-1"
    assert records[0].severity == Severity.HIGH


def test_C1_ignores_commented_curl_pipe_shell(tmp_path):
    (tmp_path / "install.sh").write_text(
        "# curl https://example.com/install.sh | sh\n", encoding="utf-8"
    )

    assert C1CurlPipeShellRule().evaluate(tmp_path) == []


def test_F5_detects_private_key_block(tmp_path):
    (tmp_path / "server.key").write_text(
        "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    records = F5PrivateKeysDetectedRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "F-5"
    assert records[0].severity == Severity.CRITICAL


def test_F5_ignores_public_key_block(tmp_path):
    (tmp_path / "server.pub").write_text(
        "-----BEGIN PUBLIC KEY-----\nredacted\n-----END PUBLIC KEY-----\n",
        encoding="utf-8",
    )

    assert F5PrivateKeysDetectedRule().evaluate(tmp_path) == []


def test_H2_detects_python_requests_verify_false(tmp_path):
    (tmp_path / "client.py").write_text(
        "import requests\nrequests.get('https://example.com', verify=False)\n",
        encoding="utf-8",
    )

    records = H2TLSVerificationDisabledRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "H-2"
    assert records[0].severity == Severity.HIGH


def test_H2_ignores_default_tls_verification(tmp_path):
    (tmp_path / "client.py").write_text(
        "import requests\nrequests.get('https://example.com')\n", encoding="utf-8"
    )

    assert H2TLSVerificationDisabledRule().evaluate(tmp_path) == []
