from src.models import Severity
from src.rules.F_secrets.F1_hardcoded_secrets import F1HardcodedSecretsRule
from src.rules.F_secrets.F2_secret_files_committed import F2SecretFilesCommittedRule
from src.rules.F_secrets.F4_exposed_tokens_in_docs import F4ExposedTokensInDocsRule
from src.rules.F_secrets.F6_cloud_credentials_detected import (
    F6CloudCredentialsDetectedRule,
)


def test_F1_detects_high_entropy_hardcoded_secret(tmp_path):
    (tmp_path / "settings.py").write_text(
        "API_KEY = 'AbCdEfGhIjKlMnOpQrStUvWxYz123456'\n", encoding="utf-8"
    )

    records = F1HardcodedSecretsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "F-1"
    assert records[0].severity == Severity.HIGH


def test_F1_reports_placeholder_secret_as_medium(tmp_path):
    (tmp_path / "settings.py").write_text(
        "API_KEY = 'your_api_key'\n", encoding="utf-8"
    )

    records = F1HardcodedSecretsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "F-1"
    assert records[0].severity == Severity.MEDIUM


def test_F2_detects_private_key_file(tmp_path):
    (tmp_path / "server.key").write_text("redacted\n", encoding="utf-8")

    records = F2SecretFilesCommittedRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "F-2"
    assert records[0].severity == Severity.HIGH


def test_F2_ignores_public_key_file(tmp_path):
    (tmp_path / "server.pub").write_text("ssh-rsa AAAA...\n", encoding="utf-8")

    assert F2SecretFilesCommittedRule().evaluate(tmp_path) == []


def test_F4_detects_github_token_in_docs(tmp_path):
    (tmp_path / "README.md").write_text(
        "Use token ghp_abcdefghijklmnopqrstuvwxyz123456 for deployment.\n",
        encoding="utf-8",
    )

    records = F4ExposedTokensInDocsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "F-4"
    assert records[0].severity == Severity.HIGH


def test_F4_ignores_placeholder_token_in_docs(tmp_path):
    (tmp_path / "README.md").write_text(
        "Use token <token> or your_token here.\n", encoding="utf-8"
    )

    assert F4ExposedTokensInDocsRule().evaluate(tmp_path) == []


def test_F6_detects_aws_access_key(tmp_path):
    (tmp_path / "prod.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n", encoding="utf-8"
    )

    records = F6CloudCredentialsDetectedRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "F-6"
    assert records[0].severity == Severity.HIGH


def test_F6_ignores_placeholder_cloud_credential(tmp_path):
    (tmp_path / "example.env").write_text(
        "AWS_ACCESS_KEY_ID=your_aws_access_key\n", encoding="utf-8"
    )

    assert F6CloudCredentialsDetectedRule().evaluate(tmp_path) == []
