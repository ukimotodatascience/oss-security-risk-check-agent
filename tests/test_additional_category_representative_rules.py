from src.models import Severity
from src.rules.D_config.D2_debug_enabled import D2DebugEnabledRule
from src.rules.D_config.D4_permissive_cors import D4PermissiveCORSRule
from src.rules.D_config.D5_insecure_sample_config import D5InsecureSampleConfigRule
from src.rules.D_config.D6_missing_security_headers import D6MissingSecurityHeadersRule
from src.rules.D_config.D7_insecure_file_permissions import (
    D7InsecureFilePermissionsRule,
)
from src.rules.E_auth.E5_default_credentials import E5DefaultCredentialsRule
from src.rules.G_runtime.G2_privileged_container import G2PrivilegedContainerRule
from src.rules.I_logging.I1_sensitive_data_in_logs import I1SensitiveDataInLogsRule
from src.rules.J_maintenance.J2_missing_security_policy import (
    J2MissingSecurityPolicyRule,
)
from src.rules.K_license.K1_missing_license import K1MissingLicenseRule
from src.rules.L_malware.L4_runtime_download_and_execute import (
    L4RuntimeDownloadAndExecuteRule,
)


def test_D2_detects_debug_enabled_in_production_config(tmp_path):
    (tmp_path / "production.env").write_text("DEBUG=true\n", encoding="utf-8")

    records = D2DebugEnabledRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "D-2"
    assert records[0].severity == Severity.HIGH


def test_D2_ignores_debug_disabled(tmp_path):
    (tmp_path / "production.env").write_text("DEBUG=false\n", encoding="utf-8")

    assert D2DebugEnabledRule().evaluate(tmp_path) == []


def test_D4_detects_wildcard_cors_with_credentials(tmp_path):
    (tmp_path / "app.conf").write_text(
        "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\n",
        encoding="utf-8",
    )

    records = D4PermissiveCORSRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "D-4"
    assert records[0].severity == Severity.HIGH


def test_D4_ignores_specific_cors_origin(tmp_path):
    (tmp_path / "app.conf").write_text(
        "Access-Control-Allow-Origin: https://app.example.com\n",
        encoding="utf-8",
    )

    assert D4PermissiveCORSRule().evaluate(tmp_path) == []


def test_D5_detects_weak_password_in_sample_config(tmp_path):
    (tmp_path / "sample.env").write_text("PASSWORD=password\n", encoding="utf-8")

    records = D5InsecureSampleConfigRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "D-5"
    assert records[0].severity == Severity.MEDIUM


def test_D5_ignores_secure_value_in_sample_config(tmp_path):
    (tmp_path / "sample.env").write_text("PASSWORD=${APP_PASSWORD}\n", encoding="utf-8")

    assert D5InsecureSampleConfigRule().evaluate(tmp_path) == []


def test_D6_detects_missing_security_headers(tmp_path):
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n", encoding="utf-8"
    )

    records = D6MissingSecurityHeadersRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "D-6"
    assert records[0].severity == Severity.MEDIUM
    assert records[0].message is not None
    assert "Content-Security-Policy" in records[0].message


def test_D6_ignores_config_with_recommended_security_headers(tmp_path):
    (tmp_path / "nginx.conf").write_text(
        """
add_header Content-Security-Policy "default-src 'self'";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "DENY";
add_header Referrer-Policy "no-referrer";
""",
        encoding="utf-8",
    )

    assert D6MissingSecurityHeadersRule().evaluate(tmp_path) == []


def test_D7_detects_world_readable_sensitive_file(tmp_path):
    secret_file = tmp_path / "server.key"
    secret_file.write_text("redacted\n", encoding="utf-8")
    secret_file.chmod(0o644)

    records = D7InsecureFilePermissionsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "D-7"
    assert records[0].severity == Severity.HIGH


def test_D7_ignores_non_sensitive_file_even_if_world_readable(tmp_path):
    secret_file = tmp_path / "readme.txt"
    secret_file.write_text("public docs\n", encoding="utf-8")
    secret_file.chmod(0o644)

    assert D7InsecureFilePermissionsRule().evaluate(tmp_path) == []


def test_E5_detects_default_credentials(tmp_path):
    (tmp_path / "settings.ini").write_text(
        "username=admin\npassword=password\n", encoding="utf-8"
    )

    records = E5DefaultCredentialsRule().evaluate(tmp_path)

    assert [record.rule_id for record in records] == ["E-5", "E-5"]
    assert all(record.severity == Severity.MEDIUM for record in records)


def test_E5_ignores_non_default_credentials(tmp_path):
    (tmp_path / "settings.ini").write_text(
        "username=service_user\npassword=${APP_PASSWORD}\n", encoding="utf-8"
    )

    assert E5DefaultCredentialsRule().evaluate(tmp_path) == []


def test_G2_detects_privileged_container_setting(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: example/app\n    privileged: true\n",
        encoding="utf-8",
    )

    records = G2PrivilegedContainerRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "G-2"
    assert records[0].severity == Severity.HIGH


def test_G2_ignores_privileged_false(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: example/app\n    privileged: false\n",
        encoding="utf-8",
    )

    assert G2PrivilegedContainerRule().evaluate(tmp_path) == []


def test_I1_detects_password_logging(tmp_path):
    (tmp_path / "app.py").write_text(
        "logger.info('password=%s', password)\n", encoding="utf-8"
    )

    records = I1SensitiveDataInLogsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "I-1"
    assert records[0].severity == Severity.HIGH


def test_I1_ignores_masked_secret_logging(tmp_path):
    (tmp_path / "app.py").write_text(
        "logger.info('password=[REDACTED]')\n", encoding="utf-8"
    )

    assert I1SensitiveDataInLogsRule().evaluate(tmp_path) == []


def test_J2_detects_missing_security_policy(tmp_path):
    (tmp_path / "README.md").write_text("# Example Project\n", encoding="utf-8")

    records = J2MissingSecurityPolicyRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "J-2"


def test_J2_ignores_existing_security_policy(tmp_path):
    (tmp_path / "SECURITY.md").write_text(
        "Please report vulnerabilities to security@example.com.\n", encoding="utf-8"
    )

    assert J2MissingSecurityPolicyRule().evaluate(tmp_path) == []


def test_K1_detects_missing_license(tmp_path):
    (tmp_path / "README.md").write_text("# Example Project\n", encoding="utf-8")

    records = K1MissingLicenseRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "K-1"


def test_K1_ignores_existing_license_file(tmp_path):
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")

    assert K1MissingLicenseRule().evaluate(tmp_path) == []


def test_L4_detects_curl_pipe_bash(tmp_path):
    (tmp_path / "install.sh").write_text(
        "curl https://example.com/bootstrap.sh | bash\n", encoding="utf-8"
    )

    records = L4RuntimeDownloadAndExecuteRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "L-4"
    assert records[0].severity == Severity.HIGH


def test_L4_ignores_download_without_execution(tmp_path):
    (tmp_path / "install.sh").write_text(
        "curl -o bootstrap.sh https://example.com/bootstrap.sh\n", encoding="utf-8"
    )

    assert L4RuntimeDownloadAndExecuteRule().evaluate(tmp_path) == []
