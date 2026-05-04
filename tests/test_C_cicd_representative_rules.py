from src.models import Severity
from src.rules.C_cicd.C2_unpinned_actions import C2UnpinnedActionsRule
from src.rules.C_cicd.C3_third_party_action_usage import C3ThirdPartyActionUsageRule
from src.rules.C_cicd.C4_untrusted_checkout import C4UntrustedCheckoutRule
from src.rules.C_cicd.C5_dangerous_workflow_triggers import (
    C5DangerousWorkflowTriggersRule,
)
from src.rules.C_cicd.C6_insecure_artifact_handling import (
    C6InsecureArtifactHandlingRule,
)
from src.rules.C_cicd.C7_dangerous_makefile import C7DangerousMakefileRule
from src.rules.C_cicd.C8_unsafe_container_build import C8UnsafeContainerBuildRule


def _write_workflow(tmp_path, name: str, content: str):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    path = workflows / name
    path.write_text(content, encoding="utf-8")
    return path


def test_C2_detects_action_pinned_to_mutable_tag(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: CI
jobs:
  test:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
""",
    )

    records = C2UnpinnedActionsRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-2"
    assert records[0].severity == Severity.MEDIUM


def test_C2_ignores_action_pinned_to_full_sha(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: CI
jobs:
  test:
    steps:
      - name: Checkout
        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
""",
    )

    assert C2UnpinnedActionsRule().evaluate(tmp_path) == []


def test_C3_detects_many_third_party_actions(tmp_path):
    _write_workflow(
        tmp_path,
        "third-party.yml",
        """
jobs:
  test:
    steps:
      - name: A
        uses: vendor-a/action@v1
      - name: B
        uses: vendor-b/action@v1
      - name: C
        uses: vendor-c/action@v1
""",
    )

    records = C3ThirdPartyActionUsageRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-3"
    assert records[0].severity == Severity.MEDIUM


def test_C3_ignores_first_party_and_local_actions(tmp_path):
    _write_workflow(
        tmp_path,
        "first-party.yml",
        """
jobs:
  test:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Script
        uses: ./github/actions/script
""",
    )

    assert C3ThirdPartyActionUsageRule().evaluate(tmp_path) == []


def test_C4_detects_pull_request_target_checkout_of_pr_head(tmp_path):
    _write_workflow(
        tmp_path,
        "pr-target.yml",
        """
on:
  pull_request_target:

jobs:
  test:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""",
    )

    records = C4UntrustedCheckoutRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-4"
    assert records[0].severity == Severity.HIGH


def test_C4_ignores_regular_pull_request_checkout(tmp_path):
    _write_workflow(
        tmp_path,
        "pr.yml",
        """
on:
  pull_request:

jobs:
  test:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
""",
    )

    assert C4UntrustedCheckoutRule().evaluate(tmp_path) == []


def test_C5_detects_risky_comment_trigger_with_secret(tmp_path):
    _write_workflow(
        tmp_path,
        "comment.yml",
        """
on:
  issue_comment:

jobs:
  deploy:
    steps:
      - run: deploy --token ${{ secrets.DEPLOY_TOKEN }}
""",
    )

    records = C5DangerousWorkflowTriggersRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-5"
    assert records[0].severity == Severity.HIGH


def test_C5_ignores_push_trigger(tmp_path):
    _write_workflow(
        tmp_path,
        "push.yml",
        """
on:
  push:

jobs:
  test:
    steps:
      - run: pytest
""",
    )

    assert C5DangerousWorkflowTriggersRule().evaluate(tmp_path) == []


def test_C6_detects_download_artifact_without_verification(tmp_path):
    _write_workflow(
        tmp_path,
        "artifact.yml",
        """
jobs:
  consume:
    steps:
      - name: Download artifact
        uses: actions/download-artifact@v4
      - run: ./deploy.sh
""",
    )

    records = C6InsecureArtifactHandlingRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-6"
    assert records[0].severity == Severity.HIGH


def test_C6_ignores_download_artifact_with_hash_verification(tmp_path):
    _write_workflow(
        tmp_path,
        "artifact.yml",
        """
jobs:
  consume:
    steps:
      - name: Download artifact
        uses: actions/download-artifact@v4
      - run: sha256sum -c artifact.sha256
""",
    )

    assert C6InsecureArtifactHandlingRule().evaluate(tmp_path) == []


def test_C7_detects_makefile_curl_pipe_shell(tmp_path):
    (tmp_path / "Makefile").write_text(
        "install:\n\tcurl https://example.com/install.sh | sh\n", encoding="utf-8"
    )

    records = C7DangerousMakefileRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-7"
    assert records[0].severity == Severity.HIGH


def test_C7_ignores_safe_makefile_target(tmp_path):
    (tmp_path / "Makefile").write_text("test:\n\tpython -m pytest\n", encoding="utf-8")

    assert C7DangerousMakefileRule().evaluate(tmp_path) == []


def test_C8_detects_docker_build_with_host_network(tmp_path):
    _write_workflow(
        tmp_path,
        "build.yml",
        """
jobs:
  build:
    steps:
      - run: docker build --network=host -t example/app .
""",
    )

    records = C8UnsafeContainerBuildRule().evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "C-8"
    assert records[0].severity == Severity.HIGH


def test_C8_ignores_normal_docker_build(tmp_path):
    _write_workflow(
        tmp_path,
        "build.yml",
        """
jobs:
  build:
    steps:
      - run: docker build -t example/app .
""",
    )

    assert C8UnsafeContainerBuildRule().evaluate(tmp_path) == []
