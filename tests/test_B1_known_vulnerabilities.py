from src.models import Severity
from src.rules.B_dependencies.B1_known_vulnerabilities import B1KnownVulnerabilitiesRule
from src.rules.B_dependencies.vuln_sources import VulnHit


class FakeVulnLookup:
    def __init__(self, hits: list[VulnHit] | None = None, should_fail: bool = False):
        self.hits = hits or []
        self.should_fail = should_fail

    def lookup(self, ecosystem: str, name: str, version: str) -> list[VulnHit]:
        if self.should_fail:
            raise AssertionError(
                "lookup should not be called for unpinned dependencies"
            )
        assert ecosystem == "python"
        assert name == "vulnerable-lib"
        assert version == "1.0.0"
        return self.hits


def test_B1_reports_mocked_known_vulnerability(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "vulnerable-lib==1.0.0\n", encoding="utf-8"
    )
    rule = B1KnownVulnerabilitiesRule(
        lookup=FakeVulnLookup(
            hits=[
                VulnHit(
                    vuln_id="CVE-2099-0001",
                    source="test",
                    summary="Mocked critical vulnerability",
                    severity_score=9.8,
                    references=("https://example.com/advisory",),
                )
            ]
        )
    )

    records = rule.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "B-1"
    assert records[0].severity == Severity.CRITICAL
    assert records[0].file_path == "requirements.txt"
    assert records[0].line == 1
    assert records[0].message is not None
    assert "CVE-2099-0001" in records[0].message


def test_B1_reports_unpinned_dependency_without_lookup(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
    rule = B1KnownVulnerabilitiesRule(lookup=FakeVulnLookup(should_fail=True))

    records = rule.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].rule_id == "B-1"
    assert records[0].severity == Severity.MEDIUM
    assert records[0].message is not None
    assert "バージョン照合ができません" in records[0].message
