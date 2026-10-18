import json
from pathlib import Path

from src.cli import main
from src.fixture import load_fixture
from src.metrics import severity_counts
from src.scanner import scan
from src.utils.models import Severity

FIXTURE = Path(__file__).parent / "fixtures" / "public_bucket.json"


def _scan():
    return scan(*load_fixture(FIXTURE))


def _by_rule(findings):
    return {f.rule_id: f for f in findings}


def test_public_bucket_findings_are_high():
    result = _scan()
    public = _by_rule(result.buckets["public-bucket"])

    assert public["bucket.acl"].severity is Severity.HIGH
    assert public["bucket.policy"].severity is Severity.HIGH
    assert public["bucket.cors"].severity is Severity.HIGH


def test_private_bucket_has_no_high_findings():
    result = _scan()
    private = result.buckets["private-bucket"]

    assert all(f.severity is not Severity.HIGH for f in private)
    assert all(f.severity is not Severity.UNKNOWN for f in private)


def test_every_check_returns_the_same_shape():
    for finding in _scan().findings:
        assert set(finding.to_dict()) == {"rule_id", "severity", "bucket", "message", "evidence"}


def test_danger_gauge_counts_high_severity():
    result = _scan()
    counts = severity_counts(result)

    assert counts["danger"] == sum(1 for f in result.findings if f.severity is Severity.HIGH)
    # Public ACL is HIGH in the report, so the DANGER panel moves too.
    assert counts["danger"] >= 1
    assert sum(counts.values()) == len(result.findings)


def test_iam_findings_are_folder_level_and_counted_once():
    result = _scan()

    iam = _by_rule(result.folder_findings)
    assert set(iam) == {"iam.vm_sa_access", "iam.sa_roles", "iam.static_keys"}
    assert all(f.bucket == "*" and f.evidence["scope"] == "folder" for f in iam.values())
    assert iam["iam.vm_sa_access"].severity is Severity.HIGH
    for findings in result.buckets.values():
        assert not any(f.rule_id.startswith("iam.") for f in findings)


def test_cli_fail_on_high_exits_non_zero(capsys):
    assert main(["scan", "--fixture", str(FIXTURE), "--fail-on", "high"]) == 1
    assert "public-bucket" in capsys.readouterr().out


def test_cli_fail_on_never_exits_zero_and_outputs_json(capsys):
    assert main(["scan", "--fixture", str(FIXTURE), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    acl = next(f for f in report["buckets"]["public-bucket"] if f["rule_id"] == "bucket.acl")
    assert acl["severity"] == "high"


def test_cli_missing_fixture_exits_2():
    assert main(["scan", "--fixture", "does-not-exist.json"]) == 2
