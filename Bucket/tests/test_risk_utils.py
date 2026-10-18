from typing import Any

from src.utils.models import Severity
from src.utils.risk_utils import bindings_source, finding_from_risk, overall_risk


def test_overall_risk():
    report: list[dict[str, Any]] = [{"risk": "DANGER"}, {"risk": "WARNING"}]
    assert overall_risk(report, risk="risk") == "DANGER"

    report = [{"risk": "WARNING"}, {"risk": "SAFE"}]
    assert overall_risk(report, risk="risk") == "WARNING"

    report = [{"risk": "SAFE"}]
    assert overall_risk(report, risk="risk") == "SAFE"

    report = []
    assert overall_risk(report, risk="risk") == "SAFE"


def test_bindings_source():
    assert bindings_source({"admin"}, set(), set()) == "Folder"
    assert bindings_source({"admin"}, {"editor"}, set()) == "Folder+Cloud"
    assert bindings_source(set(), set(), set()) == "NO_ROLES"


def test_finding_from_risk_maps_severity():
    assert finding_from_risk("r", "b", "DANGER", "m", {}).severity is Severity.HIGH
    assert finding_from_risk("r", "b", "WARNING", "m", {}).severity is Severity.MEDIUM
    assert finding_from_risk("r", "b", "SAFE", "m", {}).severity is Severity.INFO


def test_finding_from_risk_missing_data_is_unknown_not_safe():
    finding = finding_from_risk("r", "b", "SAFE", "m", {}, ["folder_bindings"])
    assert finding.severity is Severity.UNKNOWN
    assert finding.evidence["missing_sources"] == ["folder_bindings"]

    # A confirmed HIGH finding stays HIGH even with partial data.
    assert finding_from_risk("r", "b", "DANGER", "m", {}, ["vms"]).severity is Severity.HIGH
