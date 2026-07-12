import sys
import os
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.utils.risk_utils import overall_risk, bindings_source


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