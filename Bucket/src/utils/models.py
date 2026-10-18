from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Bucket value for findings that are not bound to one bucket (folder/cloud/organization IAM).
FOLDER_SCOPE = "*"


class RiskLevel(str, Enum):
    """Risk of a single item (VM, SA, key, trigger, CDN resource) inside a finding's evidence."""

    DANGER = "DANGER"
    WARNING = "WARNING"
    SAFE = "SAFE"
    NO_CONFIGURATION = "NO_CONFIGURATION"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    # The check could not be completed (API error, missing data). Never counted as safe.
    UNKNOWN = "unknown"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}

RISK_TO_SEVERITY = {
    RiskLevel.DANGER.value: Severity.HIGH,
    RiskLevel.WARNING.value: Severity.MEDIUM,
    RiskLevel.NO_CONFIGURATION.value: Severity.LOW,
    RiskLevel.SAFE.value: Severity.INFO,
    RiskLevel.UNKNOWN.value: Severity.UNKNOWN,
    RiskLevel.ERROR.value: Severity.UNKNOWN,
}


@dataclass(frozen=True)
class Finding:
    """Single result shape returned by every check."""

    rule_id: str
    severity: Severity
    bucket: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "bucket": self.bucket,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    folder_id: str
    buckets: dict[str, list[Finding]]
    folder_findings: list[Finding]

    @property
    def findings(self) -> list[Finding]:
        return [f for findings in self.buckets.values() for f in findings] + self.folder_findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "folder_id": self.folder_id,
            "buckets": {name: [f.to_dict() for f in findings] for name, findings in self.buckets.items()},
            "folder_findings": [f.to_dict() for f in self.folder_findings],
        }
