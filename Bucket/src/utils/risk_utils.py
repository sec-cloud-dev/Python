from enum import Enum
from typing import Any, Iterable

from src.utils.models import RISK_TO_SEVERITY, Finding, RiskLevel, Severity

# IAM bindings are read at folder/cloud/organization level; bucket-level bindings are not fetched.
IAM_SCOPE_EVIDENCE = {
    "scope": "folder",
    "note": (
        "Роли выданы на уровне folder/cloud/organization и действуют на все бакеты папки; "
        "bucket-level bindings не запрашивались"
    ),
}


def overall_risk(report: list[dict[str, Any]], risk: str = "risk") -> str:
    if not report:
        return RiskLevel.SAFE.value

    statuses = []
    for item in report:
        status = item.get(risk)
        if isinstance(status, Enum):
            status = status.value
        if isinstance(status, str):
            statuses.append(status)

    if any(status in (RiskLevel.ERROR.value, RiskLevel.UNKNOWN.value) for status in statuses):
        return RiskLevel.UNKNOWN.value
    if RiskLevel.DANGER.value in statuses:
        return RiskLevel.DANGER.value
    if RiskLevel.WARNING.value in statuses:
        return RiskLevel.WARNING.value
    return RiskLevel.SAFE.value


def bindings_source(folder_roles: set, cloud_roles: set, organization_roles: set) -> str:
    sources = []
    if folder_roles:
        sources.append("Folder")
    if cloud_roles:
        sources.append("Cloud")
    if organization_roles:
        sources.append("Organization")
    return "+".join(sources) if sources else "NO_ROLES"


def finding_from_risk(
    rule_id: str,
    bucket: str,
    risk: str,
    message: str,
    evidence: dict[str, Any],
    missing_sources: Iterable[str] = (),
) -> Finding:
    """Build a finding from an aggregated chain risk.

    If some inventory sources could not be fetched, the result is UNKNOWN rather than safe:
    only a confirmed HIGH finding survives incomplete data.
    """
    severity = RISK_TO_SEVERITY.get(risk, Severity.UNKNOWN)
    missing = list(missing_sources)
    if missing:
        evidence = {**evidence, "missing_sources": missing}
        if severity is not Severity.HIGH:
            severity = Severity.UNKNOWN
            message = f"{message}. Неполные данные: не удалось получить {', '.join(missing)}"
    return Finding(rule_id, severity, bucket, message, evidence)
