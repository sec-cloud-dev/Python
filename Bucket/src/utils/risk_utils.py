from typing import Any


def overall_risk(report: list[dict[str, Any]], risk: str = "risk") -> str:

    if not report:
        return "SAFE"

    if any(r.get(risk) == "DANGER" for r in report):
        return "DANGER"
    elif any(r.get(risk) == "WARNING" for r in report):
        return "WARNING"
    else:
        return "SAFE"


def bindings_source(folder_roles: set, cloud_roles: set, organization_roles: set) -> str:
    has_folder = bool(folder_roles)
    has_cloud = bool(cloud_roles)
    has_organization = bool(organization_roles)

    if has_folder and has_cloud and has_organization:
        return "Cloud+Folder+Organization"
    elif has_folder and has_cloud:
        return "Folder+Cloud"
    elif has_folder and has_organization:
        return "Folder+Organization"
    elif has_cloud and has_organization:
        return "Cloud+Organization"
    elif has_cloud:
        return "Cloud"
    elif has_folder:
        return "Folder"
    elif has_organization:
        return "Organization"
    else:
        return "NO_ROLES"
