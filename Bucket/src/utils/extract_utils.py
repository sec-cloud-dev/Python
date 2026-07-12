from typing import Any


def _extract_sa_roles_for_bucket(bindings: list[dict[str, Any]], function_id: str | None = None):
    sa_roles = {}
    roles = set()

    for binding in bindings:
        subject = binding.get("subject", {})
        if subject.get("type") != "serviceAccount":
            continue

        sa_id = subject.get("id", "")
        role_id = binding.get("roleId", "")

        if not sa_id or not role_id:
            continue

        if subject.get("id") == function_id:
            roles.add(role_id)

        sa_roles.setdefault(sa_id, set()).add(role_id)
    return sa_roles, roles
