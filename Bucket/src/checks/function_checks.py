import logging
from typing import Any
from src.clients.yandex_client import (
    triggers_get,
    folder_access_bindings_get,
    cloud_bindings_get,
    organization_bindings_get,
    organization_id_get,
)
from src.utils.extract_utils import _extract_sa_roles_for_bucket
from src.utils.risk_utils import bindings_source, overall_risk
from src.config import DANGEROUS_ROLES, SAFE_ROLES

logger = logging.getLogger(__name__)


def bucket_triggers_checkout(fol: str, col: str, name: str) -> list[dict[str, Any]]:
    report = []

    folder_bindings = folder_access_bindings_get(fol)
    cloud_bindings = cloud_bindings_get(col)
    organization_bindings = organization_bindings_get(organization_id_get())

    for trig in triggers_get(fol):

        rule = trig.get("rule", {}).get("objectStorage", "")

        if not rule:
            continue

        bucket_id = rule.get("bucketId", "")

        if bucket_id != name:
            continue

        invoke_fn = rule.get("invokeFunction", {})
        function_id = invoke_fn.get("functionId", "")
        trigger_sa_id = invoke_fn.get("serviceAccountId", "")

        _, folder_sa_roles = _extract_sa_roles_for_bucket(folder_bindings, trigger_sa_id)
        _, cloud_sa_roles = _extract_sa_roles_for_bucket(cloud_bindings, trigger_sa_id)
        _, organization_sa_roles = _extract_sa_roles_for_bucket(organization_bindings, trigger_sa_id)

        all_roles = folder_sa_roles | cloud_sa_roles | organization_sa_roles

        role_source = bindings_source(folder_sa_roles, cloud_sa_roles, organization_sa_roles)

        if all_roles & DANGEROUS_ROLES:
            risk = "DANGER"
        elif all_roles & SAFE_ROLES:
            risk = "SAFE"
        else:
            risk = "WARNING"

        chains = {
            "Bucket_name": name,
            "Id_function": function_id,
            "Sa_id": trigger_sa_id,
            "level_bindings": role_source,
            "Bindings": sorted(all_roles),
            "Risk": risk,
        }

        report.append(chains)

    risp = overall_risk(report, risk="Risk")

    return {"Risk": risp, "Chains": report}
