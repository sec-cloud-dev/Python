import logging
from src.config import DANGEROUS_ROLES, SAFE_ROLES
from src.inventory import BINDING_SOURCES, CloudInventory
from src.utils.extract_utils import _extract_sa_roles_for_bucket
from src.utils.models import Finding
from src.utils.risk_utils import IAM_SCOPE_EVIDENCE, bindings_source, finding_from_risk, overall_risk

logger = logging.getLogger(__name__)


def bucket_triggers_checkout(inventory: CloudInventory, name: str) -> Finding:
    rule_id = "functions.trigger_sa"
    missing = inventory.missing("triggers", *BINDING_SOURCES)
    report = []

    folder_bindings = inventory.folder_bindings or []
    cloud_bindings = inventory.cloud_bindings or []
    organization_bindings = inventory.organization_bindings or []

    for trig in inventory.triggers or []:

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
    if not report:
        message = "Триггеров Cloud Functions на бакет нет"
    else:
        message = f"Триггеров на бакет: {len(report)}, с опасными ролями SA: {sum(1 for c in report if c['Risk'] == 'DANGER')}"

    return finding_from_risk(rule_id, name, risp, message, {**IAM_SCOPE_EVIDENCE, "chains": report}, missing)
