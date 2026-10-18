import logging
from typing import Any
from src.config import DANGEROUS_ROLES, SAFE_ROLES
from src.inventory import BINDING_SOURCES, CloudInventory
from src.utils.extract_utils import _extract_sa_roles_for_bucket
from src.utils.models import FOLDER_SCOPE, Finding
from src.utils.risk_utils import IAM_SCOPE_EVIDENCE, bindings_source, finding_from_risk, overall_risk

logger = logging.getLogger(__name__)


def checks_vm_sa_bucket_access(inventory: CloudInventory) -> Finding:
    """VM -> SA -> storage roles. Roles are folder/cloud/organization level, so this is a folder finding."""
    rule_id = "iam.vm_sa_access"
    logger.info("Проверка связи: ВМ -> SA -> Object Storage")

    missing = inventory.missing("vms", *BINDING_SOURCES)
    vms = inventory.vms or []

    folder_sa_roles, _ = _extract_sa_roles_for_bucket(inventory.folder_bindings or [])
    cloud_sa_roles, _ = _extract_sa_roles_for_bucket(inventory.cloud_bindings or [])
    organization_sa_roles, _ = _extract_sa_roles_for_bucket(inventory.organization_bindings or [])

    chains = []

    for vm in vms:
        vm_name = vm.get("name", "")
        vm_id = vm.get("id", "")
        sa_id = vm.get("serviceAccountId", "")

        if not sa_id:
            continue

        roles_from_folder = folder_sa_roles.get(sa_id, set())
        roles_from_cloud = cloud_sa_roles.get(sa_id, set())
        roles_from_organization = organization_sa_roles.get(sa_id, set())

        all_roles = roles_from_folder | roles_from_cloud | roles_from_organization

        if not all_roles:
            continue

        role_source = bindings_source(roles_from_folder, roles_from_cloud, roles_from_organization)

        has_public_ip = _vm_has_public_ip(vm)

        if all_roles & DANGEROUS_ROLES:
            risk = "DANGER"
        elif all_roles & SAFE_ROLES:
            risk = "SAFE"
        else:
            risk = "WARNING"

        chain = {
            "vm_name": vm_name,
            "id": vm_id,
            "sa_id": sa_id,
            "roles": sorted(all_roles),
            "role_source": role_source,
            "public_ip": has_public_ip,
            "risk": risk,
        }

        chains.append(chain)

        if risk == "DANGER" and has_public_ip:
            logger.warning(
                f"КРИТИЧНО - ВМ '{vm_name}' имеет публичный IP и ее SA ({sa_id}) "
                f"имеет роли: {sorted(all_roles)} ({role_source})"
            )
        elif risk == "DANGER":
            logger.warning(f"ВМ: '{vm_name}', SA: ({sa_id}) имеет опасные роли: {sorted(all_roles)} ({role_source})")
        else:
            logger.info(f"ВМ: '{vm_name}', SA: ({sa_id}), Роли: {sorted(all_roles)}, Риск: {risk}")

    if not chains:
        logger.info("Нет связей ВМ -> SA с ролями")

    overall = overall_risk(chains, risk="risk")
    dangerous = [c for c in chains if c["risk"] == "DANGER"]
    if dangerous:
        exposed = sum(1 for c in dangerous if c["public_ip"])
        message = f"ВМ с SA, имеющим опасные роли на все бакеты папки: {len(dangerous)} (с публичным IP: {exposed})"
    else:
        message = f"ВМ с SA и ролями: {len(chains)}, опасных ролей нет"

    return finding_from_risk(rule_id, FOLDER_SCOPE, overall, message, {**IAM_SCOPE_EVIDENCE, "chains": chains}, missing)


def _vm_has_public_ip(vm: dict[str, Any]) -> bool:
    interfaces = vm.get("networkInterfaces", [])
    for iface in interfaces:
        v4 = iface.get("primaryV4Address", {})
        if v4.get("oneToOneNat"):
            return True
    return False
