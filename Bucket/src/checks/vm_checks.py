import logging
from typing import Any
from src.clients.yandex_client import (
    vm_get,
    folder_access_bindings_get,
    cloud_bindings_get,
    organization_bindings_get,
    organization_id_get,
)
from src.utils.extract_utils import _extract_sa_roles_for_bucket
from src.utils.risk_utils import bindings_source, overall_risk
from src.config import DANGEROUS_ROLES, SAFE_ROLES

logger = logging.getLogger(__name__)


def checks_vm_sa_bucket_access(folder_id: str, cloud_id: str, bucket_name: str) -> dict[str, Any]:
    logger.info(f"Проверка связи: ВМ -> SA -> Бакет '{bucket_name}'")

    vms = vm_get(folder_id)

    if not vms:
        logger.info(f"В {folder_id} Не найдено ВМ")
        return {"status": "NO_Links", "chains": []}

    folder_bindings = folder_access_bindings_get(folder_id)
    cloud_bindings = cloud_bindings_get(cloud_id)
    organization_bindings = organization_bindings_get(organization_id_get())

    folder_sa_roles, _ = _extract_sa_roles_for_bucket(folder_bindings)
    cloud_sa_roles, _ = _extract_sa_roles_for_bucket(cloud_bindings)
    organization_sa_roles, _ = _extract_sa_roles_for_bucket(organization_bindings)

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
                f"Бакет: {bucket_name}: КРИТИЧНО - ВМ '{vm_name}' имеет"
                f"Публичный IP и ее SA ({sa_id}) имеет роли: {sorted(all_roles)}"
                f"На бакет"
            )
        elif risk == "DANGER":
            logger.warning(
                f"Бакет: {bucket_name}: ВМ: '{vm_name}, SA: ({sa_id})' имеет"
                f"Опасные роли: {sorted(all_roles)} На бакет"
            )
        else:
            logger.info(
                f"Бакет: {bucket_name}: ВМ: '{vm_name}', SA: ({sa_id})," f"Роли: {sorted(all_roles)}, Риск: {risk}"
            )

    if not chains:
        logger.info(f"Бакет: {bucket_name}: нет связей ВМ -> SA -> бакет")

    overall_status = overall_risk(chains, risk="risk")

    return {"status": overall_status, "chains": chains}


def _vm_has_public_ip(vm: dict[str, Any]) -> bool:
    interfaces = vm.get("networkInterfaces", [])
    for iface in interfaces:
        v4 = iface.get("primaryV4Address", {})
        if v4.get("oneToOneNat"):
            return True
    return False
