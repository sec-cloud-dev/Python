import logging
from datetime import datetime, timezone
from typing import Any
from src.clients.yandex_client import (
    folder_access_bindings_get,
    cloud_bindings_get,
    organization_bindings_get,
    organization_id_get,
    access_key_sa,
    sa_get,
)
from src.utils.extract_utils import _extract_sa_roles_for_bucket
from src.utils.risk_utils import overall_risk
from src.config import DANGEROUS_ROLES, SAFE_ROLES

logger = logging.getLogger(__name__)


def check_all_sa_bucket(folder_id: str, cloud_id: str, bucket_name: str) -> list[dict[str, Any]]:
    logger.info(f"Проверка SA с доступом к бакету: '{bucket_name}'")

    results = []
    folder_bindings = folder_access_bindings_get(folder_id)
    cloud_bindings = cloud_bindings_get(cloud_id)
    organization_bindings = organization_bindings_get(organization_id_get())

    all_roles = folder_bindings + cloud_bindings + organization_bindings
    all_sa_roles, _ = _extract_sa_roles_for_bucket(all_roles)

    for sa_id, roles in all_sa_roles.items():
        if roles & DANGEROUS_ROLES:
            logger.warning(f"Бакет: {bucket_name}: SA: {sa_id} имеет опасные роли для бакета: {sorted(roles)}")
            risk = "DANGER"
        elif roles & SAFE_ROLES:
            logger.info(f"Бакет: {bucket_name}: SA: {sa_id} Имеет безопасные роли для бакета: {sorted(roles)}")
            risk = "SAFE"
        else:
            logger.warning(f"Бакет: {bucket_name}: SA: {sa_id} Имеет не определенные роли для бакета: {sorted(roles)}")
            risk = "WARNING"

        sa = {"sa_id": sa_id, "role": sorted(roles), "risk": risk}

        results.append(sa)

    if not results:
        return {"status": "NO_SA", "sa_list": []}

    status_sa = overall_risk(results, risk="risk")

    return {"status": status_sa, "sa_list": results}


def checks_sa_stat_key(folder_id: str) -> dict[str, Any]:
    sa_list = sa_get(folder_id)
    report = []

    if not sa_list:
        logger.info("Не найдено SA в папке")
        return {"status": "SAFE", "report": []}

    for sa in sa_list:
        name = sa.get("name", "")
        sa_id = sa.get("id", "")
        access_key = access_key_sa(sa_id)

        if not access_key:
            logger.info(f"Для SA: {name} Нету статического ключа")
            continue

        for key in access_key:
            key_id = key.get("keyId", "")
            created_at = key.get("createdAt", "")
            last_used = key.get("lastUsedAt", "")

            risk_key_sa = "SAFE"

            if not last_used:
                logger.warning(f"Созданный статический ключ для SA: {name} Не использовался вообще")
                risk_key_sa = "WARNING"

                reports = {
                    "sa_name": name,
                    "key_id": key_id,
                    "created_at": created_at,
                    "last_used": "never",
                    "risk": risk_key_sa,
                }
                report.append(reports)
                continue

            if last_used:
                last_usedet = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                days_ago = (now - last_usedet).days
            else:
                days_ago = None

            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days = (now - created).days

            if days_ago is not None and days_ago >= 90:
                logger.warning(
                    f"Ключ не использовался 90 дней или больше. Забытый/потанциально утекший ключ sa: {name}"
                )
                risk_key_sa = "WARNING"

            if days >= 90:
                logger.warning(
                    f"Ключ у sa: {name} Был создан более чем 90 дней назад риск утечки требуется ротация ключа: {key_id} По 152-фз"
                )
                risk_key_sa = "DANGER"

            reports = {
                "sa_name": name,
                "key_id": key_id,
                "created_at": created_at,
                "last_used": last_used,
                "risk": risk_key_sa,
            }

            report.append(reports)

    over = overall_risk(report, risk="risk")

    return {"status": over, "report": report}